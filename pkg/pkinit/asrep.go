package pkinit

import (
	"crypto/sha1"
	"encoding/asn1"
	"fmt"
	"math/big"
	"time"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/types"
)

// DecryptedASRep contains the decrypted AS-REP data
type DecryptedASRep struct {
	EncPart    EncASRepPart
	SessionKey types.EncryptionKey
	ASRepKey   []byte // The truncated key - needed for getnthash
}

// EncASRepPart represents the decrypted part of AS-REP
type EncASRepPart struct {
	Key           types.EncryptionKey `asn1:"explicit,tag:0"`
	LastReq       []LastReqEntry      `asn1:"explicit,tag:1"`
	Nonce         int                 `asn1:"explicit,tag:2"`
	KeyExpiration time.Time           `asn1:"generalized,optional,explicit,tag:3"`
	Flags         asn1.BitString      `asn1:"explicit,tag:4"`
	AuthTime      time.Time           `asn1:"generalized,explicit,tag:5"`
	StartTime     time.Time           `asn1:"generalized,optional,explicit,tag:6"`
	EndTime       time.Time           `asn1:"generalized,explicit,tag:7"`
	RenewTill     time.Time           `asn1:"generalized,optional,explicit,tag:8"`
	SRealm        string              `asn1:"generalstring,explicit,tag:9"`
	SName         types.PrincipalName `asn1:"explicit,tag:10"`
	CAddr         []types.HostAddress `asn1:"optional,explicit,tag:11"`
}

// LastReqEntry represents a last-req entry
type LastReqEntry struct {
	LRType  int32     `asn1:"explicit,tag:0"`
	LRValue time.Time `asn1:"generalized,explicit,tag:1"`
}

// EncryptedData represents encrypted data in Kerberos
type EncryptedData struct {
	EType  int32  `asn1:"explicit,tag:0"`
	KVNO   int    `asn1:"optional,explicit,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

// DecryptASRep decrypts the AS-REP using PKINIT DH key derivation
func (p *PKINITClient) DecryptASRep(asRepBytes []byte) (*DecryptedASRep, error) {
	// Strip the APPLICATION 11 tag wrapper from AS-REP
	// AS-REP ::= [APPLICATION 11] KDC-REP
	var appWrapper asn1.RawValue
	_, err := asn1.Unmarshal(asRepBytes, &appWrapper)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AS-REP wrapper: %w", err)
	}

	// Parse raw AS-REP to extract padata
	var rawASRep struct {
		PVNO    int `asn1:"explicit,tag:0"`
		MsgType int `asn1:"explicit,tag:1"`
		PAData  []struct {
			PADataType  int32  `asn1:"explicit,tag:1"`
			PADataValue []byte `asn1:"explicit,tag:2"`
		} `asn1:"optional,explicit,tag:2"`
		CRealm  string        `asn1:"generalstring,explicit,tag:3"`
		CName   asn1.RawValue `asn1:"explicit,tag:4"`
		Ticket  asn1.RawValue `asn1:"explicit,tag:5"`
		EncPart EncryptedData `asn1:"explicit,tag:6"`
	}

	_, err = asn1.Unmarshal(appWrapper.Bytes, &rawASRep)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AS-REP: %w", err)
	}

	// Find PA_PK_AS_REP (type 17)
	var paPkAsRepBytes []byte
	for _, pa := range rawASRep.PAData {
		if pa.PADataType == 17 {
			paPkAsRepBytes = pa.PADataValue
			break
		}
	}

	if paPkAsRepBytes == nil {
		return nil, fmt.Errorf("PA_PK_AS_REP not found in AS-REP")
	}

	// PA_PK_AS_REP is a CHOICE type, so paPkAsRepBytes is directly the [0] tagged DHRepInfo
	// Parse it as a RawValue first to extract the content
	var paPkAsRepWrapper asn1.RawValue
	_, err = asn1.Unmarshal(paPkAsRepBytes, &paPkAsRepWrapper)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PA_PK_AS_REP wrapper: %w", err)
	}

	// Now parse the DHRepInfo content
	// DHRepInfo is a SEQUENCE containing [0] dhSignedData and [1] serverDHNonce
	// [0] is IMPLICIT OCTET STRING
	// [1] is EXPLICIT (contains OCTET STRING inside)
	type DHRepInfoRaw struct {
		DHSignedData  asn1.RawValue `asn1:"tag:0"`
		ServerDHNonce asn1.RawValue `asn1:"optional,tag:1"`
	}

	var dhRepInfoRaw DHRepInfoRaw
	_, err = asn1.Unmarshal(paPkAsRepWrapper.Bytes, &dhRepInfoRaw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DHRepInfo: %w", err)
	}

	// Extract dhSignedData - it's implicit, so the Bytes contain the actual OCTET STRING data
	dhSignedData := dhRepInfoRaw.DHSignedData.Bytes

	// Extract serverDHNonce - it's explicit, so we need to unmarshal the OCTET STRING inside
	var serverDHNonce []byte
	if dhRepInfoRaw.ServerDHNonce.Bytes != nil {
		_, err = asn1.Unmarshal(dhRepInfoRaw.ServerDHNonce.Bytes, &serverDHNonce)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal serverDHNonce: %w", err)
		}
	}

	type DHRepInfo struct {
		DHSignedData  []byte
		ServerDHNonce []byte
	}
	dhRepInfo := DHRepInfo{
		DHSignedData:  dhSignedData,
		ServerDHNonce: serverDHNonce,
	}

	// Parse the ContentInfo from dhSignedData
	var contentInfo ContentInfo
	_, err = asn1.Unmarshal(dhRepInfo.DHSignedData, &contentInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ContentInfo: %w", err)
	}

	// Parse SignedData
	var signedData SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SignedData: %w", err)
	}

	// Extract KDCDHKeyInfo from encapContentInfo
	kdcDHKeyInfoOID := asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 2}
	if !signedData.EncapContentInfo.ContentType.Equal(kdcDHKeyInfoOID) {
		return nil, fmt.Errorf("unexpected encapContentInfo type: %v", signedData.EncapContentInfo.ContentType)
	}

	// The Content is an OCTET STRING containing the KDCDHKeyInfo
	var kdcDHKeyInfoBytes []byte
	_, err = asn1.Unmarshal(signedData.EncapContentInfo.Content.Bytes, &kdcDHKeyInfoBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KDCDHKeyInfo OCTET STRING: %w", err)
	}

	// Parse KDCDHKeyInfo
	var kdcDHKeyInfo KDCDHKeyInfo
	_, err = asn1.Unmarshal(kdcDHKeyInfoBytes, &kdcDHKeyInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KDCDHKeyInfo: %w", err)
	}

	// Extract server's DH public key from subjectPublicKey
	// The BitString contains an INTEGER, so we need to parse it
	var serverPubKey *big.Int
	_, err = asn1.Unmarshal(kdcDHKeyInfo.SubjectPublicKey.Bytes, &serverPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server public key INTEGER: %w", err)
	}

	// Perform DH exchange to get shared secret
	sharedSecret := p.dh.Exchange(serverPubKey)

	// Combine: shared_secret + client_dh_nonce + server_dh_nonce
	fullKey := append(sharedSecret, p.dh.DHNonce...)
	fullKey = append(fullKey, dhRepInfo.ServerDHNonce...)

	// Determine key size based on encryption type
	etype := rawASRep.EncPart.EType
	var keySize int
	switch etype {
	case etypeID.AES256_CTS_HMAC_SHA1_96:
		keySize = 32
	case etypeID.AES128_CTS_HMAC_SHA1_96:
		keySize = 16
	default:
		return nil, fmt.Errorf("unsupported encryption type: %d", etype)
	}

	// Truncate key using PKINIT-specific derivation
	tKey := truncateKey(fullKey, keySize)

	// Decrypt enc-part
	decrypted, err := decryptEncPart(tKey, etype, rawASRep.EncPart.Cipher)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt enc-part: %w", err)
	}

	// Parse EncASRepPart
	// EncASRepPart is wrapped in APPLICATION 25 tag
	var encASRepPartApp asn1.RawValue
	_, err = asn1.Unmarshal(decrypted, &encASRepPartApp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EncASRepPart APPLICATION tag: %w", err)
	}

	var encASRepPart EncASRepPart
	_, err = asn1.Unmarshal(encASRepPartApp.Bytes, &encASRepPart)
	if err != nil {
		return nil, fmt.Errorf("failed to parse EncASRepPart: %w", err)
	}

	return &DecryptedASRep{
		EncPart:    encASRepPart,
		SessionKey: encASRepPart.Key,
		ASRepKey:   tKey,
	}, nil
}

// truncateKey implements the PKINIT key derivation function
// This matches the Python implementation exactly
func truncateKey(value []byte, keySize int) []byte {
	output := make([]byte, 0, keySize)
	currentNum := byte(0)

	for len(output) < keySize {
		h := sha1.New()
		h.Write([]byte{currentNum})
		h.Write(value)
		currentDigest := h.Sum(nil)

		if len(output)+len(currentDigest) > keySize {
			output = append(output, currentDigest[:keySize-len(output)]...)
			break
		}

		output = append(output, currentDigest...)
		currentNum++
	}

	return output
}

// decryptEncPart decrypts the encrypted part using AES-CTS
func decryptEncPart(key []byte, etype int32, ciphertext []byte) ([]byte, error) {
	switch etype {
	case etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96:
		return decryptAESCTS(key, etype, ciphertext, 3) // key usage 3 for AS-REP
	default:
		return nil, fmt.Errorf("unsupported etype: %d", etype)
	}
}

// decryptAESCTS decrypts using AES-CTS mode (Kerberos-style)
func decryptAESCTS(key []byte, etypeID int32, ciphertext []byte, keyUsage uint32) ([]byte, error) {
	// Try manual decryption first (following Python's exact logic)
	manualResult, manualErr := manualDecryptAES(key, etypeID, ciphertext, keyUsage)
	if manualErr == nil {
		return manualResult, nil
	}

	// Fall back to gokrb5
	et, err := crypto.GetEtype(etypeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get etype: %w", err)
	}

	plaintext, err := et.DecryptMessage(key, ciphertext, keyUsage)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
