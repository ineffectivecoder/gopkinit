package pkinit

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/types"
)

// ASReqOptions contains options for building an AS-REQ
type ASReqOptions struct {
	Domain   string
	Username string
	KDCOpts  []string // default: ["forwardable", "renewable", "renewable-ok"]
}

// KDCReqBody structure
type KDCReqBody struct {
	KDCOptions        asn1.BitString      `asn1:"explicit,tag:0"`
	CName             asn1.RawValue       `asn1:"optional"` // [1] wrapper added manually
	Realm             asn1.RawValue       `asn1:""`         // [2] wrapper added manually
	SName             asn1.RawValue       `asn1:"optional"` // [3] wrapper added manually
	From              time.Time           `asn1:"generalized,optional,explicit,tag:4"`
	Till              time.Time           `asn1:"generalized,explicit,tag:5"`
	RTime             time.Time           `asn1:"generalized,optional,explicit,tag:6"`
	Nonce             int                 `asn1:"explicit,tag:7"`
	EType             []int32             `asn1:"explicit,tag:8"`
	Addresses         []types.HostAddress `asn1:"optional,explicit,tag:9"`
	EncAuthData       asn1.RawValue       `asn1:"optional,explicit,tag:10"`
	AdditionalTickets asn1.RawValue       `asn1:"optional,explicit,tag:11"`
}

// encodePrincipalNameWithTag manually encodes a PrincipalName with GENERALSTRING
// and wraps it with an explicit context tag
func encodePrincipalNameWithTag(tag int, nameType int32, nameStrings []string) (asn1.RawValue, error) {
	// Encode name strings as SEQUENCE OF GENERALSTRING
	var nameStringBytes []byte
	for _, s := range nameStrings {
		// GENERALSTRING tag is 0x1B
		strBytes := append([]byte{0x1B}, encodeLength(len(s))...)
		strBytes = append(strBytes, []byte(s)...)
		nameStringBytes = append(nameStringBytes, strBytes...)
	}
	// Wrap in SEQUENCE
	nameSeqBytes := append([]byte{0x30}, encodeLength(len(nameStringBytes))...)
	nameSeqBytes = append(nameSeqBytes, nameStringBytes...)

	// Encode name type as INTEGER
	nameTypeBytes, err := asn1.Marshal(nameType)
	if err != nil {
		return asn1.RawValue{}, err
	}

	// Build PrincipalName SEQUENCE content:
	// SEQUENCE {
	//   name-type [0] INTEGER,
	//   name-string [1] SEQUENCE OF GENERALSTRING
	// }
	nameTypeTagged := append([]byte{0xA0}, encodeLength(len(nameTypeBytes))...)
	nameTypeTagged = append(nameTypeTagged, nameTypeBytes...)

	nameSeqTagged := append([]byte{0xA1}, encodeLength(len(nameSeqBytes))...)
	nameSeqTagged = append(nameSeqTagged, nameSeqBytes...)

	principalBytes := append(nameTypeTagged, nameSeqTagged...)
	principalSeq := append([]byte{0x30}, encodeLength(len(principalBytes))...)
	principalSeq = append(principalSeq, principalBytes...)

	// Wrap with explicit context tag
	tagByte := byte(0xA0 | tag) // Context-specific, constructed
	wrapped := append([]byte{tagByte}, encodeLength(len(principalSeq))...)
	wrapped = append(wrapped, principalSeq...)

	return asn1.RawValue{FullBytes: wrapped}, nil
}

// encodeGeneralStringWithTag manually encodes a string as GENERALSTRING
// and wraps it with an explicit context tag
func encodeGeneralStringWithTag(tag int, s string) asn1.RawValue {
	// GENERALSTRING tag is 0x1B
	strBytes := append([]byte{0x1B}, encodeLength(len(s))...)
	strBytes = append(strBytes, []byte(s)...)

	// Wrap with explicit context tag
	tagByte := byte(0xA0 | tag) // Context-specific, constructed
	wrapped := append([]byte{tagByte}, encodeLength(len(strBytes))...)
	wrapped = append(wrapped, strBytes...)

	return asn1.RawValue{FullBytes: wrapped}
}

// PAData represents padata structure
type PAData struct {
	PADataType  int32  `asn1:"explicit,tag:1"`
	PADataValue []byte `asn1:"explicit,tag:2"`
}

// PAPacRequest represents PA-PAC-REQUEST
type PAPacRequest struct {
	IncludePAC bool `asn1:"explicit,tag:0"`
}

// ASREQ represents an AS-REQ message (without APPLICATION wrapper)
type ASREQ struct {
	PVNO    int        `asn1:"explicit,tag:1"`
	MsgType int        `asn1:"explicit,tag:2"`
	PAData  []PAData   `asn1:"optional,explicit,tag:3"`
	ReqBody KDCReqBody `asn1:"explicit,tag:4"`
}

// BuildASReq builds an AS-REQ message with PKINIT padata
func (p *PKINITClient) BuildASReq(opts ASReqOptions) ([]byte, error) {
	if opts.KDCOpts == nil {
		opts.KDCOpts = []string{"forwardable", "renewable", "renewable-ok"}
	}

	now := time.Now().UTC()

	// Ensure realm is uppercase
	realm := strings.ToUpper(opts.Domain)

	// Build KDC-REQ-BODY
	// Manually encode PrincipalNames with GENERALSTRING and explicit tags
	cnameRaw, err := encodePrincipalNameWithTag(1, nametype.KRB_NT_PRINCIPAL, []string{opts.Username})
	if err != nil {
		return nil, fmt.Errorf("failed to encode cname: %w", err)
	}

	snameRaw, err := encodePrincipalNameWithTag(3, nametype.KRB_NT_SRV_INST, []string{"krbtgt", realm})
	if err != nil {
		return nil, fmt.Errorf("failed to encode sname: %w", err)
	}

	realmRaw := encodeGeneralStringWithTag(2, realm)

	// Build KDC options bit string
	kdcOpts := makeKDCOptions(opts.KDCOpts)

	// Generate nonce
	nonceInt, err := rand.Int(rand.Reader, big.NewInt(0x7FFFFFFF))
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	nonce := int(nonceInt.Int64())

	reqBody := KDCReqBody{
		KDCOptions: kdcOpts,
		CName:      cnameRaw,
		Realm:      realmRaw,
		SName:      snameRaw,
		Till:       now.Add(24 * time.Hour),
		RTime:      now.Add(24 * time.Hour),
		Nonce:      nonce,
		EType:      []int32{18, 17}, // AES256-CTS-HMAC-SHA1-96, AES128-CTS-HMAC-SHA1-96
	}

	// Encode req-body for checksum
	reqBodyBytes, err := asn1.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal req-body: %w", err)
	}

	// Compute SHA1 checksum of req-body
	h := sha1.New()
	h.Write(reqBodyBytes)
	paChecksum := h.Sum(nil)

	// Generate authenticator nonce
	authNonceInt, err := rand.Int(rand.Reader, big.NewInt(0x7FFFFFFF))
	if err != nil {
		return nil, fmt.Errorf("failed to generate auth nonce: %w", err)
	}
	authNonce := int(authNonceInt.Int64())

	// Build PKAuthenticator
	pkAuth := PKAuthenticator{
		Cusec:      now.Nanosecond() / 1000,
		Ctime:      now.Truncate(time.Second),
		Nonce:      authNonce,
		PaChecksum: paChecksum,
	}

	// Get DH public key info
	pubKeyInfo, err := p.dh.GetPublicKeyInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get public key info: %w", err)
	}

	// Build AuthPack
	authPack := AuthPack{
		PKAuthenticator:   pkAuth,
		ClientPublicValue: pubKeyInfo,
		ClientDHNonce:     p.dh.DHNonce,
	}

	authPackBytes, err := asn1.Marshal(authPack)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AuthPack: %w", err)
	}

	// Sign AuthPack (wrapped in ContentInfo - matches gettgtpkinit.py)
	signedAuthPack, err := SignAuthPack(authPackBytes, p.cert, p.privKey, true)
	if err != nil {
		return nil, fmt.Errorf("failed to sign AuthPack: %w", err)
	}

	// Build PA_PK_AS_REQ with manual IMPLICIT tagging
	// Per RFC 4556, signedAuthPack is [0] IMPLICIT OCTET STRING
	// The signedAuthPack is a ContentInfo structure that needs IMPLICIT [0] tagging
	// Python's asn1crypto library handles this automatically, but Go's encoding/asn1
	// doesn't support implicit tagging on Marshal, so we construct it manually:
	//   [0] IMPLICIT means: tag the content as 0x80 (context-specific, primitive, tag 0)
	//   and wrap in SEQUENCE (0x30)

	// Construct [0] IMPLICIT tag (0x80 = context-specific, primitive, tag 0)
	implicitPayload := append([]byte{0x80}, encodeLength(len(signedAuthPack))...)
	implicitPayload = append(implicitPayload, signedAuthPack...)

	// Wrap in SEQUENCE
	paPkAsReqBytes := append([]byte{0x30}, encodeLength(len(implicitPayload))...)
	paPkAsReqBytes = append(paPkAsReqBytes, implicitPayload...)

	// Build PA-PAC-REQUEST
	paPacReq := PAPacRequest{
		IncludePAC: true,
	}

	paPacReqBytes, err := asn1.Marshal(paPacReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal PA-PAC-REQUEST: %w", err)
	}

	// Build padata
	paData := []PAData{
		{
			PADataType:  128, // PA-PAC-REQUEST
			PADataValue: paPacReqBytes,
		},
		{
			PADataType:  16, // PA-PK-AS-REQ
			PADataValue: paPkAsReqBytes,
		},
	}

	// Build AS-REQ
	asReq := ASREQ{
		PVNO:    5,
		MsgType: 10, // AS-REQ
		PAData:  paData,
		ReqBody: reqBody,
	}

	// Marshal the AS-REQ body (this is a SEQUENCE)
	asReqBytes, err := asn1.Marshal(asReq)
	if err != nil {
		return nil, err
	}

	// Wrap with APPLICATION 10 tag per RFC 4120
	// AS-REQ ::= [APPLICATION 10] KDC-REQ
	// Manually construct the APPLICATION tag
	// Tag byte: class=APPLICATION(01), constructed=1, tag=10(01010) = 01101010 = 0x6a
	result := make([]byte, 0, len(asReqBytes)+10)
	result = append(result, 0x6a) // APPLICATION 10, constructed

	// Length encoding (long form for lengths >= 128)
	if len(asReqBytes) < 128 {
		result = append(result, byte(len(asReqBytes)))
	} else {
		lenBytes := encodeLength(len(asReqBytes))
		result = append(result, lenBytes...)
	}
	result = append(result, asReqBytes...)
	return result, nil
}

// makeKDCOptions creates a bit string from option names
func makeKDCOptions(opts []string) asn1.BitString {
	// KDC option bit positions (RFC 4120)
	optMap := map[string]int{
		"forwardable":     1,
		"forwarded":       2,
		"proxiable":       3,
		"proxy":           4,
		"allow-postdate":  5,
		"postdated":       6,
		"renewable":       8,
		"renewable-ok":    27,
		"enc-tkt-in-skey": 28,
		"renew":           30,
		"validate":        31,
	}

	// Create a 32-bit array (KDC options is 32 bits)
	bits := make([]byte, 4)

	for _, opt := range opts {
		if pos, ok := optMap[opt]; ok {
			bytePos := pos / 8
			bitPos := 7 - (pos % 8)
			bits[bytePos] |= 1 << bitPos
		}
	}

	return asn1.BitString{
		Bytes:     bits,
		BitLength: 32,
	}
}

// encodeLength encodes an ASN.1 length in long form
func encodeLength(length int) []byte {
	if length < 128 {
		return []byte{byte(length)}
	}

	// Long form: first byte has high bit set and indicates number of length bytes
	var lenBytes []byte
	for l := length; l > 0; l >>= 8 {
		lenBytes = append([]byte{byte(l & 0xff)}, lenBytes...)
	}

	return append([]byte{byte(0x80 | len(lenBytes))}, lenBytes...)
}

// PKINITClient holds the PKINIT client state
type PKINITClient struct {
	cert    *x509.Certificate
	privKey crypto.PrivateKey
	issuer  string
	dh      *DirtyDH
}
