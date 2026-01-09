package s4u

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/gopkinit/pkg/ccache"
	"github.com/ineffectivecoder/gopkinit/pkg/krb"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// S4U2SelfClient handles S4U2Self impersonation
type S4U2SelfClient struct {
	ccache     *ccache.CCache
	tgt        *ccache.Credential
	kdcAddress string
}

// NewS4U2SelfClient creates a new S4U2Self client
func NewS4U2SelfClient(ccachePath, kdcAddress string) (*S4U2SelfClient, error) {
	cc, err := ccache.ReadCCache(ccachePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read ccache: %w", err)
	}

	tgt, err := cc.GetTGT()
	if err != nil {
		return nil, fmt.Errorf("failed to get TGT from ccache: %w", err)
	}

	return &S4U2SelfClient{
		ccache:     cc,
		tgt:        tgt,
		kdcAddress: kdcAddress,
	}, nil
}

// GetS4U2SelfTicket requests a service ticket impersonating another user
// Based on PKINITtools/gets4uticket.py implementation
func (s *S4U2SelfClient) GetS4U2SelfTicket(targetUser, targetRealm, serviceName, serviceRealm string, outputPath string) error {
	// Convert ticket bytes to gokrb5 Ticket
	ticket, err := s.tgt.ToTicket()
	if err != nil {
		return fmt.Errorf("failed to convert ticket: %w", err)
	}

	// Build PA-FOR-USER
	paForUser, err := s.buildPAForUser(targetUser, targetRealm)
	if err != nil {
		return fmt.Errorf("failed to build PA-FOR-USER: %w", err)
	}

	// Parse service name (format: service/host)
	// PKINITtools uses the target SPN directly in S4U2Self with NAME_TYPE.SRV_INST
	sname, err := parseSPN(serviceName)
	if err != nil {
		return fmt.Errorf("failed to parse SPN: %w", err)
	}

	// Use uppercase realm as PKINITtools does
	realmUpper := strings.ToUpper(s.tgt.Client.Realm)

	// Create minimal config for TGS request
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realmUpper

	// Use gokrb5's built-in NewTGSReq (same approach as U2U which works)
	tgsReq, err := messages.NewTGSReq(
		s.tgt.Client.ToPrincipalName(),
		realmUpper,
		cfg,
		ticket,
		s.tgt.Key,
		sname,
		false, // not renewal
	)
	if err != nil {
		return fmt.Errorf("failed to build TGS-REQ: %w", err)
	}

	// Add PA-FOR-USER padata for S4U2Self
	tgsReq.PAData = append(tgsReq.PAData, paForUser)

	reqBytes, err := tgsReq.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal TGS-REQ: %w", err)
	}

	// Send TGS-REQ
	client := krb.NewKDCClient(s.kdcAddress)
	respBytes, err := client.SendTGSReq(reqBytes)
	if err != nil {
		// Check if this is error 16 (KDC_ERR_PADATA_TYPE_NOSUPP)
		// In S4U2Self context, this typically means delegation is not enabled for this account
		if strings.Contains(err.Error(), "KDC_ERR_PADATA_TYPE_NOSUPP") || strings.Contains(err.Error(), "(16)") {
			return fmt.Errorf("S4U2Self failed - delegation may not be enabled for this account. Original error: %w", err)
		}
		return fmt.Errorf("failed to send TGS-REQ: %w", err)
	}

	// Parse TGS-REP
	tgsRep, err := krb.ParseTGSRep(respBytes)
	if err != nil {
		return fmt.Errorf("failed to parse TGS-REP: %w", err)
	}

	// Decrypt TGS-REP
	encPart, err := krb.DecryptTGSRep(tgsRep, s.tgt.Key)
	if err != nil {
		return fmt.Errorf("failed to decrypt TGS-REP: %w", err)
	}

	// Save to ccache with impersonated user as client principal
	// The S4U2Self ticket is for the impersonated user, not the machine account
	impersonatedPrincipal := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{targetUser},
	}
	if err := s.saveToCCacheForUser(outputPath, &tgsRep.Ticket, encPart, targetRealm, impersonatedPrincipal); err != nil {
		return fmt.Errorf("failed to save ccache: %w", err)
	}

	return nil
}

// buildPAForUser constructs a PA-FOR-USER padata
func (s *S4U2SelfClient) buildPAForUser(username, realm string) (types.PAData, error) {
	// Build checksum data: nameType(4) + username + realm + "Kerberos"
	// Per MS-SFU 2.2.1, the S4UByteArray is: name-type (4 bytes LE) + name + realm + auth-package
	// Note: Impacket uses domain as-is, but domain is typically already uppercase in Kerberos
	checksumData := make([]byte, 4)
	binary.LittleEndian.PutUint32(checksumData, uint32(nametype.KRB_NT_PRINCIPAL))
	checksumData = append(checksumData, []byte(username)...)
	checksumData = append(checksumData, []byte(realm)...)
	checksumData = append(checksumData, []byte("Kerberos")...)

	// Compute RFC 4757 HMAC-MD5 checksum (KERB_CHECKSUM_HMAC_MD5 type -138)
	// Per MS-SFU 2.2.1, this checksum is ALWAYS HMAC-MD5 regardless of session key type
	// The HMAC-MD5 algorithm uses the raw key bytes directly
	checksumValue := computeKerbHMACMD5(s.tgt.Key.KeyValue, 17, checksumData)

	// Build PA-FOR-USER structure with manual GeneralString encoding
	// Go's asn1 package doesn't support generalstring on nested slice elements,
	// so we manually construct the raw ASN.1 bytes
	paBytes := marshalPAForUser(username, realm, checksumValue)

	return types.PAData{
		PADataType:  129, // PA-FOR-USER
		PADataValue: paBytes,
	}, nil
}

// saveToCCacheForUser saves the service ticket to a ccache file with specified client principal
func (s *S4U2SelfClient) saveToCCacheForUser(path string, ticket *messages.Ticket, encPart *messages.EncKDCRepPart, clientRealm string, clientPrincipal types.PrincipalName) error {
	return ccache.WriteCCache(path, *ticket, *encPart, encPart.Key, clientRealm, clientPrincipal)
}

// parseSPN parses a service principal name
func parseSPN(spn string) (types.PrincipalName, error) {
	// SPN format: service/host or service/host@realm
	// We only care about service/host part

	// Simple parsing - split by /
	var components []string
	for i := 0; i < len(spn); i++ {
		if spn[i] == '/' {
			components = append(components, spn[:i])
			components = append(components, spn[i+1:])
			break
		}
	}

	// Single component (no /)
	if len(components) != 2 {
		components = []string{spn}
	}

	return types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: components,
	}, nil
}

// computeKerbHMACMD5 computes the RFC 4757 Kerberos HMAC-MD5 checksum.
// This is used for KERB_CHECKSUM_HMAC_MD5 (checksum type -138 / 0xFFFFFF76).
// Algorithm:
//  1. ksign = HMAC-MD5(key, "signaturekey\x00")
//  2. md5hash = MD5(usage_str(keyusage) + text) where usage_str is 4-byte little-endian keyusage
//  3. checksum = HMAC-MD5(ksign, md5hash)
func computeKerbHMACMD5(key []byte, keyusage uint32, data []byte) []byte {
	// Step 1: Derive signing key
	ksign := hmac.New(md5.New, key)
	ksign.Write([]byte("signaturekey\x00"))
	ksignKey := ksign.Sum(nil)

	// Step 2: Compute MD5 of usage_str + data
	usageBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(usageBytes, keyusage)

	md5Hash := md5.New()
	md5Hash.Write(usageBytes)
	md5Hash.Write(data)
	md5Value := md5Hash.Sum(nil)

	// Step 3: HMAC-MD5(ksign, md5hash)
	finalHmac := hmac.New(md5.New, ksignKey)
	finalHmac.Write(md5Value)
	return finalHmac.Sum(nil)
}

// marshalPAForUser manually constructs PA-FOR-USER-ENC ASN.1 with proper GeneralString tags
// This is necessary because Go's asn1 package doesn't properly support GeneralString (0x1b)
// for nested elements in the way Kerberos requires.
func marshalPAForUser(username, realm string, checksum []byte) []byte {
	// Build from innermost to outermost

	// userName: PrincipalName SEQUENCE
	// name-type: [0] INTEGER 1 (NT_PRINCIPAL)
	nameType := asn1Explicit(0, asn1Integer(1))
	// name-string: [1] SEQUENCE OF GeneralString
	nameStringContent := asn1GeneralString(username)
	nameStringSeq := asn1Sequence(nameStringContent)
	nameString := asn1Explicit(1, nameStringSeq)
	principalName := asn1Sequence(append(nameType, nameString...))
	userName := asn1Explicit(0, principalName)

	// userRealm: [1] GeneralString
	userRealm := asn1Explicit(1, asn1GeneralString(realm))

	// cksum: [2] Checksum SEQUENCE
	// cksumtype: [0] INTEGER -138 (HMAC_MD5)
	cksumType := asn1Explicit(0, asn1Integer(-138))
	// checksum: [1] OCTET STRING
	checksumOctet := asn1Explicit(1, asn1OctetString(checksum))
	checksumSeq := asn1Sequence(append(cksumType, checksumOctet...))
	cksum := asn1Explicit(2, checksumSeq)

	// auth-package: [3] GeneralString "Kerberos"
	authPackage := asn1Explicit(3, asn1GeneralString("Kerberos"))

	// PA-FOR-USER-ENC SEQUENCE
	content := append(userName, userRealm...)
	content = append(content, cksum...)
	content = append(content, authPackage...)
	return asn1Sequence(content)
}

// ASN.1 helper functions

func asn1Sequence(content []byte) []byte {
	return asn1TLV(0x30, content)
}

func asn1Explicit(tag int, content []byte) []byte {
	return asn1TLV(0xa0+byte(tag), content)
}

func asn1Integer(val int) []byte {
	// Handle negative numbers using two's complement
	if val >= 0 && val <= 127 {
		return asn1TLV(0x02, []byte{byte(val)})
	}
	if val >= -128 && val < 0 {
		return asn1TLV(0x02, []byte{byte(val)})
	}
	// For -138: 0xFFFFFF76 in 2 bytes as -138 = 0xFF76
	if val == -138 {
		return asn1TLV(0x02, []byte{0xff, 0x76})
	}
	// General case for larger integers
	var bytes []byte
	v := val
	for v != 0 && v != -1 {
		bytes = append([]byte{byte(v & 0xff)}, bytes...)
		v >>= 8
	}
	// Add sign byte if needed
	if val > 0 && bytes[0]&0x80 != 0 {
		bytes = append([]byte{0}, bytes...)
	}
	if val < 0 && bytes[0]&0x80 == 0 {
		bytes = append([]byte{0xff}, bytes...)
	}
	return asn1TLV(0x02, bytes)
}

func asn1GeneralString(s string) []byte {
	return asn1TLV(0x1b, []byte(s)) // 0x1b = GeneralString tag
}

func asn1OctetString(content []byte) []byte {
	return asn1TLV(0x04, content)
}

func asn1TLV(tag byte, content []byte) []byte {
	length := len(content)
	if length < 128 {
		return append([]byte{tag, byte(length)}, content...)
	}
	// Long form length encoding
	lenBytes := []byte{}
	l := length
	for l > 0 {
		lenBytes = append([]byte{byte(l & 0xff)}, lenBytes...)
		l >>= 8
	}
	return append(append([]byte{tag, 0x80 | byte(len(lenBytes))}, lenBytes...), content...)
}

// PA-FOR-USER ASN.1 structure (kept for reference but not used)
type PAForUserEnc struct {
	UserName    paForUserPrincipal `asn1:"explicit,tag:0"`
	UserRealm   string             `asn1:"generalstring,explicit,tag:1"`
	CkSum       paForUserChecksum  `asn1:"explicit,tag:2"`
	AuthPackage string             `asn1:"generalstring,explicit,tag:3"`
}

type paForUserPrincipal struct {
	NameType   int32                 `asn1:"explicit,tag:0"`
	NameString []paForUserNameString `asn1:"generalstring,explicit,tag:1"`
}

type paForUserNameString string

type paForUserChecksum struct {
	CksumType int32  `asn1:"explicit,tag:0"`
	Checksum  []byte `asn1:"explicit,tag:1"`
}
