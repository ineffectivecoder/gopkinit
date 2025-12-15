package s4u

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/ineffectivecoder/gopkinit/pkg/ccache"
	"github.com/ineffectivecoder/gopkinit/pkg/krb"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
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
	sname, err := parseSPN(serviceName)
	if err != nil {
		return fmt.Errorf("failed to parse SPN: %w", err)
	}

	// Build S4U2Self TGS-REQ
	tgsReq := &krb.TGSRequest{
		Realm:      s.tgt.Client.Realm,
		CName:      s.tgt.Client.ToPrincipalName(),
		TGT:        ticket,
		SessionKey: s.tgt.Key,
		SName:      sname,
		SRealm:     serviceRealm,
		PAData:     []types.PAData{paForUser},
	}

	reqBytes, err := tgsReq.BuildTGSReq()
	if err != nil {
		return fmt.Errorf("failed to build TGS-REQ: %w", err)
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

	// Save to ccache
	if err := s.saveToCCache(outputPath, &tgsRep.Ticket, encPart); err != nil {
		return fmt.Errorf("failed to save ccache: %w", err)
	}

	return nil
}

// buildPAForUser constructs a PA-FOR-USER padata
func (s *S4U2SelfClient) buildPAForUser(username, realm string) (types.PAData, error) {
	// Build checksum data: nameType(4) + username + realm + "Kerberos"
	// Per MS-SFU 2.2.1, the S4UByteArray is: name-type (4 bytes LE) + name + realm + auth-package
	checksumData := make([]byte, 4)
	binary.LittleEndian.PutUint32(checksumData, uint32(nametype.KRB_NT_PRINCIPAL))
	checksumData = append(checksumData, []byte(username)...)
	checksumData = append(checksumData, []byte(realm)...)
	checksumData = append(checksumData, []byte("Kerberos")...)

	// Compute RFC 4757 HMAC-MD5 checksum (KERB_CHECKSUM_HMAC_MD5 type -138)
	// This is NOT a simple HMAC-MD5. It uses the Kerberos HMAC-MD5 algorithm:
	// 1. ksign = HMAC-MD5(key, "signaturekey\x00")
	// 2. md5hash = MD5(usage_str(keyusage) + data) where usage_str is 4-byte LE keyusage
	// 3. checksum = HMAC-MD5(ksign, md5hash)
	// Key usage 17 is used for PA-FOR-USER checksum (S4U)
	checksumValue := computeKerbHMACMD5(s.tgt.Key.KeyValue, 17, checksumData)

	// Build PA-FOR-USER structure
	paForUser := PAForUserEnc{
		UserName: types.PrincipalName{
			NameType:   nametype.KRB_NT_PRINCIPAL,
			NameString: []string{username},
		},
		UserRealm: realm,
		CkSum: types.Checksum{
			CksumType: chksumtype.KERB_CHECKSUM_HMAC_MD5,
			Checksum:  checksumValue,
		},
		AuthPackage: "Kerberos",
	}

	paBytes, err := asn1.Marshal(paForUser)
	if err != nil {
		return types.PAData{}, fmt.Errorf("failed to marshal PA-FOR-USER: %w", err)
	}

	return types.PAData{
		PADataType:  129, // PA-FOR-USER
		PADataValue: paBytes,
	}, nil
}

// saveToCCache saves the service ticket to a ccache file
func (s *S4U2SelfClient) saveToCCache(path string, ticket *messages.Ticket, encPart *messages.EncKDCRepPart) error {
	return ccache.WriteCCache(path, *ticket, *encPart, encPart.Key, s.tgt.Client.Realm, s.tgt.Client.ToPrincipalName())
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

// PA-FOR-USER ASN.1 structure
type PAForUserEnc struct {
	UserName    types.PrincipalName `asn1:"explicit,tag:0"`
	UserRealm   string              `asn1:"generalstring,explicit,tag:1"`
	CkSum       types.Checksum      `asn1:"explicit,tag:2"`
	AuthPackage string              `asn1:"generalstring,explicit,tag:3"`
}
