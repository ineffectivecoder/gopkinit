package s4u

import (
"crypto/hmac"
"crypto/md5"
"encoding/asn1"
"encoding/binary"
"fmt"

"github.com/ineffectivecoder/gopkinit/pkg/ccache"
"github.com/ineffectivecoder/gopkinit/pkg/krb"
"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
"github.com/jcmturner/gokrb5/v8/iana/nametype"
"github.com/jcmturner/gokrb5/v8/messages"
"github.com/jcmturner/gokrb5/v8/types"
)

// S4U2SelfClient handles S4U2Self impersonation
type S4U2SelfClient struct {
	ccache      *ccache.CCache
	tgt         *ccache.Credential
	kdcAddress  string
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
	checksumData := make([]byte, 4)
	binary.LittleEndian.PutUint32(checksumData, uint32(nametype.KRB_NT_PRINCIPAL))
	checksumData = append(checksumData, []byte(username)...)
	checksumData = append(checksumData, []byte(realm)...)
	checksumData = append(checksumData, []byte("Kerberos")...)

	// Compute HMAC-MD5 checksum
	h := hmac.New(md5.New, s.tgt.Key.KeyValue)
	h.Write(checksumData)
	checksumValue := h.Sum(nil)

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

// PA-FOR-USER ASN.1 structure
type PAForUserEnc struct {
	UserName    types.PrincipalName `asn1:"explicit,tag:0"`
	UserRealm   string              `asn1:"generalstring,explicit,tag:1"`
	CkSum       types.Checksum      `asn1:"explicit,tag:2"`
	AuthPackage string              `asn1:"generalstring,explicit,tag:3"`
}
