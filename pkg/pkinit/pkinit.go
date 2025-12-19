package pkinit

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"fmt"

	"github.com/ineffectivecoder/gopkinit/pkg/cert"
	"github.com/ineffectivecoder/gopkinit/pkg/krb"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// TGTResult contains the result of a TGT request
type TGTResult struct {
	Ticket     messages.Ticket
	EncPart    EncASRepPart
	SessionKey types.EncryptionKey
	ASRepKey   string // Hex-encoded, for getnthash
	ASRepBytes []byte // Raw AS-REP for debugging
	Realm      string
	CName      types.PrincipalName
}

// NewFromPFX creates a new PKINIT client from a PFX file
func NewFromPFX(pfxPath, password string) (*PKINITClient, error) {
	bundle, err := cert.LoadPFX(pfxPath, password)
	if err != nil {
		return nil, fmt.Errorf("failed to load PFX: %w", err)
	}

	return newFromCertBundle(bundle)
}

// NewFromPFXData creates a new PKINIT client from PFX data bytes
func NewFromPFXData(pfxData []byte, password string) (*PKINITClient, error) {
	bundle, err := cert.LoadPFXData(pfxData, password)
	if err != nil {
		return nil, fmt.Errorf("failed to load PFX data: %w", err)
	}

	return newFromCertBundle(bundle)
}

// newFromCertBundle creates a PKINIT client from a certificate bundle
func newFromCertBundle(bundle *cert.CertificateBundle) (*PKINITClient, error) {
	// Initialize DH with static parameters
	dhParams := StaticDHParams()
	dh, err := NewDirtyDH(dhParams)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize DH: %w", err)
	}

	return &PKINITClient{
		cert:    bundle.Certificate,
		privKey: bundle.PrivateKey,
		issuer:  bundle.Issuer,
		dh:      dh,
	}, nil
}

// GetTGT requests a TGT from the KDC using PKINIT
func (p *PKINITClient) GetTGT(domain, username, kdcAddress, proxyAddr string) (*TGTResult, error) {
	// Build AS-REQ
	opts := ASReqOptions{
		Domain:   domain,
		Username: username,
		KDCOpts:  []string{"forwardable", "renewable", "renewable-ok"},
	}

	asReqBytes, err := p.BuildASReq(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to build AS-REQ: %w", err)
	}

	// Send AS-REQ to KDC
	client := krb.NewKDCClient(kdcAddress)
	if proxyAddr != "" {
		client.SetProxy(proxyAddr)
	}
	asRepBytes, err := client.SendASReq(asReqBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to send AS-REQ: %w", err)
	}

	// Check if response is KRB-ERROR instead of AS-REP
	var appTag asn1.RawValue
	_, err = asn1.Unmarshal(asRepBytes, &appTag)
	if err != nil {
		return nil, fmt.Errorf("failed to parse KDC response: %w", err)
	}

	// APPLICATION 30 = KRB-ERROR, APPLICATION 11 = AS-REP
	if appTag.Tag == 30 {
		return nil, parseKRBError(asRepBytes)
	}

	if appTag.Tag != 11 {
		return nil, fmt.Errorf("unexpected response tag: %d (expected 11 for AS-REP or 30 for KRB-ERROR)", appTag.Tag)
	}

	// Decrypt AS-REP
	decrypted, err := p.DecryptASRep(asRepBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt AS-REP: %w", err)
	}

	// Strip the APPLICATION 11 tag wrapper from AS-REP for parsing
	var appWrapper asn1.RawValue
	_, err = asn1.Unmarshal(asRepBytes, &appWrapper)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AS-REP wrapper: %w", err)
	}

	// Parse the full AS-REP to extract the ticket
	var rawASRep struct {
		PVNO    int `asn1:"explicit,tag:0"`
		MsgType int `asn1:"explicit,tag:1"`
		PAData  []struct {
			PADataType  int32  `asn1:"explicit,tag:1"`
			PADataValue []byte `asn1:"explicit,tag:2"`
		} `asn1:"optional,explicit,tag:2"`
		CRealm    string              `asn1:"generalstring,explicit,tag:3"`
		CName     types.PrincipalName `asn1:"explicit,tag:4"`
		TicketRaw asn1.RawValue       `asn1:"explicit,tag:5"`
		EncPart   EncryptedData       `asn1:"explicit,tag:6"`
	}

	_, err = asn1.Unmarshal(appWrapper.Bytes, &rawASRep)
	if err != nil {
		return nil, fmt.Errorf("failed to parse AS-REP for ticket: %w", err)
	}

	// Parse the ticket - it should have APPLICATION 1 tag
	var ticketApp asn1.RawValue
	_, err = asn1.Unmarshal(rawASRep.TicketRaw.Bytes, &ticketApp)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ticket wrapper: %w", err)
	}

	var ticket messages.Ticket
	_, err = asn1.Unmarshal(ticketApp.Bytes, &ticket)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ticket: %w", err)
	}

	return &TGTResult{
		Ticket:     ticket,
		EncPart:    decrypted.EncPart,
		SessionKey: decrypted.SessionKey,
		ASRepKey:   hex.EncodeToString(decrypted.ASRepKey),
		ASRepBytes: asRepBytes,
		Realm:      rawASRep.CRealm,
		CName:      rawASRep.CName,
	}, nil
}

// GetCertificate returns the certificate being used
func (p *PKINITClient) GetCertificate() *x509.Certificate {
	return p.cert
}

// GetPrivateKey returns the private key being used
func (p *PKINITClient) GetPrivateKey() crypto.PrivateKey {
	return p.privKey
}

// GetIssuer returns the issuer common name
func (p *PKINITClient) GetIssuer() string {
	return p.issuer
}

// parseKRBError parses a KRB-ERROR message and returns a descriptive error
func parseKRBError(data []byte) error {
	var appWrapper asn1.RawValue
	_, err := asn1.Unmarshal(data, &appWrapper)
	if err != nil {
		return fmt.Errorf("KRB-ERROR received but failed to parse: %w", err)
	}

	var krbError struct {
		PVNO      int                 `asn1:"explicit,tag:0"`
		MsgType   int                 `asn1:"explicit,tag:1"`
		CTime     asn1.RawValue       `asn1:"optional,explicit,tag:2"`
		Cusec     int                 `asn1:"optional,explicit,tag:3"`
		STime     asn1.RawValue       `asn1:"explicit,tag:4"`
		Susec     int                 `asn1:"explicit,tag:5"`
		ErrorCode int32               `asn1:"explicit,tag:6"`
		CRealm    string              `asn1:"optional,generalstring,explicit,tag:7"`
		CName     asn1.RawValue       `asn1:"optional,explicit,tag:8"`
		Realm     string              `asn1:"generalstring,explicit,tag:9"`
		SName     types.PrincipalName `asn1:"explicit,tag:10"`
		EText     string              `asn1:"optional,generalstring,explicit,tag:11"`
		EData     []byte              `asn1:"optional,explicit,tag:12"`
	}

	_, err = asn1.Unmarshal(appWrapper.Bytes, &krbError)
	if err != nil {
		return fmt.Errorf("KRB-ERROR received but failed to parse structure: %w", err)
	}

	errorName := getKerberosErrorName(krbError.ErrorCode)
	if krbError.EText != "" {
		return fmt.Errorf("KDC returned error: %s (%d) - %s", errorName, krbError.ErrorCode, krbError.EText)
	}
	return fmt.Errorf("KDC returned error: %s (%d)", errorName, krbError.ErrorCode)
}

// getKerberosErrorName returns the name of a Kerberos error code
func getKerberosErrorName(code int32) string {
	// Common Kerberos error codes
	errors := map[int32]string{
		6:  "KDC_ERR_C_PRINCIPAL_UNKNOWN",
		7:  "KDC_ERR_S_PRINCIPAL_UNKNOWN",
		12: "KDC_ERR_POLICY",
		14: "KDC_ERR_ETYPE_NOSUPP",
		16: "KDC_ERR_PADATA_TYPE_NOSUPP",
		17: "KDC_ERR_PREAUTH_FAILED",
		18: "KDC_ERR_CLIENT_REVOKED",
		23: "KDC_ERR_KEY_EXPIRED",
		24: "KDC_ERR_PREAUTH_REQUIRED",
		25: "KDC_ERR_SERVER_NOMATCH",
		31: "KRB_AP_ERR_BAD_INTEGRITY",
		32: "KRB_AP_ERR_TKT_EXPIRED",
		37: "KRB_AP_ERR_SKEW",
		41: "KRB_AP_ERR_BADKEYVER",
		60: "KDC_ERR_PREAUTH_EXPIRED",
		85: "KDC_ERR_CLIENT_NOT_TRUSTED",
	}

	if name, ok := errors[code]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN_ERROR_%d", code)
}
