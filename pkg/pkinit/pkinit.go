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
