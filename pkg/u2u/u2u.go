package u2u

import (
	"encoding/asn1"
	"fmt"

	"github.com/ineffectivecoder/gopkinit/pkg/ccache"
	"github.com/ineffectivecoder/gopkinit/pkg/krb"
	"github.com/ineffectivecoder/gopkinit/pkg/pac"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

type U2UClient struct {
	ccache     *ccache.CCache
	tgt        *ccache.Credential
	kdcAddress string
	asrepKey   []byte
}

func NewU2UClient(ccachePath, kdcAddress string, asrepKey []byte) (*U2UClient, error) {
	cc, err := ccache.ReadCCache(ccachePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read ccache: %w", err)
	}

	tgt, err := cc.GetTGT()
	if err != nil {
		return nil, fmt.Errorf("failed to get TGT from ccache: %w", err)
	}

	return &U2UClient{
		ccache:     cc,
		tgt:        tgt,
		kdcAddress: kdcAddress,
		asrepKey:   asrepKey,
	}, nil
}

func (u *U2UClient) GetNTHash() ([]byte, error) {
	ticket, err := u.tgt.ToTicket()
	if err != nil {
		return nil, fmt.Errorf("failed to convert ticket: %w", err)
	}

	// Create minimal config for U2U request
	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = u.tgt.Client.Realm

	// Build U2U TGS-REQ using gokrb5's built-in function
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_UNKNOWN,
		NameString: u.tgt.Client.Components,
	}

	tgsReq, err := messages.NewUser2UserTGSReq(
		u.tgt.Client.ToPrincipalName(),
		u.tgt.Client.Realm,
		cfg,
		ticket,
		u.tgt.Key,
		sname,
		false,  // not renewal
		ticket, // verifying TGT (same as client TGT for U2U)
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build U2U TGS-REQ: %w", err)
	}

	reqBytes, err := tgsReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal TGS-REQ: %w", err)
	}

	client := krb.NewKDCClient(u.kdcAddress)
	respBytes, err := client.SendTGSReq(reqBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to send TGS-REQ: %w", err)
	}

	tgsRep, err := krb.ParseTGSRep(respBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse TGS-REP: %w", err)
	}

	// For U2U, the ticket is encrypted with the TGT session key (not the new session key)
	ntHash, err := u.extractNTHashFromTicket(&tgsRep.Ticket, u.tgt.Key)
	if err != nil {
		return nil, fmt.Errorf("failed to extract NT hash: %w", err)
	}

	return ntHash, nil
}

func (u *U2UClient) extractNTHashFromTicket(ticket *messages.Ticket, key types.EncryptionKey) ([]byte, error) {
	// Decrypt ticket using gokrb5's built-in method
	err := ticket.Decrypt(key)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ticket: %w", err)
	}

	// Now ticket.DecryptedEncPart should be populated
	if len(ticket.DecryptedEncPart.AuthorizationData) == 0 {
		return nil, fmt.Errorf("no authorization data in ticket")
	}

	var adIfRelevant ADIfRelevant
	for _, ad := range ticket.DecryptedEncPart.AuthorizationData {
		if ad.ADType == 1 {
			if _, err := asn1.Unmarshal(ad.ADData, &adIfRelevant); err != nil {
				return nil, fmt.Errorf("failed to unmarshal AD-IF-RELEVANT: %w", err)
			}
			break
		}
	}

	var pacData []byte
	for _, ad := range adIfRelevant {
		if ad.ADType == 128 {
			pacData = ad.ADData
			break
		}
	}

	if pacData == nil {
		return nil, fmt.Errorf("PAC not found in authorization data")
	}

	pacStruct, err := pac.ParsePAC(pacData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PAC: %w", err)
	}

	credBuf := pacStruct.FindBuffer(pac.PACTypeCredentials)
	if credBuf == nil {
		return nil, fmt.Errorf("PAC_CREDENTIAL_INFO not found - TGT may not be from PKINIT")
	}

	fmt.Printf("[DEBUG] Full credentials buffer (%d bytes): %x\n", len(credBuf.Data), credBuf.Data)

	credInfo, err := pac.ParseCredentialInfo(credBuf.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential info: %w", err)
	}

	fmt.Printf("[DEBUG] PAC_CREDENTIAL_INFO Version: %d, EncryptionType: %d, DataLen: %d\n",
		credInfo.Version, credInfo.EncryptionType, len(credInfo.SerializedData))
	fmt.Printf("[DEBUG] AS-REP key: %x\n", u.asrepKey)
	fmt.Printf("[DEBUG] TGT session key: %x\n", u.tgt.Key.KeyValue)
	fmt.Printf("[DEBUG] SerializedData (first 32 bytes): %x\n", credInfo.SerializedData[:min(32, len(credInfo.SerializedData))])

	// Create an EncryptionKey from the AS-REP key bytes
	// Python forces etype 18 (AES256) regardless of what the PAC says
	asrepEncKey := types.EncryptionKey{
		KeyType:  18, // AES256-CTS-HMAC-SHA1-96
		KeyValue: u.asrepKey,
	}

	// Try different key usage numbers with AS-REP key (like Python does)
	// Python uses key usage 16 for PAC credential decryption
	keyUsages := []uint32{16, 11, 9, 2}
	var decrypted []byte
	for _, ku := range keyUsages {
		fmt.Printf("[DEBUG] Trying AS-REP key with usage %d\n", ku)
		dec, err := crypto.DecryptMessage(credInfo.SerializedData, asrepEncKey, ku)
		if err == nil {
			decrypted = dec
			fmt.Printf("[DEBUG] SUCCESS with AS-REP key and usage %d!\n", ku)
			break
		}
	}

	if decrypted == nil {
		return nil, fmt.Errorf("failed to decrypt PAC credentials with AS-REP key")
	}

	credData, err := pac.ParseCredentialData(decrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credential data: %w", err)
	}

	if len(credData.Credentials) == 0 {
		return nil, fmt.Errorf("no credentials found in PAC")
	}

	for _, cred := range credData.Credentials {
		if len(cred.NTPassword) > 0 {
			return cred.NTPassword, nil
		}
	}

	return nil, fmt.Errorf("NT password not found in credentials")
}

type EncTicketPart struct {
	Flags             asn1.BitString      `asn1:"explicit,tag:0"`
	Key               EncryptionKey       `asn1:"explicit,tag:1"`
	CRealm            string              `asn1:"generalstring,explicit,tag:2"`
	CName             PrincipalName       `asn1:"explicit,tag:3"`
	Transited         TransitedEncoding   `asn1:"explicit,tag:4"`
	AuthTime          asn1.RawValue       `asn1:"generalized,explicit,tag:5"`
	StartTime         asn1.RawValue       `asn1:"generalized,explicit,optional,tag:6"`
	EndTime           asn1.RawValue       `asn1:"generalized,explicit,tag:7"`
	RenewTill         asn1.RawValue       `asn1:"generalized,explicit,optional,tag:8"`
	CAddr             []HostAddress       `asn1:"explicit,optional,tag:9"`
	AuthorizationData []AuthorizationData `asn1:"explicit,optional,tag:10"`
}

type EncryptionKey struct {
	KeyType  int32  `asn1:"explicit,tag:0"`
	KeyValue []byte `asn1:"explicit,tag:1"`
}

type PrincipalName struct {
	NameType   int32    `asn1:"explicit,tag:0"`
	NameString []string `asn1:"generalstring,explicit,tag:1"`
}

type TransitedEncoding struct {
	TRType   int32  `asn1:"explicit,tag:0"`
	Contents []byte `asn1:"explicit,tag:1"`
}

type HostAddress struct {
	AddrType int32  `asn1:"explicit,tag:0"`
	Address  []byte `asn1:"explicit,tag:1"`
}

type AuthorizationData struct {
	ADType int32  `asn1:"explicit,tag:0"`
	ADData []byte `asn1:"explicit,tag:1"`
}

type ADIfRelevant []AuthorizationData
