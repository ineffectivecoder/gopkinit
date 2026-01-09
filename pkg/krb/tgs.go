package krb

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/flags"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// TGSRequest represents a TGS-REQ builder
type TGSRequest struct {
	Realm         string
	CName         types.PrincipalName
	TGT           messages.Ticket
	SessionKey    types.EncryptionKey
	SName         types.PrincipalName
	SRealm        string
	EncTktInSKey  bool             // U2U flag
	AdditionalTkt *messages.Ticket // For U2U
	PAData        []types.PAData   // Additional PA-DATA
	KDCOptions    asn1.BitString
	Till          time.Time
}

// BuildTGSReq constructs a TGS-REQ message
func (t *TGSRequest) BuildTGSReq() ([]byte, error) {
	// Build AP-REQ for PA-TGS-REQ
	apReq, err := t.buildAPReq()
	if err != nil {
		return nil, fmt.Errorf("failed to build AP-REQ: %w", err)
	}

	apReqBytes, err := apReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AP-REQ: %w", err)
	}

	// Build TGS-REQ
	tgsReq := messages.TGSReq{}
	tgsReq.ReqBody = t.buildReqBody()
	tgsReq.MsgType = msgtype.KRB_TGS_REQ
	tgsReq.PVNO = 5

	// PA-TGS-REQ (AP-REQ) - padata type 1 per RFC 4120
	paTGSReq := types.PAData{
		PADataType:  1, // PA-TGS-REQ (was incorrectly 2)
		PADataValue: apReqBytes,
	}

	tgsReq.PAData = append([]types.PAData{paTGSReq}, t.PAData...)

	return tgsReq.Marshal()
}

// buildAPReq constructs an AP-REQ for the TGS-REQ
func (t *TGSRequest) buildAPReq() (messages.APReq, error) {
	apReq := messages.APReq{
		PVNO:    5,
		MsgType: msgtype.KRB_AP_REQ,
		Ticket:  t.TGT,
	}

	// AP options (none for TGS-REQ typically)
	apReq.APOptions = types.NewKrbFlags()

	// Build authenticator
	auth := types.Authenticator{
		AVNO:   5,
		CRealm: t.Realm,
		CName:  t.CName,
		CTime:  time.Now().UTC(),
		Cusec:  time.Now().Nanosecond() / 1000,
	}

	// Marshal authenticator
	authBytes, err := auth.Marshal()
	if err != nil {
		return apReq, fmt.Errorf("failed to marshal authenticator: %w", err)
	}

	// Encrypt authenticator with session key
	etype, err := crypto.GetEtype(t.SessionKey.KeyType)
	if err != nil {
		return apReq, fmt.Errorf("failed to get etype: %w", err)
	}

	// Key usage 7: TGS-REQ PA-TGS-REQ AP-REQ Authenticator
	encAuth, _, err := etype.EncryptMessage(t.SessionKey.KeyValue, authBytes, uint32(keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR))
	if err != nil {
		return apReq, fmt.Errorf("failed to encrypt authenticator: %w", err)
	}

	apReq.EncryptedAuthenticator = types.EncryptedData{
		EType:  t.SessionKey.KeyType,
		Cipher: encAuth,
	}

	return apReq, nil
}

// buildReqBody constructs the TGS-REQ body
func (t *TGSRequest) buildReqBody() messages.KDCReqBody {
	body := messages.KDCReqBody{}

	// KDC options
	if t.KDCOptions.Bytes != nil {
		body.KDCOptions = t.KDCOptions
	} else {
		// Default options
		opts := types.NewKrbFlags()
		types.SetFlag(&opts, flags.Forwardable)
		types.SetFlag(&opts, flags.Renewable)
		types.SetFlag(&opts, flags.Canonicalize)
		if t.EncTktInSKey {
			types.SetFlag(&opts, flags.EncTktInSkey)
		}
		body.KDCOptions = opts
	}

	// Service name
	body.SName = t.SName

	// Realm
	if t.SRealm != "" {
		body.Realm = t.SRealm
	} else {
		body.Realm = t.Realm
	}

	// Till time
	if t.Till.IsZero() {
		body.Till = time.Now().UTC().Add(24 * time.Hour)
	} else {
		body.Till = t.Till
	}

	// Nonce
	nonceBig, _ := rand.Int(rand.Reader, big.NewInt(0x7FFFFFFF))
	body.Nonce = int(nonceBig.Int64())

	// Encryption types
	body.EType = []int32{
		int32(etypeID.AES256_CTS_HMAC_SHA1_96),
		int32(etypeID.AES128_CTS_HMAC_SHA1_96),
		int32(etypeID.RC4_HMAC),
	}

	// Additional tickets (for U2U)
	if t.AdditionalTkt != nil {
		body.AdditionalTickets = []messages.Ticket{*t.AdditionalTkt}
	}

	return body
}

// SendTGSReq sends a TGS-REQ and returns the TGS-REP
func (c *KDCClient) SendTGSReq(req []byte) ([]byte, error) {
	// TGS uses same TCP transport as AS
	return c.SendASReq(req)
}

// ParseTGSRep parses a TGS-REP message
func ParseTGSRep(data []byte) (*messages.TGSRep, error) {
	var tgsRep messages.TGSRep
	if err := tgsRep.Unmarshal(data); err != nil {
		// Check if this might be a KRB-ERROR instead
		// Error code 16 in S4U2Self context typically means delegation not enabled
		if strings.Contains(err.Error(), "KDC_ERR_PADATA_TYPE_NOSUPP") || strings.Contains(err.Error(), "(16)") {
			return nil, fmt.Errorf("S4U2Self failed - the account may not have delegation enabled, or the target user may not be delegatable: %w", err)
		}
		return nil, fmt.Errorf("failed to unmarshal TGS-REP: %w", err)
	}

	if tgsRep.MsgType != msgtype.KRB_TGS_REP {
		return nil, fmt.Errorf("expected TGS-REP (msg type 13), got %d", tgsRep.MsgType)
	}

	return &tgsRep, nil
}

// DecryptTGSRep decrypts the encrypted part of a TGS-REP
func DecryptTGSRep(tgsRep *messages.TGSRep, key types.EncryptionKey) (*messages.EncKDCRepPart, error) {
	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, fmt.Errorf("failed to get etype: %w", err)
	}

	// Key usage 8: TGS-REP encrypted part
	plaintext, err := etype.DecryptMessage(key.KeyValue, tgsRep.EncPart.Cipher, uint32(keyusage.TGS_REP_ENCPART_SESSION_KEY))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt TGS-REP: %w", err)
	}

	var encPart messages.EncKDCRepPart
	if err := encPart.Unmarshal(plaintext); err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted part: %w", err)
	}

	return &encPart, nil
}
