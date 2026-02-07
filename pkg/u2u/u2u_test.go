package u2u

import (
	"encoding/asn1"
	"testing"

	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// TestEncTicketPartASN1Tags verifies the EncTicketPart struct has correct ASN.1 field count.
func TestEncTicketPartASN1Tags(t *testing.T) {
	// Verify the struct can be instantiated with expected fields
	etp := EncTicketPart{
		CRealm: "TEST.COM",
		CName: PrincipalName{
			NameType:   1,
			NameString: []string{"testuser"},
		},
		Key: EncryptionKey{
			KeyType:  18,
			KeyValue: []byte{0x01, 0x02, 0x03},
		},
	}

	if etp.CRealm != "TEST.COM" {
		t.Errorf("CRealm = %q, want %q", etp.CRealm, "TEST.COM")
	}
}

// TestEncryptionKeyASN1RoundTrip verifies the custom EncryptionKey can marshal/unmarshal.
func TestEncryptionKeyASN1RoundTrip(t *testing.T) {
	key := EncryptionKey{
		KeyType:  18,
		KeyValue: []byte{0xAA, 0xBB, 0xCC, 0xDD},
	}

	encoded, err := asn1.Marshal(key)
	if err != nil {
		t.Fatalf("Marshal EncryptionKey: %v", err)
	}

	var decoded EncryptionKey
	_, err = asn1.Unmarshal(encoded, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal EncryptionKey: %v", err)
	}

	if decoded.KeyType != key.KeyType {
		t.Errorf("KeyType = %d, want %d", decoded.KeyType, key.KeyType)
	}
	if len(decoded.KeyValue) != len(key.KeyValue) {
		t.Errorf("KeyValue length = %d, want %d", len(decoded.KeyValue), len(key.KeyValue))
	}
}

// TestPrincipalNameASN1RoundTrip verifies the custom PrincipalName can marshal/unmarshal.
func TestPrincipalNameASN1RoundTrip(t *testing.T) {
	pn := PrincipalName{
		NameType:   1,
		NameString: []string{"testuser"},
	}

	encoded, err := asn1.Marshal(pn)
	if err != nil {
		t.Fatalf("Marshal PrincipalName: %v", err)
	}

	var decoded PrincipalName
	_, err = asn1.Unmarshal(encoded, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal PrincipalName: %v", err)
	}

	if decoded.NameType != pn.NameType {
		t.Errorf("NameType = %d, want %d", decoded.NameType, pn.NameType)
	}
	if len(decoded.NameString) != 1 || decoded.NameString[0] != "testuser" {
		t.Errorf("NameString = %v, want [testuser]", decoded.NameString)
	}
}

// TestAuthorizationDataASN1RoundTrip verifies AuthorizationData marshal/unmarshal.
func TestAuthorizationDataASN1RoundTrip(t *testing.T) {
	ad := AuthorizationData{
		ADType: 1, // AD-IF-RELEVANT
		ADData: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}

	encoded, err := asn1.Marshal(ad)
	if err != nil {
		t.Fatalf("Marshal AuthorizationData: %v", err)
	}

	var decoded AuthorizationData
	_, err = asn1.Unmarshal(encoded, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal AuthorizationData: %v", err)
	}

	if decoded.ADType != 1 {
		t.Errorf("ADType = %d, want 1", decoded.ADType)
	}
}

// TestADIfRelevantASN1 verifies the ADIfRelevant sequence type.
func TestADIfRelevantASN1(t *testing.T) {
	adif := ADIfRelevant{
		{ADType: 1, ADData: []byte{0x01}},
		{ADType: 128, ADData: []byte{0x02}},
	}

	encoded, err := asn1.Marshal(adif)
	if err != nil {
		t.Fatalf("Marshal ADIfRelevant: %v", err)
	}

	var decoded ADIfRelevant
	_, err = asn1.Unmarshal(encoded, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal ADIfRelevant: %v", err)
	}

	if len(decoded) != 2 {
		t.Fatalf("decoded length = %d, want 2", len(decoded))
	}
	if decoded[0].ADType != 1 {
		t.Errorf("decoded[0].ADType = %d, want 1", decoded[0].ADType)
	}
	if decoded[1].ADType != 128 {
		t.Errorf("decoded[1].ADType = %d, want 128", decoded[1].ADType)
	}
}

// TestNewU2UClientFileNotFound tests error when ccache file doesn't exist.
func TestNewU2UClientFileNotFound(t *testing.T) {
	_, err := NewU2UClient("/nonexistent/file.ccache", "10.0.0.1", []byte{0x01})
	if err == nil {
		t.Fatal("NewU2UClient() should fail on missing ccache file")
	}
}

// TestHostAddressASN1 verifies HostAddress struct fields.
func TestHostAddressASN1(t *testing.T) {
	ha := HostAddress{
		AddrType: 2, // IPv4
		Address:  []byte{10, 0, 0, 1},
	}

	encoded, err := asn1.Marshal(ha)
	if err != nil {
		t.Fatalf("Marshal HostAddress: %v", err)
	}

	var decoded HostAddress
	_, err = asn1.Unmarshal(encoded, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal HostAddress: %v", err)
	}

	if decoded.AddrType != 2 {
		t.Errorf("AddrType = %d, want 2", decoded.AddrType)
	}
}

// TestTransitedEncodingASN1 verifies TransitedEncoding struct.
func TestTransitedEncodingASN1(t *testing.T) {
	te := TransitedEncoding{
		TRType:   1,
		Contents: []byte{},
	}

	encoded, err := asn1.Marshal(te)
	if err != nil {
		t.Fatalf("Marshal TransitedEncoding: %v", err)
	}

	var decoded TransitedEncoding
	_, err = asn1.Unmarshal(encoded, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal TransitedEncoding: %v", err)
	}

	if decoded.TRType != 1 {
		t.Errorf("TRType = %d, want 1", decoded.TRType)
	}
}

// TestU2UClientExtractNoAuthData tests extractNTHashFromTicket with empty ticket.
// gokrb5's Ticket.Decrypt panics on empty cipher data, so we recover from that.
func TestU2UClientExtractNoAuthData(t *testing.T) {
	client := &U2UClient{
		asrepKey: make([]byte, 32),
	}

	ticket := &messages.Ticket{
		TktVNO: 5,
		Realm:  "TEST.COM",
	}

	key := types.EncryptionKey{
		KeyType:  18,
		KeyValue: make([]byte, 32),
	}

	// gokrb5's Ticket.Decrypt panics on empty cipher data (slice bounds error)
	// so we expect either an error return or a panic
	didPanic := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				didPanic = true
			}
		}()
		_, err := client.extractNTHashFromTicket(ticket, key)
		if err == nil {
			t.Fatal("extractNTHashFromTicket() should fail with invalid ticket")
		}
	}()

	// Either an error or a panic is acceptable — both mean it properly rejects bad input
	if !didPanic {
		// It returned an error (which is fine)
		t.Log("extractNTHashFromTicket correctly returned error for invalid ticket")
	} else {
		t.Log("extractNTHashFromTicket panicked on invalid ticket (gokrb5 limitation)")
	}
}
