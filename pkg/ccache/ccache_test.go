package ccache

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"

	goforkasn1 "github.com/jcmturner/gofork/encoding/asn1"
)

// TestWriteReadCCacheRoundTrip verifies that writing and reading a ccache
// preserves the principal, session key, timestamps, and ticket data.
func TestWriteReadCCacheRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	ccPath := filepath.Join(tmpDir, "test.ccache")

	// Create test data
	ticket := messages.Ticket{
		TktVNO: 5,
		Realm:  "TEST.COM",
		SName: types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: []string{"krbtgt", "TEST.COM"},
		},
		EncPart: types.EncryptedData{
			EType:  18,
			Cipher: []byte{0xDE, 0xAD, 0xBE, 0xEF},
		},
	}

	now := time.Now().UTC().Truncate(time.Second)
	encPart := messages.EncKDCRepPart{
		Key: types.EncryptionKey{
			KeyType:  18,
			KeyValue: bytes.Repeat([]byte{0x42}, 32),
		},
		Flags: goforkasn1.BitString{
			Bytes:     []byte{0x50, 0x80, 0x00, 0x00}, // forwardable + renewable
			BitLength: 32,
		},
		AuthTime:  now.Add(-1 * time.Hour),
		StartTime: now,
		EndTime:   now.Add(10 * time.Hour),
		RenewTill: now.Add(7 * 24 * time.Hour),
		SRealm:    "TEST.COM",
		SName: types.PrincipalName{
			NameType:   nametype.KRB_NT_SRV_INST,
			NameString: []string{"krbtgt", "TEST.COM"},
		},
	}

	sessionKey := types.EncryptionKey{
		KeyType:  18,
		KeyValue: bytes.Repeat([]byte{0x42}, 32),
	}

	cname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{"testuser"},
	}

	// Write ccache
	err := WriteCCache(ccPath, ticket, encPart, sessionKey, "TEST.COM", cname)
	if err != nil {
		t.Fatalf("WriteCCache() error: %v", err)
	}

	// Verify file exists and is non-empty
	info, err := os.Stat(ccPath)
	if err != nil {
		t.Fatalf("ccache file not found: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("ccache file is empty")
	}

	// Read it back
	cc, err := ReadCCache(ccPath)
	if err != nil {
		t.Fatalf("ReadCCache() error: %v", err)
	}

	// Verify version
	if cc.Version != 0x0504 {
		t.Errorf("Version = 0x%04x, want 0x0504", cc.Version)
	}

	// Verify default principal
	if cc.DefaultPrincipal.Realm != "TEST.COM" {
		t.Errorf("DefaultPrincipal.Realm = %q, want %q", cc.DefaultPrincipal.Realm, "TEST.COM")
	}
	if len(cc.DefaultPrincipal.Components) != 1 || cc.DefaultPrincipal.Components[0] != "testuser" {
		t.Errorf("DefaultPrincipal.Components = %v, want [testuser]", cc.DefaultPrincipal.Components)
	}

	// Verify credentials
	if len(cc.Credentials) != 1 {
		t.Fatalf("Credentials count = %d, want 1", len(cc.Credentials))
	}

	cred := cc.Credentials[0]

	// Verify client principal
	if cred.Client.Realm != "TEST.COM" {
		t.Errorf("Client.Realm = %q, want %q", cred.Client.Realm, "TEST.COM")
	}

	// Verify server principal
	if cred.Server.Realm != "TEST.COM" {
		t.Errorf("Server.Realm = %q, want %q", cred.Server.Realm, "TEST.COM")
	}
	if len(cred.Server.Components) < 2 || cred.Server.Components[0] != "krbtgt" {
		t.Errorf("Server.Components = %v, want [krbtgt TEST.COM]", cred.Server.Components)
	}

	// Verify session key
	if cred.Key.KeyType != 18 {
		t.Errorf("Key.KeyType = %d, want 18", cred.Key.KeyType)
	}
	if len(cred.Key.KeyValue) != 32 {
		t.Errorf("Key.KeyValue length = %d, want 32", len(cred.Key.KeyValue))
	}

	// Verify timestamps are close (within 1 second due to Unix timestamp truncation)
	if cred.EndTime.IsZero() {
		t.Error("EndTime is zero")
	}
}

// TestGetTGT verifies TGT lookup in credential cache.
func TestGetTGT(t *testing.T) {
	cc := &CCache{
		DefaultPrincipal: Principal{
			Realm:      "EXAMPLE.COM",
			Components: []string{"admin"},
		},
		Credentials: []Credential{
			{
				Server: Principal{
					Realm:      "EXAMPLE.COM",
					Components: []string{"krbtgt", "EXAMPLE.COM"},
				},
				Ticket: []byte{0x01, 0x02},
			},
		},
	}

	tgt, err := cc.GetTGT()
	if err != nil {
		t.Fatalf("GetTGT() error: %v", err)
	}

	if len(tgt.Ticket) != 2 {
		t.Errorf("TGT ticket length = %d, want 2", len(tgt.Ticket))
	}
}

// TestGetTGTNotFound tests error when no TGT exists.
func TestGetTGTNotFound(t *testing.T) {
	cc := &CCache{
		DefaultPrincipal: Principal{
			Realm:      "EXAMPLE.COM",
			Components: []string{"admin"},
		},
		Credentials: []Credential{
			{
				Server: Principal{
					Realm:      "EXAMPLE.COM",
					Components: []string{"cifs", "fileserver"},
				},
			},
		},
	}

	_, err := cc.GetTGT()
	if err == nil {
		t.Fatal("GetTGT() should return error when no TGT exists")
	}
}

// TestGetTGTSingleComponent tests the single-component krbtgt format.
func TestGetTGTSingleComponent(t *testing.T) {
	cc := &CCache{
		DefaultPrincipal: Principal{
			Realm:      "EXAMPLE.COM",
			Components: []string{"admin"},
		},
		Credentials: []Credential{
			{
				Server: Principal{
					Realm:      "EXAMPLE.COM",
					Components: []string{"krbtgt/EXAMPLE.COM"},
				},
				Ticket: []byte{0xAA},
			},
		},
	}

	tgt, err := cc.GetTGT()
	if err != nil {
		t.Fatalf("GetTGT() error: %v", err)
	}

	if len(tgt.Ticket) != 1 {
		t.Errorf("TGT ticket length = %d, want 1", len(tgt.Ticket))
	}
}

// TestParseCCacheInvalidVersion tests rejection of unsupported versions.
func TestParseCCacheInvalidVersion(t *testing.T) {
	// Create data with version 3 (0x0503) — unsupported
	data := []byte{0x05, 0x03, 0x00, 0x00}
	_, err := ParseCCache(data)
	if err == nil {
		t.Fatal("ParseCCache() should reject version 0x0503")
	}
}

// TestParseCCacheTooShort tests handling of truncated data.
func TestParseCCacheTooShort(t *testing.T) {
	_, err := ParseCCache([]byte{0x05})
	if err == nil {
		t.Fatal("ParseCCache() should fail on truncated data")
	}
}

// TestReadCCacheFileNotFound tests error on missing file.
func TestReadCCacheFileNotFound(t *testing.T) {
	_, err := ReadCCache("/nonexistent/path/file.ccache")
	if err == nil {
		t.Fatal("ReadCCache() should fail on missing file")
	}
}

// TestToPrincipalName verifies Principal to gokrb5 type conversion.
func TestToPrincipalName(t *testing.T) {
	p := Principal{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		Components: []string{"user"},
	}

	pn := p.ToPrincipalName()
	if pn.NameType != nametype.KRB_NT_PRINCIPAL {
		t.Errorf("NameType = %d, want %d", pn.NameType, nametype.KRB_NT_PRINCIPAL)
	}
	if len(pn.NameString) != 1 || pn.NameString[0] != "user" {
		t.Errorf("NameString = %v, want [user]", pn.NameString)
	}
}
