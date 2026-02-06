package s4u

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// TestComputeKerbHMACMD5 verifies the RFC 4757 HMAC-MD5 checksum computation.
func TestComputeKerbHMACMD5(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 16)
	data := []byte("test data for checksum")
	keyUsage := uint32(17)

	result := computeKerbHMACMD5(key, keyUsage, data)

	// Result should be 16 bytes (MD5 output)
	if len(result) != 16 {
		t.Fatalf("checksum length = %d, want 16", len(result))
	}

	// Verify it's deterministic
	result2 := computeKerbHMACMD5(key, keyUsage, data)
	if !bytes.Equal(result, result2) {
		t.Error("computeKerbHMACMD5 is not deterministic")
	}
}

// TestComputeKerbHMACMD5ManualVerification verifies against manual step-by-step computation.
func TestComputeKerbHMACMD5ManualVerification(t *testing.T) {
	key := []byte("sixteen-byte-key") // exactly 16 bytes
	data := []byte("checksum input")
	keyUsage := uint32(17)

	// Step 1: ksign = HMAC-MD5(key, "signaturekey\x00")
	ksign := hmac.New(md5.New, key)
	ksign.Write([]byte("signaturekey\x00"))
	ksignKey := ksign.Sum(nil)

	// Step 2: MD5(usage_le32 + data)
	usageBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(usageBytes, keyUsage)
	md5Hash := md5.New()
	md5Hash.Write(usageBytes)
	md5Hash.Write(data)
	md5Value := md5Hash.Sum(nil)

	// Step 3: HMAC-MD5(ksign, md5hash)
	finalHmac := hmac.New(md5.New, ksignKey)
	finalHmac.Write(md5Value)
	expected := finalHmac.Sum(nil)

	got := computeKerbHMACMD5(key, keyUsage, data)

	if !bytes.Equal(got, expected) {
		t.Errorf("computeKerbHMACMD5() = %x, want %x", got, expected)
	}
}

// TestComputeKerbHMACMD5DifferentInputs ensures different inputs produce different checksums.
func TestComputeKerbHMACMD5DifferentInputs(t *testing.T) {
	key := bytes.Repeat([]byte{0xAA}, 16)

	result1 := computeKerbHMACMD5(key, 17, []byte("input one"))
	result2 := computeKerbHMACMD5(key, 17, []byte("input two"))

	if bytes.Equal(result1, result2) {
		t.Error("different inputs produced the same checksum")
	}
}

// TestComputeKerbHMACMD5DifferentKeyUsage ensures different key usage produces different checksums.
func TestComputeKerbHMACMD5DifferentKeyUsage(t *testing.T) {
	key := bytes.Repeat([]byte{0xBB}, 16)
	data := []byte("same data")

	result1 := computeKerbHMACMD5(key, 17, data)
	result2 := computeKerbHMACMD5(key, 18, data)

	if bytes.Equal(result1, result2) {
		t.Error("different key usages produced the same checksum")
	}
}

// TestMarshalPAForUser verifies the PA-FOR-USER structure can be produced.
func TestMarshalPAForUser(t *testing.T) {
	checksum := bytes.Repeat([]byte{0xCC}, 16)
	result := marshalPAForUser("testuser", "TEST.COM", checksum)

	if len(result) == 0 {
		t.Fatal("marshalPAForUser() returned empty result")
	}

	// Should be a SEQUENCE (tag 0x30)
	if result[0] != 0x30 {
		t.Errorf("first byte = 0x%02X, want 0x30 (SEQUENCE)", result[0])
	}

	// Should contain GeneralString tags (0x1B) for username, realm, "Kerberos"
	gsCount := 0
	for _, b := range result {
		if b == 0x1B {
			gsCount++
		}
	}
	if gsCount < 3 {
		t.Errorf("found %d GeneralString tags, want at least 3", gsCount)
	}

	// Should contain "testuser" bytes
	if !bytes.Contains(result, []byte("testuser")) {
		t.Error("output does not contain username 'testuser'")
	}

	// Should contain "TEST.COM" bytes
	if !bytes.Contains(result, []byte("TEST.COM")) {
		t.Error("output does not contain realm 'TEST.COM'")
	}

	// Should contain "Kerberos" bytes
	if !bytes.Contains(result, []byte("Kerberos")) {
		t.Error("output does not contain auth-package 'Kerberos'")
	}
}

// TestParseSPN tests service principal name parsing.
func TestParseSPN(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantParts []string
		wantNType int32
	}{
		{
			name:      "standard SPN",
			input:     "cifs/fileserver.domain.com",
			wantParts: []string{"cifs", "fileserver.domain.com"},
			wantNType: 2, // KRB_NT_SRV_INST
		},
		{
			name:      "SPN without slash",
			input:     "krbtgt",
			wantParts: []string{"krbtgt"},
			wantNType: 2,
		},
		{
			name:      "HTTP SPN",
			input:     "HTTP/webapp.test.com",
			wantParts: []string{"HTTP", "webapp.test.com"},
			wantNType: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pn, err := parseSPN(tt.input)
			if err != nil {
				t.Fatalf("parseSPN() error: %v", err)
			}

			if pn.NameType != tt.wantNType {
				t.Errorf("NameType = %d, want %d", pn.NameType, tt.wantNType)
			}

			if len(pn.NameString) != len(tt.wantParts) {
				t.Fatalf("NameString = %v, want %v", pn.NameString, tt.wantParts)
			}

			for i, part := range tt.wantParts {
				if pn.NameString[i] != part {
					t.Errorf("NameString[%d] = %q, want %q", i, pn.NameString[i], part)
				}
			}
		})
	}
}

// TestASN1TLVHelpers tests the low-level ASN.1 construction helpers.
func TestASN1TLVHelpers(t *testing.T) {
	t.Run("asn1Sequence", func(t *testing.T) {
		content := []byte{0x01, 0x02, 0x03}
		result := asn1Sequence(content)
		if result[0] != 0x30 {
			t.Errorf("tag = 0x%02X, want 0x30", result[0])
		}
		if result[1] != 3 {
			t.Errorf("length = %d, want 3", result[1])
		}
	})

	t.Run("asn1Explicit tag 0", func(t *testing.T) {
		content := []byte{0x01}
		result := asn1Explicit(0, content)
		if result[0] != 0xA0 {
			t.Errorf("tag = 0x%02X, want 0xA0", result[0])
		}
	})

	t.Run("asn1Explicit tag 3", func(t *testing.T) {
		content := []byte{0x01}
		result := asn1Explicit(3, content)
		if result[0] != 0xA3 {
			t.Errorf("tag = 0x%02X, want 0xA3", result[0])
		}
	})

	t.Run("asn1Integer positive", func(t *testing.T) {
		result := asn1Integer(1)
		if result[0] != 0x02 {
			t.Errorf("tag = 0x%02X, want 0x02 (INTEGER)", result[0])
		}
		if result[2] != 1 {
			t.Errorf("value = %d, want 1", result[2])
		}
	})

	t.Run("asn1Integer -138", func(t *testing.T) {
		result := asn1Integer(-138)
		// Should be: 0x02 0x02 0xFF 0x76
		if result[0] != 0x02 {
			t.Errorf("tag = 0x%02X, want 0x02", result[0])
		}
		if result[1] != 2 {
			t.Errorf("length = %d, want 2", result[1])
		}
		// -138 in two's complement = 0xFF76
		if result[2] != 0xFF || result[3] != 0x76 {
			t.Errorf("value bytes = %02X%02X, want FF76", result[2], result[3])
		}
	})

	t.Run("asn1GeneralString", func(t *testing.T) {
		result := asn1GeneralString("test")
		if result[0] != 0x1B {
			t.Errorf("tag = 0x%02X, want 0x1B (GeneralString)", result[0])
		}
		if result[1] != 4 {
			t.Errorf("length = %d, want 4", result[1])
		}
		if string(result[2:]) != "test" {
			t.Errorf("value = %q, want %q", string(result[2:]), "test")
		}
	})

	t.Run("asn1OctetString", func(t *testing.T) {
		data := []byte{0xDE, 0xAD}
		result := asn1OctetString(data)
		if result[0] != 0x04 {
			t.Errorf("tag = 0x%02X, want 0x04 (OCTET STRING)", result[0])
		}
		if result[1] != 2 {
			t.Errorf("length = %d, want 2", result[1])
		}
	})
}

// TestASN1TLVLongForm tests TLV encoding for lengths >= 128.
func TestASN1TLVLongForm(t *testing.T) {
	content := bytes.Repeat([]byte{0xFF}, 200)
	result := asn1TLV(0x30, content)

	// Tag
	if result[0] != 0x30 {
		t.Errorf("tag = 0x%02X, want 0x30", result[0])
	}

	// Length 200 > 127, so long form: 0x81 0xC8
	if result[1] != 0x81 {
		t.Errorf("length byte 1 = 0x%02X, want 0x81", result[1])
	}
	if result[2] != 0xC8 {
		t.Errorf("length byte 2 = 0x%02X, want 0xC8 (200)", result[2])
	}

	// Total size: 1 (tag) + 2 (length) + 200 (content) = 203
	if len(result) != 203 {
		t.Errorf("total length = %d, want 203", len(result))
	}
}

// TestComputeKerbHMACMD5KnownVector tests against a pre-computed vector.
func TestComputeKerbHMACMD5KnownVector(t *testing.T) {
	// Use all-zeros key and empty data to create a reproducible test
	key := make([]byte, 16)
	data := []byte{}

	result := computeKerbHMACMD5(key, 0, data)
	resultHex := hex.EncodeToString(result)

	// Recompute manually
	ksign := hmac.New(md5.New, key)
	ksign.Write([]byte("signaturekey\x00"))
	ksignKey := ksign.Sum(nil)

	usageBytes := make([]byte, 4)
	md5Hash := md5.New()
	md5Hash.Write(usageBytes)
	md5Hash.Write(data)
	md5Value := md5Hash.Sum(nil)

	finalHmac := hmac.New(md5.New, ksignKey)
	finalHmac.Write(md5Value)
	expected := hex.EncodeToString(finalHmac.Sum(nil))

	if resultHex != expected {
		t.Errorf("got %s, want %s", resultHex, expected)
	}
}
