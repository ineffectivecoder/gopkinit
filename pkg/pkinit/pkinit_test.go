package pkinit

import (
	"bytes"
	"crypto/sha1"
	"encoding/asn1"
	"encoding/hex"
	"testing"
)

// TestTruncateKey verifies the PKINIT key derivation function
// against known inputs and outputs.
func TestTruncateKey(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		keySize int
		wantLen int
	}{
		{
			name:    "AES256 key size (32 bytes)",
			input:   bytes.Repeat([]byte{0xAB}, 128),
			keySize: 32,
			wantLen: 32,
		},
		{
			name:    "AES128 key size (16 bytes)",
			input:   bytes.Repeat([]byte{0xCD}, 128),
			keySize: 16,
			wantLen: 16,
		},
		{
			name:    "empty input still produces key",
			input:   []byte{},
			keySize: 32,
			wantLen: 32,
		},
		{
			name:    "small input",
			input:   []byte{0x01, 0x02, 0x03},
			keySize: 16,
			wantLen: 16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := truncateKey(tt.input, tt.keySize)
			if len(got) != tt.wantLen {
				t.Errorf("truncateKey() returned %d bytes, want %d", len(got), tt.wantLen)
			}
		})
	}
}

// TestTruncateKeyDeterminism ensures the same input always produces the same output.
func TestTruncateKeyDeterminism(t *testing.T) {
	input := bytes.Repeat([]byte{0x42}, 64)
	result1 := truncateKey(input, 32)
	result2 := truncateKey(input, 32)

	if !bytes.Equal(result1, result2) {
		t.Error("truncateKey() is not deterministic")
	}
}

// TestTruncateKeyManualVerification verifies the algorithm step-by-step:
// SHA1(0x00 || value) || SHA1(0x01 || value) || ... truncated to keySize
func TestTruncateKeyManualVerification(t *testing.T) {
	input := []byte("test input for pkinit key derivation")
	keySize := 32

	// Manually compute expected output
	var expected []byte
	for i := byte(0); len(expected) < keySize; i++ {
		h := sha1.New()
		h.Write([]byte{i})
		h.Write(input)
		digest := h.Sum(nil)
		if len(expected)+len(digest) > keySize {
			expected = append(expected, digest[:keySize-len(expected)]...)
		} else {
			expected = append(expected, digest...)
		}
	}

	got := truncateKey(input, keySize)
	if !bytes.Equal(got, expected) {
		t.Errorf("truncateKey() = %x, want %x", got, expected)
	}
}

// TestEncodeLength tests ASN.1 length encoding for short and long forms.
func TestEncodeLength(t *testing.T) {
	tests := []struct {
		name   string
		length int
		want   []byte
	}{
		{
			name:   "zero length",
			length: 0,
			want:   []byte{0x00},
		},
		{
			name:   "short form: 1",
			length: 1,
			want:   []byte{0x01},
		},
		{
			name:   "short form: 127",
			length: 127,
			want:   []byte{0x7F},
		},
		{
			name:   "long form: 128",
			length: 128,
			want:   []byte{0x81, 0x80},
		},
		{
			name:   "long form: 255",
			length: 255,
			want:   []byte{0x81, 0xFF},
		},
		{
			name:   "long form: 256",
			length: 256,
			want:   []byte{0x82, 0x01, 0x00},
		},
		{
			name:   "long form: 65535",
			length: 65535,
			want:   []byte{0x82, 0xFF, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encodeLength(tt.length)
			if !bytes.Equal(got, tt.want) {
				t.Errorf("encodeLength(%d) = %x, want %x", tt.length, got, tt.want)
			}
		})
	}
}

// TestMakeKDCOptions verifies bit positions for KDC options.
func TestMakeKDCOptions(t *testing.T) {
	tests := []struct {
		name string
		opts []string
		// Check specific bit positions
		checkBit int
		wantSet  bool
	}{
		{
			name:     "forwardable sets bit 1",
			opts:     []string{"forwardable"},
			checkBit: 1,
			wantSet:  true,
		},
		{
			name:     "renewable sets bit 8",
			opts:     []string{"renewable"},
			checkBit: 8,
			wantSet:  true,
		},
		{
			name:     "renewable-ok sets bit 27",
			opts:     []string{"renewable-ok"},
			checkBit: 27,
			wantSet:  true,
		},
		{
			name:     "empty options sets nothing",
			opts:     []string{},
			checkBit: 1,
			wantSet:  false,
		},
		{
			name:     "unknown option is silently ignored",
			opts:     []string{"nonexistent"},
			checkBit: 0,
			wantSet:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bs := makeKDCOptions(tt.opts)
			if bs.BitLength != 32 {
				t.Errorf("BitLength = %d, want 32", bs.BitLength)
			}
			if len(bs.Bytes) != 4 {
				t.Fatalf("Bytes length = %d, want 4", len(bs.Bytes))
			}

			bytePos := tt.checkBit / 8
			bitPos := 7 - (tt.checkBit % 8)
			isSet := (bs.Bytes[bytePos] & (1 << bitPos)) != 0

			if isSet != tt.wantSet {
				t.Errorf("bit %d: got set=%v, want set=%v", tt.checkBit, isSet, tt.wantSet)
			}
		})
	}
}

// TestMakeKDCOptionsMultiple verifies multiple options can be combined.
func TestMakeKDCOptionsMultiple(t *testing.T) {
	bs := makeKDCOptions([]string{"forwardable", "renewable", "renewable-ok"})

	// Check all three bits
	checkBits := map[int]bool{
		1:  true, // forwardable
		8:  true, // renewable
		27: true, // renewable-ok
	}

	for bit, wantSet := range checkBits {
		bytePos := bit / 8
		bitPos := 7 - (bit % 8)
		isSet := (bs.Bytes[bytePos] & (1 << bitPos)) != 0
		if isSet != wantSet {
			t.Errorf("bit %d: got set=%v, want set=%v", bit, isSet, wantSet)
		}
	}
}

// TestGetKerberosErrorName covers known and unknown error codes.
func TestGetKerberosErrorName(t *testing.T) {
	tests := []struct {
		code int32
		want string
	}{
		{6, "KDC_ERR_C_PRINCIPAL_UNKNOWN"},
		{14, "KDC_ERR_ETYPE_NOSUPP"},
		{17, "KDC_ERR_PREAUTH_FAILED"},
		{24, "KDC_ERR_PREAUTH_REQUIRED"},
		{37, "KRB_AP_ERR_SKEW"},
		{85, "KDC_ERR_CLIENT_NOT_TRUSTED"},
		{999, "UNKNOWN_ERROR_999"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := getKerberosErrorName(tt.code)
			if got != tt.want {
				t.Errorf("getKerberosErrorName(%d) = %q, want %q", tt.code, got, tt.want)
			}
		})
	}
}

// TestEncodePrincipalNameWithTag verifies the ASN.1 encoding is valid.
func TestEncodePrincipalNameWithTag(t *testing.T) {
	raw, err := encodePrincipalNameWithTag(1, 1, []string{"testuser"})
	if err != nil {
		t.Fatalf("encodePrincipalNameWithTag() error: %v", err)
	}

	// The result should have FullBytes set
	if len(raw.FullBytes) == 0 {
		t.Fatal("encodePrincipalNameWithTag() returned empty FullBytes")
	}

	// First byte should be context-specific tag 1 (0xA1)
	if raw.FullBytes[0] != 0xA1 {
		t.Errorf("first byte = 0x%02X, want 0xA1", raw.FullBytes[0])
	}
}

// TestEncodeGeneralStringWithTag verifies GeneralString encoding.
func TestEncodeGeneralStringWithTag(t *testing.T) {
	raw := encodeGeneralStringWithTag(2, "TEST.COM")

	if len(raw.FullBytes) == 0 {
		t.Fatal("encodeGeneralStringWithTag() returned empty FullBytes")
	}

	// First byte should be context-specific tag 2 (0xA2)
	if raw.FullBytes[0] != 0xA2 {
		t.Errorf("first byte = 0x%02X, want 0xA2", raw.FullBytes[0])
	}

	// Should contain the GeneralString tag (0x1B) somewhere inside
	found := false
	for _, b := range raw.FullBytes {
		if b == 0x1B {
			found = true
			break
		}
	}
	if !found {
		t.Error("encoded output does not contain GeneralString tag (0x1B)")
	}
}

// TestEncryptedDataASN1 verifies EncryptedData can be marshaled/unmarshaled.
func TestEncryptedDataASN1(t *testing.T) {
	ed := EncryptedData{
		EType:  18,
		KVNO:   2,
		Cipher: []byte{0x01, 0x02, 0x03, 0x04},
	}

	encoded, err := asn1.Marshal(ed)
	if err != nil {
		t.Fatalf("Marshal EncryptedData: %v", err)
	}

	var decoded EncryptedData
	_, err = asn1.Unmarshal(encoded, &decoded)
	if err != nil {
		t.Fatalf("Unmarshal EncryptedData: %v", err)
	}

	if decoded.EType != ed.EType {
		t.Errorf("EType = %d, want %d", decoded.EType, ed.EType)
	}
	if !bytes.Equal(decoded.Cipher, ed.Cipher) {
		t.Errorf("Cipher mismatch")
	}
}

// TestPKINITClientCreation tests the newFromCertBundle flow won't panic with nil.
func TestPKINITClientGetters(t *testing.T) {
	// Test that a nil-safe client returns expected defaults
	client := &PKINITClient{
		issuer: "TestCA",
	}

	if client.GetIssuer() != "TestCA" {
		t.Errorf("GetIssuer() = %q, want %q", client.GetIssuer(), "TestCA")
	}

	if client.GetCertificate() != nil {
		t.Error("GetCertificate() should return nil for empty client")
	}

	if client.GetPrivateKey() != nil {
		t.Error("GetPrivateKey() should return nil for empty client")
	}
}

// TestTruncateKeyEdgeCaseSingleBlock tests when keySize <= SHA1 digest size (20 bytes).
func TestTruncateKeyEdgeCaseSingleBlock(t *testing.T) {
	input := []byte("short")
	got := truncateKey(input, 10) // Less than one SHA1 block

	if len(got) != 10 {
		t.Errorf("truncateKey() returned %d bytes, want 10", len(got))
	}

	// Verify it matches first 10 bytes of SHA1(0x00 || input)
	h := sha1.New()
	h.Write([]byte{0x00})
	h.Write(input)
	expected := h.Sum(nil)[:10]

	if !bytes.Equal(got, expected) {
		t.Errorf("truncateKey() = %x, want %x", got, expected)
	}
}

// TestTruncateKeyKnownVector tests against a manually computed vector.
func TestTruncateKeyKnownVector(t *testing.T) {
	// Use a deterministic input and verify the hex output
	input := make([]byte, 32)
	for i := range input {
		input[i] = byte(i)
	}

	got := truncateKey(input, 32)
	gotHex := hex.EncodeToString(got)

	// Compute expected: SHA1(0x00 || input) + SHA1(0x01 || input)[0:12]
	h0 := sha1.New()
	h0.Write([]byte{0x00})
	h0.Write(input)
	d0 := h0.Sum(nil) // 20 bytes

	h1 := sha1.New()
	h1.Write([]byte{0x01})
	h1.Write(input)
	d1 := h1.Sum(nil) // 20 bytes

	expected := append(d0, d1[:12]...) // 20 + 12 = 32
	expectedHex := hex.EncodeToString(expected)

	if gotHex != expectedHex {
		t.Errorf("truncateKey() = %s, want %s", gotHex, expectedHex)
	}
}
