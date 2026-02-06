package pac

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// buildTestPAC creates a minimal valid PAC structure for testing.
func buildTestPAC(bufferType uint32, bufferData []byte) []byte {
	// PAC header: cBuffers (4) + Version (4) = 8 bytes
	// Each PAC_INFO_BUFFER: Type (4) + Size (4) + Offset (8) = 16 bytes
	headerSize := 8 + 16 // one buffer

	buf := new(bytes.Buffer)

	// cBuffers
	binary.Write(buf, binary.LittleEndian, uint32(1))
	// Version
	binary.Write(buf, binary.LittleEndian, uint32(0))
	// PAC_INFO_BUFFER
	binary.Write(buf, binary.LittleEndian, bufferType)
	binary.Write(buf, binary.LittleEndian, uint32(len(bufferData)))
	binary.Write(buf, binary.LittleEndian, uint64(headerSize))

	// Buffer data
	buf.Write(bufferData)

	return buf.Bytes()
}

// TestParsePACBasic tests parsing a minimal PAC structure.
func TestParsePACBasic(t *testing.T) {
	data := []byte("credential-info-data")
	pacBytes := buildTestPAC(PACTypeCredentials, data)

	pac, err := ParsePAC(pacBytes)
	if err != nil {
		t.Fatalf("ParsePAC() error: %v", err)
	}

	if len(pac.Buffers) != 1 {
		t.Fatalf("Buffers count = %d, want 1", len(pac.Buffers))
	}

	if pac.Buffers[0].Type != PACTypeCredentials {
		t.Errorf("Buffer type = %d, want %d", pac.Buffers[0].Type, PACTypeCredentials)
	}

	if !bytes.Equal(pac.Buffers[0].Data, data) {
		t.Errorf("Buffer data = %x, want %x", pac.Buffers[0].Data, data)
	}
}

// TestParsePACMultipleBuffers tests parsing with multiple buffer types.
func TestParsePACMultipleBuffers(t *testing.T) {
	credData := []byte("cred-data-here!!")  // 16 bytes
	clientData := []byte("client-info!!!!") // 15 bytes, padded to alignment

	buf := new(bytes.Buffer)

	// Header: 2 buffers
	binary.Write(buf, binary.LittleEndian, uint32(2))
	binary.Write(buf, binary.LittleEndian, uint32(0))

	// Buffer headers start at offset 8
	// Each header is 16 bytes, so data starts at 8 + 2*16 = 40
	dataOffset1 := uint64(40)
	dataOffset2 := dataOffset1 + uint64(len(credData))

	// Buffer 1: Credentials
	binary.Write(buf, binary.LittleEndian, uint32(PACTypeCredentials))
	binary.Write(buf, binary.LittleEndian, uint32(len(credData)))
	binary.Write(buf, binary.LittleEndian, dataOffset1)

	// Buffer 2: ClientInfo
	binary.Write(buf, binary.LittleEndian, uint32(PACTypeClientInfo))
	binary.Write(buf, binary.LittleEndian, uint32(len(clientData)))
	binary.Write(buf, binary.LittleEndian, dataOffset2)

	// Write data
	buf.Write(credData)
	buf.Write(clientData)

	pac, err := ParsePAC(buf.Bytes())
	if err != nil {
		t.Fatalf("ParsePAC() error: %v", err)
	}

	if len(pac.Buffers) != 2 {
		t.Fatalf("Buffers count = %d, want 2", len(pac.Buffers))
	}
}

// TestParsePACTooShort tests rejection of truncated PAC data.
func TestParsePACTooShort(t *testing.T) {
	_, err := ParsePAC([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("ParsePAC() should fail on data shorter than 8 bytes")
	}
}

// TestParsePACOutOfBounds tests buffer pointing past data end.
func TestParsePACOutOfBounds(t *testing.T) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(1))   // 1 buffer
	binary.Write(buf, binary.LittleEndian, uint32(0))   // version
	binary.Write(buf, binary.LittleEndian, uint32(1))   // type
	binary.Write(buf, binary.LittleEndian, uint32(100)) // size — way past end
	binary.Write(buf, binary.LittleEndian, uint64(24))  // offset

	_, err := ParsePAC(buf.Bytes())
	if err == nil {
		t.Fatal("ParsePAC() should fail when buffer points out of bounds")
	}
}

// TestFindBuffer tests buffer lookup by type.
func TestFindBuffer(t *testing.T) {
	pac := &PAC{
		Buffers: []PACInfoBuffer{
			{Type: PACTypeKerbValidationInfo, Data: []byte{0x01}},
			{Type: PACTypeCredentials, Data: []byte{0x02}},
			{Type: PACTypeServerChecksum, Data: []byte{0x03}},
		},
	}

	// Find existing buffer
	credBuf := pac.FindBuffer(PACTypeCredentials)
	if credBuf == nil {
		t.Fatal("FindBuffer(Credentials) returned nil")
	}
	if !bytes.Equal(credBuf.Data, []byte{0x02}) {
		t.Errorf("FindBuffer(Credentials) data = %x, want 02", credBuf.Data)
	}

	// Find nonexistent buffer
	upnBuf := pac.FindBuffer(PACTypeUPNDNSInfo)
	if upnBuf != nil {
		t.Error("FindBuffer(UPNDNSInfo) should return nil for missing buffer")
	}
}

// TestPAC constants are correct per MS-PAC.
func TestPACTypeConstants(t *testing.T) {
	tests := []struct {
		name  string
		value uint32
		want  uint32
	}{
		{"KerbValidationInfo", PACTypeKerbValidationInfo, 1},
		{"Credentials", PACTypeCredentials, 2},
		{"ServerChecksum", PACTypeServerChecksum, 6},
		{"PrivSvrChecksum", PACTypePrivSvrChecksum, 7},
		{"ClientInfo", PACTypeClientInfo, 10},
		{"UPNDNSInfo", PACTypeUPNDNSInfo, 12},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.value, tt.want)
			}
		})
	}
}

// TestParseCredentialInfo tests parsing PAC_CREDENTIAL_INFO.
func TestParseCredentialInfo(t *testing.T) {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.LittleEndian, uint32(0))  // Version
	binary.Write(buf, binary.LittleEndian, uint32(18)) // AES256
	buf.Write([]byte{0xAA, 0xBB, 0xCC, 0xDD})          // encrypted data

	credInfo, err := ParseCredentialInfo(buf.Bytes())
	if err != nil {
		t.Fatalf("ParseCredentialInfo() error: %v", err)
	}

	if credInfo.Version != 0 {
		t.Errorf("Version = %d, want 0", credInfo.Version)
	}

	if credInfo.EncryptionType != 18 {
		t.Errorf("EncryptionType = %d, want 18", credInfo.EncryptionType)
	}

	if len(credInfo.SerializedData) != 4 {
		t.Errorf("SerializedData length = %d, want 4", len(credInfo.SerializedData))
	}
}

// TestParseCredentialInfoTooShort tests rejection of short data.
func TestParseCredentialInfoTooShort(t *testing.T) {
	_, err := ParseCredentialInfo([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("ParseCredentialInfo() should fail on data shorter than 8 bytes")
	}
}

// TestParseNTLMCredential24Bytes tests the 24-byte NTLM credential format.
func TestParseNTLMCredential24Bytes(t *testing.T) {
	data := make([]byte, 24)
	binary.LittleEndian.PutUint32(data[0:4], 0) // Version
	binary.LittleEndian.PutUint32(data[4:8], 0) // Flags
	// bytes 8-23: NT password (16 bytes)
	for i := 8; i < 24; i++ {
		data[i] = byte(i - 8 + 0xA0) // distinguishable pattern
	}

	var cred NTLMCredential
	err := parseNTLMCredential(&cred, data)
	if err != nil {
		t.Fatalf("parseNTLMCredential() error: %v", err)
	}

	// In 24-byte format, there's no LM password — NTPassword is read directly
	for i := 0; i < 16; i++ {
		if cred.NTPassword[i] != byte(i+0xA0) {
			t.Errorf("NTPassword[%d] = 0x%02X, want 0x%02X", i, cred.NTPassword[i], byte(i+0xA0))
			break
		}
	}
}

// TestParseNTLMCredential40Bytes tests the 40-byte NTLM credential format (with LM password).
func TestParseNTLMCredential40Bytes(t *testing.T) {
	data := make([]byte, 40)
	binary.LittleEndian.PutUint32(data[0:4], 0) // Version
	binary.LittleEndian.PutUint32(data[4:8], 0) // Flags
	// bytes 8-23: LM password (16 bytes)
	for i := 8; i < 24; i++ {
		data[i] = byte(i - 8 + 0xB0)
	}
	// bytes 24-39: NT password (16 bytes)
	for i := 24; i < 40; i++ {
		data[i] = byte(i - 24 + 0xC0)
	}

	var cred NTLMCredential
	err := parseNTLMCredential(&cred, data)
	if err != nil {
		t.Fatalf("parseNTLMCredential() error: %v", err)
	}

	// LM password
	for i := 0; i < 16; i++ {
		if cred.LMPassword[i] != byte(i+0xB0) {
			t.Errorf("LMPassword[%d] = 0x%02X, want 0x%02X", i, cred.LMPassword[i], byte(i+0xB0))
			break
		}
	}

	// NT password
	for i := 0; i < 16; i++ {
		if cred.NTPassword[i] != byte(i+0xC0) {
			t.Errorf("NTPassword[%d] = 0x%02X, want 0x%02X", i, cred.NTPassword[i], byte(i+0xC0))
			break
		}
	}
}

// TestParseNTLMCredentialTooShort tests rejection of data under 24 bytes.
func TestParseNTLMCredentialTooShort(t *testing.T) {
	var cred NTLMCredential
	err := parseNTLMCredential(&cred, make([]byte, 10))
	if err == nil {
		t.Fatal("parseNTLMCredential() should fail on data shorter than 24 bytes")
	}
}
