package pac

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// PAC buffer types
const (
	PACTypeKerbValidationInfo = 1
	PACTypeCredentials        = 2
	PACTypeServerChecksum     = 6
	PACTypePrivSvrChecksum    = 7
	PACTypeClientInfo         = 10
	PACTypeUPNDNSInfo         = 12
)

// PAC represents a Privilege Attribute Certificate
type PAC struct {
	Version  uint32
	CBuffers uint32
	Buffers  []PACInfoBuffer
}

// PACInfoBuffer represents a PAC buffer header
type PACInfoBuffer struct {
	Type   uint32
	Size   uint32
	Offset uint64
	Data   []byte
}

// PACCredentialInfo contains encrypted credential data
type PACCredentialInfo struct {
	Version        uint32
	EncryptionType uint32
	SerializedData []byte
}

// PACCredentialData contains the decrypted credential data
type PACCredentialData struct {
	CredentialCount uint32
	Credentials     []NTLMCredential
}

// NTLMCredential contains NTLM credentials
type NTLMCredential struct {
	Version          uint32
	Flags            uint32
	LMPasswordLength uint16
	LMPassword       []byte
	NTPasswordLength uint16
	NTPassword       []byte
}

// ParsePAC parses a PAC from raw bytes
func ParsePAC(data []byte) (*PAC, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("PAC data too short")
	}

	r := bytes.NewReader(data)
	pac := &PAC{}

	// Read header
	binary.Read(r, binary.LittleEndian, &pac.CBuffers)
	binary.Read(r, binary.LittleEndian, &pac.Version)

	// Read buffer headers
	for i := uint32(0); i < pac.CBuffers; i++ {
		var buf PACInfoBuffer
		binary.Read(r, binary.LittleEndian, &buf.Type)
		binary.Read(r, binary.LittleEndian, &buf.Size)
		binary.Read(r, binary.LittleEndian, &buf.Offset)
		pac.Buffers = append(pac.Buffers, buf)
	}

	// Read buffer data
	for i := range pac.Buffers {
		offset := pac.Buffers[i].Offset - 8 // Offset is from start of PAC including header
		size := pac.Buffers[i].Size

		fmt.Printf("[DEBUG PAC ParsePAC] Buffer %d: Type=0x%x, Size=%d, Offset=%d, calc_offset=%d\n",
			i, pac.Buffers[i].Type, size, pac.Buffers[i].Offset, offset)

		if uint64(len(data)) < offset+uint64(size) {
			return nil, fmt.Errorf("PAC buffer %d out of bounds", i)
		}

		pac.Buffers[i].Data = data[offset : offset+uint64(size)]

		if pac.Buffers[i].Type == PACTypeCredentials {
			fmt.Printf("[DEBUG PAC ParsePAC] Credentials buffer first 32 bytes: %x\n",
				pac.Buffers[i].Data[:min(32, len(pac.Buffers[i].Data))])
		}
	}

	return pac, nil
}

// FindBuffer returns the first buffer of the specified type
func (p *PAC) FindBuffer(bufferType uint32) *PACInfoBuffer {
	for i := range p.Buffers {
		if p.Buffers[i].Type == bufferType {
			return &p.Buffers[i]
		}
	}
	return nil
}

// ParseCredentialInfo parses a PAC_CREDENTIAL_INFO buffer
func ParseCredentialInfo(data []byte) (*PACCredentialInfo, error) {
	if len(data) < 16 {
		return nil, fmt.Errorf("credential info data too short")
	}

	fmt.Printf("[DEBUG PAC] Input data len: %d\n", len(data))
	fmt.Printf("[DEBUG PAC] First 24 bytes: %x\n", data[:min(24, len(data))])

	// WORKAROUND: gokrb5 seems to include an 8-byte NDR header that Python doesn't get
	// If the buffer starts with a pattern like 0x07000020 00000000, skip it
	// The real structure starts with Version=0, EncType=18
	if len(data) >= 16 && binary.LittleEndian.Uint32(data[8:12]) == 0 &&
		binary.LittleEndian.Uint32(data[12:16]) == 18 {
		fmt.Printf("[DEBUG PAC] Detected NDR header, skipping first 8 bytes\n")
		data = data[8:]
	}

	credInfo := &PACCredentialInfo{}

	credInfo.Version = binary.LittleEndian.Uint32(data[0:4])
	fmt.Printf("[DEBUG PAC] Version: %d\n", credInfo.Version)

	credInfo.EncryptionType = binary.LittleEndian.Uint32(data[4:8])
	fmt.Printf("[DEBUG PAC] EncryptionType: %d\n", credInfo.EncryptionType)

	// Encrypted data starts at offset 8
	credInfo.SerializedData = data[8:]
	fmt.Printf("[DEBUG PAC] SerializedData len: %d\n", len(credInfo.SerializedData))
	fmt.Printf("[DEBUG PAC] SerializedData first 16 bytes: %x\n", credInfo.SerializedData[:min(16, len(credInfo.SerializedData))])

	return credInfo, nil
}

// ParseCredentialData parses decrypted PAC credential data
func ParseCredentialData(data []byte) (*PACCredentialData, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("credential data too short")
	}

	r := bytes.NewReader(data)
	credData := &PACCredentialData{}

	// Skip TypeSerialization1 header (first 4 bytes are 0x00000001)
	var typeSerial uint32
	binary.Read(r, binary.LittleEndian, &typeSerial)

	// Skip ReferentID (4 bytes)
	var referentID uint32
	binary.Read(r, binary.LittleEndian, &referentID)

	// Read credential count
	binary.Read(r, binary.LittleEndian, &credData.CredentialCount)

	// Read each credential
	for i := uint32(0); i < credData.CredentialCount; i++ {
		var cred NTLMCredential

		// Package name length (skip)
		var packageNameLength uint16
		binary.Read(r, binary.LittleEndian, &packageNameLength)

		// Package name (skip)
		packageName := make([]byte, packageNameLength)
		r.Read(packageName)

		// Credential length
		var credLength uint16
		binary.Read(r, binary.LittleEndian, &credLength)

		// Read NTLM credential structure
		credStart := len(data) - r.Len()
		credBytes := data[credStart : credStart+int(credLength)]

		if err := parseNTLMCredential(&cred, credBytes); err != nil {
			return nil, err
		}

		credData.Credentials = append(credData.Credentials, cred)
	}

	return credData, nil
}

// parseNTLMCredential parses an NTLM_SUPPLEMENTAL_CREDENTIAL structure
func parseNTLMCredential(cred *NTLMCredential, data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("NTLM credential too short")
	}

	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &cred.Version)
	binary.Read(r, binary.LittleEndian, &cred.Flags)

	// LM password
	binary.Read(r, binary.LittleEndian, &cred.LMPasswordLength)
	if cred.LMPasswordLength > 0 {
		cred.LMPassword = make([]byte, cred.LMPasswordLength)
		r.Read(cred.LMPassword)
	}

	// NT password
	binary.Read(r, binary.LittleEndian, &cred.NTPasswordLength)
	if cred.NTPasswordLength > 0 {
		cred.NTPassword = make([]byte, cred.NTPasswordLength)
		r.Read(cred.NTPassword)
	}

	return nil
}
