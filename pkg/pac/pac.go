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
	Version    uint32
	Flags      uint32
	LMPassword [16]byte
	NTPassword [16]byte
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
	// The Offset field in PAC_INFO_BUFFER is the offset from the START of the PACTYPE structure
	// (i.e., from byte 0 which is the cBuffers field), NOT from after the header.
	for i := range pac.Buffers {
		offset := pac.Buffers[i].Offset
		size := pac.Buffers[i].Size

		if uint64(len(data)) < offset+uint64(size) {
			return nil, fmt.Errorf("PAC buffer %d out of bounds (data len=%d, need offset=%d + size=%d)", i, len(data), offset, size)
		}

		pac.Buffers[i].Data = data[offset : offset+uint64(size)]
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
// Per MS-PAC 2.6.1:
//
//	Version (4 bytes) - must be 0
//	EncryptionType (4 bytes) - e.g., 18 for AES256
//	SerializedData (variable) - encrypted PAC_CREDENTIAL_DATA
func ParseCredentialInfo(data []byte) (*PACCredentialInfo, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("credential info data too short (need at least 8 bytes, got %d)", len(data))
	}

	credInfo := &PACCredentialInfo{}

	credInfo.Version = binary.LittleEndian.Uint32(data[0:4])
	credInfo.EncryptionType = binary.LittleEndian.Uint32(data[4:8])

	// Encrypted data starts at offset 8
	credInfo.SerializedData = data[8:]

	return credInfo, nil
}

// ParseCredentialData parses decrypted PAC credential data
// The data format is:
//
//	TypeSerialization1 (16 bytes) - NDR version/endianness info
//	ReferentID (4 bytes) - typically 0xcccccccc
//	PAC_CREDENTIAL_DATA (NDR encoded)
func ParseCredentialData(data []byte) (*PACCredentialData, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("credential data too short (need at least 20 bytes, got %d)", len(data))
	}

	r := bytes.NewReader(data)
	credData := &PACCredentialData{}

	// Skip TypeSerialization1 header (16 bytes)
	typeSerial := make([]byte, 16)
	r.Read(typeSerial)

	// Read ReferentID (4 bytes, typically 0xcccccccc)
	var referentID uint32
	binary.Read(r, binary.LittleEndian, &referentID)

	// Now we're at the PAC_CREDENTIAL_DATA in NDR format
	// NDR conformant array: MaxCount, Offset, ActualCount, then data
	var maxCount uint32
	binary.Read(r, binary.LittleEndian, &maxCount)

	// Read each credential from the NDR array
	// Each SECPKG_SUPPLEMENTAL_CRED has:
	//   - RPC_UNICODE_STRING for PackageName (which has Length, MaximumLength, Pointer)
	//   - ULONG CredentialSize
	//   - PUCHAR_ARRAY Credentials (pointer to array)

	// Store the CredentialSize values for later use
	credSizes := make([]uint32, maxCount)

	for i := uint32(0); i < maxCount; i++ {
		// RPC_UNICODE_STRING for PackageName
		// Structure: Length (2 bytes), MaximumLength (2 bytes), Pointer (4 bytes)
		var pkgNameLen, pkgNameMaxLen uint16
		var pkgNamePtr uint32
		binary.Read(r, binary.LittleEndian, &pkgNameLen)
		binary.Read(r, binary.LittleEndian, &pkgNameMaxLen)
		binary.Read(r, binary.LittleEndian, &pkgNamePtr)

		// Read 8 bytes - there appear to be TWO uint32 fields here
		// The SECOND field (at offset +4) is the actual credential size we need
		var field1, credSize uint32
		binary.Read(r, binary.LittleEndian, &field1)   // Unknown field (appears to be a referent ID or marker)
		binary.Read(r, binary.LittleEndian, &credSize) // Actual credential size

		credSizes[i] = credSize
		credData.CredentialCount++
	}

	// After processing the array headers, we need to read the actual string and credential data
	// This is pointed to by the pointers we read above
	// For now, let's read the package name string if present
	for i := uint32(0); i < maxCount; i++ {
		// Read package name conformant array: MaxCount, Offset, ActualCount, Data
		var pkgMaxCount, pkgOffset, pkgActualCount uint32
		binary.Read(r, binary.LittleEndian, &pkgMaxCount)
		binary.Read(r, binary.LittleEndian, &pkgOffset)
		binary.Read(r, binary.LittleEndian, &pkgActualCount)

		// Read the wide-char string
		pkgNameBytes := make([]byte, pkgActualCount*2)
		r.Read(pkgNameBytes)

		// Convert from UTF-16LE to string
		pkgName := ""
		for j := 0; j < len(pkgNameBytes); j += 2 {
			if j+1 < len(pkgNameBytes) {
				c := uint16(pkgNameBytes[j]) | uint16(pkgNameBytes[j+1])<<8
				if c != 0 {
					pkgName += string(rune(c))
				}
			}
		}

		// Align to 4-byte boundary
		if pkgActualCount*2%4 != 0 {
			padding := 4 - (pkgActualCount * 2 % 4)
			r.Read(make([]byte, padding))
		}

		// Read credentials conformant array: MaxCount, Offset, ActualCount, Data
		var credMaxCount, credOffset, credActualCount uint32
		binary.Read(r, binary.LittleEndian, &credMaxCount)
		binary.Read(r, binary.LittleEndian, &credOffset)
		binary.Read(r, binary.LittleEndian, &credActualCount)

		// Use CredentialSize from the SECPKG_SUPPLEMENTAL_CRED structure
		// The actual NTLM credential data is 4 bytes larger than CredentialSize
		// The first 4 bytes appear to be a referent ID or size marker
		credBytes := make([]byte, credSizes[i]+4)
		r.Read(credBytes)

		// Skip the first 4 bytes which appear to be a size/referent ID, not part of NTLM_SUPPLEMENTAL_CREDENTIAL
		var ntlmCred NTLMCredential
		if err := parseNTLMCredential(&ntlmCred, credBytes[4:]); err != nil {
			return nil, err
		}

		credData.Credentials = append(credData.Credentials, ntlmCred)
	}

	return credData, nil
}

// parseNTLMCredential parses an NTLM_SUPPLEMENTAL_CREDENTIAL structure
// Per MS-PAC 2.6.4, when CredentialSize is 24, the structure has:
//
//	Version (4 bytes)
//	Flags (4 bytes)
//	NtPassword (16 bytes)
//
// When CredentialSize is 40, the structure has:
//
//	Version (4 bytes)
//	Flags (4 bytes)
//	LmPassword (16 bytes)
//	NtPassword (16 bytes)
func parseNTLMCredential(cred *NTLMCredential, data []byte) error {
	if len(data) < 24 {
		return fmt.Errorf("NTLM credential too short (need at least 24 bytes, got %d)", len(data))
	}

	r := bytes.NewReader(data)

	binary.Read(r, binary.LittleEndian, &cred.Version)
	binary.Read(r, binary.LittleEndian, &cred.Flags)

	// If credential is only 24 bytes, there's no LMPassword
	if len(data) == 24 {
		r.Read(cred.NTPassword[:])
	} else {
		r.Read(cred.LMPassword[:])
		r.Read(cred.NTPassword[:])
	}

	return nil
}
