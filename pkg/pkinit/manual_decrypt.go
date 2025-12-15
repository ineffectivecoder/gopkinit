package pkinit

import (
	"crypto/hmac"
	"crypto/sha1"
	"fmt"

	"github.com/jcmturner/aescts/v2"
	"github.com/jcmturner/gokrb5/v8/crypto"
)

// manualDecryptAES manually decrypts AES-CTS ciphertext following the exact Python logic
// This bypasses gokrb5 to isolate any library incompatibilities
func manualDecryptAES(baseKey []byte, etypeID int32, ciphertext []byte, keyUsage uint32) ([]byte, error) {
	// Determine block size and MAC size based on etype
	blockSize := 16
	macSize := 12

	if len(ciphertext) < blockSize+macSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// Split ciphertext: [encrypted_data][mac]
	encryptedData := ciphertext[:len(ciphertext)-macSize]
	expectedMAC := ciphertext[len(ciphertext)-macSize:]

	// Get etype for key derivation
	et, err := crypto.GetEtype(etypeID)
	if err != nil {
		return nil, fmt.Errorf("failed to get etype: %w", err)
	}

	// Derive Ke and Ki from base key
	// Python code: ki = cls.derive(key, pack('>IB', keyusage, 0x55))
	//              ke = cls.derive(key, pack('>IB', keyusage, 0xAA))
	kiConstant := []byte{
		byte(keyUsage >> 24),
		byte(keyUsage >> 16),
		byte(keyUsage >> 8),
		byte(keyUsage),
		0x55, // For integrity key
	}

	keConstant := []byte{
		byte(keyUsage >> 24),
		byte(keyUsage >> 16),
		byte(keyUsage >> 8),
		byte(keyUsage),
		0xAA, // For encryption key
	}

	ki, err := et.DeriveKey(baseKey, kiConstant)
	if err != nil {
		return nil, fmt.Errorf("failed to derive Ki: %w", err)
	}

	ke, err := et.DeriveKey(baseKey, keConstant)
	if err != nil {
		return nil, fmt.Errorf("failed to derive Ke: %w", err)
	}

	// Decrypt with Ke
	// Python: basic_plaintext = cls.basic_decrypt(ke, basic_ctext)
	zeroIV := make([]byte, blockSize)
	plaintext, err := aescts.Decrypt(ke, zeroIV, encryptedData)
	if err != nil {
		return nil, fmt.Errorf("AES-CTS decryption failed: %w", err)
	}

	// Compute HMAC over plaintext
	// Python: hmac = HMAC.new(ki.contents, basic_plaintext, cls.hashmod).digest()
	//         expmac = hmac[:cls.macsize]
	mac := hmac.New(sha1.New, ki)
	mac.Write(plaintext)
	computedMAC := mac.Sum(nil)[:macSize]

	// Verify HMAC
	if !hmac.Equal(computedMAC, expectedMAC) {
		// Try alternative: HMAC over ciphertext instead
		mac2 := hmac.New(sha1.New, ki)
		mac2.Write(encryptedData)
		computedMAC2 := mac2.Sum(nil)[:macSize]

		if !hmac.Equal(computedMAC2, expectedMAC) {
			return nil, fmt.Errorf("HMAC verification failed (tried both plaintext and ciphertext)")
		}
	}

	// Python: return basic_plaintext[cls.blocksize:]
	// Strip the confounder (first block)
	if len(plaintext) < blockSize {
		return nil, fmt.Errorf("plaintext too short to strip confounder")
	}

	result := plaintext[blockSize:]

	return result, nil
}
