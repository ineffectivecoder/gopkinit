package pkinit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

// generateSelfSignedCert creates a self-signed certificate for testing.
func generateSelfSignedCert(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test@TEST.COM",
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}

	return cert, key
}

// TestSignAuthPackProducesValidCMS verifies that SignAuthPack produces parseable CMS SignedData.
func TestSignAuthPackProducesValidCMS(t *testing.T) {
	cert, key := generateSelfSignedCert(t)

	authPackData := []byte("test auth pack data")

	// Test with wrapping
	result, err := SignAuthPack(authPackData, cert, key, true)
	if err != nil {
		t.Fatalf("SignAuthPack(wrapped) error: %v", err)
	}

	if len(result) == 0 {
		t.Fatal("SignAuthPack(wrapped) returned empty result")
	}

	// Should be parseable as ContentInfo
	var contentInfo ContentInfo
	_, err = asn1.Unmarshal(result, &contentInfo)
	if err != nil {
		t.Fatalf("failed to parse wrapped result as ContentInfo: %v", err)
	}

	// ContentType should be SignedData OID
	if !contentInfo.ContentType.Equal(oidSignedData) {
		t.Errorf("ContentType = %v, want %v (SignedData)", contentInfo.ContentType, oidSignedData)
	}

	// Parse inner SignedData
	var signedData SignedData
	_, err = asn1.Unmarshal(contentInfo.Content.Bytes, &signedData)
	if err != nil {
		t.Fatalf("failed to parse SignedData: %v", err)
	}

	// Version should be 3
	if signedData.Version != 3 {
		t.Errorf("SignedData version = %d, want 3", signedData.Version)
	}

	// Should have one digest algorithm
	if len(signedData.DigestAlgorithms) != 1 {
		t.Errorf("DigestAlgorithms count = %d, want 1", len(signedData.DigestAlgorithms))
	}

	// Digest algorithm should be SHA1
	if !signedData.DigestAlgorithms[0].Algorithm.Equal(oidSHA1) {
		t.Errorf("DigestAlgorithm = %v, want SHA1", signedData.DigestAlgorithms[0].Algorithm)
	}

	// EncapContentInfo type should be PKINIT AuthData
	if !signedData.EncapContentInfo.ContentType.Equal(oidPKINITAuthData) {
		t.Errorf("EncapContentInfo type = %v, want PKINIT AuthData", signedData.EncapContentInfo.ContentType)
	}

	// Should have one signer info
	if len(signedData.SignerInfos) != 1 {
		t.Errorf("SignerInfos count = %d, want 1", len(signedData.SignerInfos))
	}

	// Signer version should be 1
	if signedData.SignerInfos[0].Version != 1 {
		t.Errorf("SignerInfo version = %d, want 1", signedData.SignerInfos[0].Version)
	}

	// Signature should not be empty
	if len(signedData.SignerInfos[0].Signature) == 0 {
		t.Error("SignerInfo Signature is empty")
	}
}

// TestSignAuthPackWithoutWrapping tests uncovered path.
func TestSignAuthPackWithoutWrapping(t *testing.T) {
	cert, key := generateSelfSignedCert(t)

	result, err := SignAuthPack([]byte("test"), cert, key, false)
	if err != nil {
		t.Fatalf("SignAuthPack(unwrapped) error: %v", err)
	}

	// Should be directly parseable as SignedData
	var signedData SignedData
	_, err = asn1.Unmarshal(result, &signedData)
	if err != nil {
		t.Fatalf("failed to parse unwrapped result as SignedData: %v", err)
	}
}

// TestSignAuthPackRejectsNonRSAKey ensures non-RSA keys are rejected.
func TestSignAuthPackRejectsNonRSAKey(t *testing.T) {
	cert, _ := generateSelfSignedCert(t)

	// Pass a string instead of RSA key
	_, err := SignAuthPack([]byte("test"), cert, "not-a-key", true)
	if err == nil {
		t.Fatal("SignAuthPack() should reject non-RSA key")
	}
}

// TestCMSOIDConstants verifies the OID constants are correct.
func TestCMSOIDConstants(t *testing.T) {
	tests := []struct {
		name string
		oid  asn1.ObjectIdentifier
		want string
	}{
		{"SignedData", oidSignedData, "1.2.840.113549.1.7.2"},
		{"PKINITAuthData", oidPKINITAuthData, "1.3.6.1.5.2.3.1"},
		{"SHA1", oidSHA1, "1.3.14.3.2.26"},
		{"RSAEncryption", oidRSAEncryption, "1.2.840.113549.1.1.1"},
		{"ContentType", oidContentType, "1.2.840.113549.1.9.3"},
		{"MessageDigest", oidMessageDigest, "1.2.840.113549.1.9.4"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.oid.String() != tt.want {
				t.Errorf("OID %s = %s, want %s", tt.name, tt.oid.String(), tt.want)
			}
		})
	}
}
