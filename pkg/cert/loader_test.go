package cert

import (
	"testing"
)

// TestLoadPFXFileNotFound tests error when PFX file doesn't exist.
func TestLoadPFXFileNotFound(t *testing.T) {
	_, err := LoadPFX("/nonexistent/path/cert.pfx", "")
	if err == nil {
		t.Fatal("LoadPFX() should fail on missing file")
	}
}

// TestLoadPFXDataInvalid tests error when PFX data is not valid PKCS12.
func TestLoadPFXDataInvalid(t *testing.T) {
	_, err := LoadPFXData([]byte("not valid pkcs12 data"), "password")
	if err == nil {
		t.Fatal("LoadPFXData() should fail on invalid PKCS12 data")
	}
}

// TestLoadPFXDataEmpty tests error when PFX data is empty.
func TestLoadPFXDataEmpty(t *testing.T) {
	_, err := LoadPFXData([]byte{}, "")
	if err == nil {
		t.Fatal("LoadPFXData() should fail on empty data")
	}
}

// TestCertificateBundleFields verifies the bundle struct holds expected types.
func TestCertificateBundleFields(t *testing.T) {
	// Verify the struct can be created with expected field types
	bundle := &CertificateBundle{
		Certificate: nil,
		PrivateKey:  nil,
		Issuer:      "TestCA",
	}

	if bundle.Issuer != "TestCA" {
		t.Errorf("Issuer = %q, want %q", bundle.Issuer, "TestCA")
	}
}
