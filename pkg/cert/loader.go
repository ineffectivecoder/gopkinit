package cert

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"os"

	"software.sslmate.com/src/go-pkcs12"
)

// CertificateBundle holds the certificate, private key, and issuer information
type CertificateBundle struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.PrivateKey // typically *rsa.PrivateKey
	Issuer      string
}

// LoadPFX loads a PFX/PKCS12 file with an optional password
func LoadPFX(path string, password string) (*CertificateBundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read PFX file: %w", err)
	}
	return LoadPFXData(data, password)
}

// LoadPFXData loads a PFX/PKCS12 from raw bytes with an optional password
func LoadPFXData(data []byte, password string) (*CertificateBundle, error) {
	// Parse the PFX/PKCS12 data
	privateKey, certificate, err := pkcs12.Decode(data, password)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PFX: %w", err)
	}

	// Extract issuer common name
	issuer := ""
	if certificate.Issuer.CommonName != "" {
		issuer = certificate.Issuer.CommonName
	}

	return &CertificateBundle{
		Certificate: certificate,
		PrivateKey:  privateKey,
		Issuer:      issuer,
	}, nil
}
