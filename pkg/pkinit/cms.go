package pkinit

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"math/big"
)

// OIDs used in CMS/PKCS7 structures
var (
	// SignedData OID: 1.2.840.113549.1.7.2
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	// PKINIT AuthData OID: 1.3.6.1.5.2.3.1
	oidPKINITAuthData = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 1}
	// SHA1 OID: 1.3.14.3.2.26
	oidSHA1 = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	// RSA encryption OID: 1.2.840.113549.1.1.1
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	// Content type OID: 1.2.840.113549.1.9.3
	oidContentType = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	// Message digest OID: 1.2.840.113549.1.9.4
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
)

// AlgorithmIdentifier represents an algorithm with optional parameters
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// IssuerAndSerialNumber identifies a certificate
type IssuerAndSerialNumber struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// Attribute represents a CMS attribute
type Attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// SignerInfo contains signer information for CMS
type SignerInfo struct {
	Version            int `asn1:"default:1"`
	SID                IssuerAndSerialNumber
	DigestAlgorithm    AlgorithmIdentifier
	SignedAttrs        []Attribute `asn1:"optional,implicit,tag:0"`
	SignatureAlgorithm AlgorithmIdentifier
	Signature          []byte
}

// SignedData represents a CMS SignedData structure
type SignedData struct {
	Version          int                   `asn1:"default:3"`
	DigestAlgorithms []AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo EncapsulatedContentInfo
	Certificates     asn1.RawValue `asn1:"optional,implicit,tag:0"`
	SignerInfos      []SignerInfo  `asn1:"set"`
}

// SignAuthPack creates a PKCS7 signed data structure containing the AuthPack
// This matches the sign_authpack_native function from the Python implementation
func SignAuthPack(data []byte, cert *x509.Certificate, privKey crypto.PrivateKey, wrapSigned bool) ([]byte, error) {
	rsaKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key must be RSA")
	}

	// Compute SHA1 hash of the data
	h := sha1.New()
	h.Write(data)
	dataHash := h.Sum(nil)

	// Create digest algorithm (SHA1)
	// Per RFC, digest algorithms should include NULL parameters
	nullParams, _ := asn1.Marshal(asn1.NullRawValue)
	digestAlg := AlgorithmIdentifier{
		Algorithm: oidSHA1,
		Parameters: asn1.RawValue{
			FullBytes: nullParams,
		},
	}

	// Create signed attributes
	// Attribute 1: content-type = id-pkinit-authData (1.3.6.1.5.2.3.1)
	contentTypeValue, err := asn1.Marshal(oidPKINITAuthData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal content type: %w", err)
	}

	// Attribute 2: message-digest = SHA1(data)
	messageDigestValue, err := asn1.Marshal(dataHash)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal message digest: %w", err)
	}

	signedAttrs := []Attribute{
		{
			Type:   oidContentType,
			Values: []asn1.RawValue{{FullBytes: contentTypeValue}},
		},
		{
			Type:   oidMessageDigest,
			Values: []asn1.RawValue{{FullBytes: messageDigestValue}},
		},
	}

	// Encode signed attributes for signing
	// NOTE: When signing, we use a SET OF encoding (tag 0x31) instead of context-specific
	signedAttrsBytes, err := asn1.Marshal(signedAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed attributes: %w", err)
	}
	// Change the tag from SEQUENCE to SET for proper CMS encoding
	if len(signedAttrsBytes) > 0 {
		signedAttrsBytes[0] = 0x31 // SET tag
	}

	// Sign the signed attributes
	h = sha1.New()
	h.Write(signedAttrsBytes)
	signedAttrsHash := h.Sum(nil)

	signature, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA1, signedAttrsHash)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	// Create IssuerAndSerialNumber
	issuerBytes, err := asn1.Marshal(cert.Issuer.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("failed to marshal issuer: %w", err)
	}

	sid := IssuerAndSerialNumber{
		Issuer:       asn1.RawValue{FullBytes: issuerBytes},
		SerialNumber: cert.SerialNumber,
	}

	// Create signature algorithm (RSA with NULL parameters)
	// Python's minikerberos uses rsaEncryption, not sha1WithRSAEncryption
	sigAlg := AlgorithmIdentifier{
		Algorithm: oidRSAEncryption,
		Parameters: asn1.RawValue{
			FullBytes: nullParams,
		},
	}

	// Create SignerInfo
	signerInfo := SignerInfo{
		Version:            1,
		SID:                sid,
		DigestAlgorithm:    digestAlg,
		SignedAttrs:        signedAttrs,
		SignatureAlgorithm: sigAlg,
		Signature:          signature,
	}

	// Create EncapsulatedContentInfo
	// The content must be an OCTET STRING per CMS spec
	// Marshal as OCTET STRING (tag 0x04)
	octetString := append([]byte{0x04}, encodeLength(len(data))...)
	octetString = append(octetString, data...)

	encapContentInfo := EncapsulatedContentInfo{
		ContentType: oidPKINITAuthData,
		Content: asn1.RawValue{
			Class:      2, // Context-specific
			Tag:        0,
			IsCompound: true,
			Bytes:      octetString,
		},
	}

	// Wrap certificate in proper ASN.1 structure
	certBytes := cert.Raw
	certsRaw := asn1.RawValue{
		Class:      2, // Context-specific
		Tag:        0,
		IsCompound: true,
		Bytes:      certBytes,
	}

	// Create SignedData
	signedData := SignedData{
		Version:          3,
		DigestAlgorithms: []AlgorithmIdentifier{digestAlg},
		EncapContentInfo: encapContentInfo,
		Certificates:     certsRaw,
		SignerInfos:      []SignerInfo{signerInfo},
	}

	signedDataBytes, err := asn1.Marshal(signedData)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed data: %w", err)
	}

	if wrapSigned {
		// Wrap in ContentInfo
		contentInfo := ContentInfo{
			ContentType: oidSignedData,
			Content: asn1.RawValue{
				Class:      2, // Context-specific
				Tag:        0,
				IsCompound: true,
				Bytes:      signedDataBytes,
			},
		}

		return asn1.Marshal(contentInfo)
	}

	return signedDataBytes, nil
}
