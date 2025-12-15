package pkinit

import (
	"crypto/rand"
	"encoding/asn1"
	"math/big"
)

// DHParams holds Diffie-Hellman parameters
type DHParams struct {
	P *big.Int
	G *big.Int
	Q *big.Int
}

// DirtyDH implements the Diffie-Hellman key exchange used in PKINIT
// Uses static well-known parameters required for AD compatibility
type DirtyDH struct {
	P       *big.Int
	G       *big.Int
	Q       *big.Int // Always 0 for our purposes
	PrivKey *big.Int
	PubKey  *big.Int
	DHNonce []byte // Random 32 bytes
}

// StaticDHParams returns the static DH parameters used by PKINITtools
// These MUST match the Python tool exactly for AD compatibility
// AD rejects dynamically generated params as "unsafe"
func StaticDHParams() DHParams {
	// This is the same static P value from the Python tool
	// p = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff
	p := new(big.Int)
	p.SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff", 16)

	return DHParams{
		P: p,
		G: big.NewInt(2),
		Q: big.NewInt(0),
	}
}

// NewDirtyDH creates a new DH instance with the given parameters
func NewDirtyDH(params DHParams) (*DirtyDH, error) {
	dh := &DirtyDH{
		P: params.P,
		G: params.G,
		Q: params.Q,
	}

	// Generate random private key
	max := new(big.Int).Sub(dh.P, big.NewInt(2))
	privKey, err := rand.Int(rand.Reader, max)
	if err != nil {
		return nil, err
	}
	dh.PrivKey = new(big.Int).Add(privKey, big.NewInt(1))

	// Calculate public key: g^privkey mod p
	dh.PubKey = new(big.Int).Exp(dh.G, dh.PrivKey, dh.P)

	// Generate DH nonce (32 random bytes)
	dh.DHNonce = make([]byte, 32)
	_, err = rand.Read(dh.DHNonce)
	if err != nil {
		return nil, err
	}

	return dh, nil
}

// GetPublicKey returns the public key as bytes for inclusion in AuthPack
func (d *DirtyDH) GetPublicKey() []byte {
	return d.PubKey.Bytes()
}

// Exchange computes the shared secret given the server's public key
func (d *DirtyDH) Exchange(serverPubKey *big.Int) []byte {
	// shared_secret = server_pubkey^privkey mod p
	sharedSecret := new(big.Int).Exp(serverPubKey, d.PrivKey, d.P)

	// CRITICAL: Must pad to the full modulus size (128 bytes for 1024-bit DH)
	// big.Int.Bytes() strips leading zeros, but Kerberos PKINIT expects
	// the shared secret to always be the full modulus length
	expectedLen := (d.P.BitLen() + 7) / 8 // 1024 bits = 128 bytes
	secretBytes := sharedSecret.Bytes()

	if len(secretBytes) < expectedLen {
		// Pad with leading zeros
		padded := make([]byte, expectedLen)
		copy(padded[expectedLen-len(secretBytes):], secretBytes)
		return padded
	}

	return secretBytes
}

// DomainParameters represents the ASN.1 DH domain parameters
type DomainParameters struct {
	P asn1.RawValue
	G asn1.RawValue
	Q asn1.RawValue
}

// PublicKeyAlgorithm represents the algorithm identifier for DH
type PublicKeyAlgorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters DomainParameters `asn1:"optional"`
}

// SubjectPublicKeyInfo represents the public key info structure
type SubjectPublicKeyInfo struct {
	Algorithm PublicKeyAlgorithm
	PublicKey asn1.BitString
}

// GetPublicKeyInfo returns the SubjectPublicKeyInfo structure for AuthPack
func (d *DirtyDH) GetPublicKeyInfo() (SubjectPublicKeyInfo, error) {
	// DH algorithm OID: 1.2.840.10046.2.1
	dhOID := asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}

	// Encode P as INTEGER
	pBytes, err := asn1.Marshal(d.P)
	if err != nil {
		return SubjectPublicKeyInfo{}, err
	}

	// Encode G as INTEGER
	gBytes, err := asn1.Marshal(d.G)
	if err != nil {
		return SubjectPublicKeyInfo{}, err
	}

	// Encode Q as INTEGER (always 0)
	qBytes, err := asn1.Marshal(d.Q)
	if err != nil {
		return SubjectPublicKeyInfo{}, err
	}

	params := DomainParameters{
		P: asn1.RawValue{FullBytes: pBytes},
		G: asn1.RawValue{FullBytes: gBytes},
		Q: asn1.RawValue{FullBytes: qBytes},
	}

	alg := PublicKeyAlgorithm{
		Algorithm:  dhOID,
		Parameters: params,
	}

	// Convert public key to BitString
	// The public key must be encoded as an INTEGER inside the BIT STRING
	// per X.509/DH key format
	pubKeyInt, err := asn1.Marshal(d.PubKey)
	if err != nil {
		return SubjectPublicKeyInfo{}, err
	}

	bitString := asn1.BitString{
		Bytes:     pubKeyInt,
		BitLength: len(pubKeyInt) * 8,
	}

	return SubjectPublicKeyInfo{
		Algorithm: alg,
		PublicKey: bitString,
	}, nil
}
