package pkinit

import (
	"math/big"
	"testing"
)

// TestStaticDHParams verifies the static DH parameters match expected values.
func TestStaticDHParams(t *testing.T) {
	params := StaticDHParams()

	// G must be 2
	if params.G.Cmp(big.NewInt(2)) != 0 {
		t.Errorf("G = %s, want 2", params.G.String())
	}

	// Q must be 0
	if params.Q.Cmp(big.NewInt(0)) != 0 {
		t.Errorf("Q = %s, want 0", params.Q.String())
	}

	// P should be the well-known 1024-bit MODP group (RFC 2409)
	expectedP := new(big.Int)
	expectedP.SetString("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff", 16)

	if params.P.Cmp(expectedP) != 0 {
		t.Error("P does not match expected MODP 1024-bit prime")
	}

	// P should be 1024 bits
	if params.P.BitLen() != 1024 {
		t.Errorf("P bit length = %d, want 1024", params.P.BitLen())
	}
}

// TestNewDirtyDH validates key generation basics.
func TestNewDirtyDH(t *testing.T) {
	params := StaticDHParams()
	dh, err := NewDirtyDH(params)
	if err != nil {
		t.Fatalf("NewDirtyDH() error: %v", err)
	}

	// Private key should be > 0
	if dh.PrivKey.Sign() <= 0 {
		t.Error("PrivKey should be positive")
	}

	// Private key should be < P
	if dh.PrivKey.Cmp(dh.P) >= 0 {
		t.Error("PrivKey should be less than P")
	}

	// Public key should be g^privkey mod p
	expected := new(big.Int).Exp(dh.G, dh.PrivKey, dh.P)
	if dh.PubKey.Cmp(expected) != 0 {
		t.Error("PubKey != G^PrivKey mod P")
	}

	// DH nonce should be 32 bytes
	if len(dh.DHNonce) != 32 {
		t.Errorf("DHNonce length = %d, want 32", len(dh.DHNonce))
	}

	// Public key bytes should not be empty
	if len(dh.GetPublicKey()) == 0 {
		t.Error("GetPublicKey() returned empty bytes")
	}
}

// TestDirtyDHExchange verifies the DH exchange with a known server public key.
func TestDirtyDHExchange(t *testing.T) {
	params := StaticDHParams()
	client, err := NewDirtyDH(params)
	if err != nil {
		t.Fatalf("NewDirtyDH(client) error: %v", err)
	}

	server, err := NewDirtyDH(params)
	if err != nil {
		t.Fatalf("NewDirtyDH(server) error: %v", err)
	}

	// Both sides should compute the same shared secret
	clientSecret := client.Exchange(server.PubKey)
	serverSecret := server.Exchange(client.PubKey)

	if len(clientSecret) != len(serverSecret) {
		t.Fatalf("shared secret lengths differ: client=%d, server=%d", len(clientSecret), len(serverSecret))
	}

	for i := range clientSecret {
		if clientSecret[i] != serverSecret[i] {
			t.Fatalf("shared secrets differ at byte %d", i)
		}
	}
}

// TestDirtyDHExchangePadding verifies the shared secret is padded to modulus size.
func TestDirtyDHExchangePadding(t *testing.T) {
	params := StaticDHParams()
	dh, err := NewDirtyDH(params)
	if err != nil {
		t.Fatalf("NewDirtyDH() error: %v", err)
	}

	// Use a small server public key that will produce a small shared secret
	serverPub := big.NewInt(3)
	secret := dh.Exchange(serverPub)

	expectedLen := (params.P.BitLen() + 7) / 8 // 128 bytes for 1024-bit
	if len(secret) != expectedLen {
		t.Errorf("Exchange() returned %d bytes, want %d (full modulus size)", len(secret), expectedLen)
	}
}

// TestGetPublicKeyInfo verifies the SubjectPublicKeyInfo structure can be built.
func TestGetPublicKeyInfo(t *testing.T) {
	params := StaticDHParams()
	dh, err := NewDirtyDH(params)
	if err != nil {
		t.Fatalf("NewDirtyDH() error: %v", err)
	}

	spki, err := dh.GetPublicKeyInfo()
	if err != nil {
		t.Fatalf("GetPublicKeyInfo() error: %v", err)
	}

	// Check DH OID
	expectedOID := "1.2.840.10046.2.1"
	if spki.Algorithm.Algorithm.String() != expectedOID {
		t.Errorf("Algorithm OID = %s, want %s", spki.Algorithm.Algorithm.String(), expectedOID)
	}

	// PublicKey BitString should not be empty
	if len(spki.PublicKey.Bytes) == 0 {
		t.Error("PublicKey BitString is empty")
	}
}

// TestNewDirtyDHUniqueness ensures each instance gets unique keys.
func TestNewDirtyDHUniqueness(t *testing.T) {
	params := StaticDHParams()

	dh1, err := NewDirtyDH(params)
	if err != nil {
		t.Fatalf("NewDirtyDH(1) error: %v", err)
	}

	dh2, err := NewDirtyDH(params)
	if err != nil {
		t.Fatalf("NewDirtyDH(2) error: %v", err)
	}

	if dh1.PrivKey.Cmp(dh2.PrivKey) == 0 {
		t.Error("two DH instances generated the same private key")
	}

	if dh1.PubKey.Cmp(dh2.PubKey) == 0 {
		t.Error("two DH instances generated the same public key")
	}
}
