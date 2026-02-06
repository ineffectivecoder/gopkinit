# gettgtpkinit - PKINIT Deep Dive

## Overview

`gettgtpkinit` implements RFC 4556 PKINIT (Public Key Cryptography for Initial Authentication in Kerberos) to obtain a TGT using X.509 certificate authentication instead of a password.

## Attack Scenarios

PKINIT authentication is useful when you have:

1. **Stolen certificates** - ESC1-ESC8 AD CS misconfigurations
2. **Shadow Credentials** - msDS-KeyCredentialLink attribute abuse
3. **Machine account certificates** - Extracted from compromised hosts
4. **Smart card certificates** - Stolen or cloned

## Protocol Flow

```
┌──────────┐                          ┌──────────┐
│  Client  │                          │   KDC    │
└────┬─────┘                          └────┬─────┘
     │                                     │
     │  AS-REQ with PA-PK-AS-REQ           │
     │  (signed AuthPack + DH public key)  │
     │────────────────────────────────────>│
     │                                     │
     │                                     │ Verify signature
     │                                     │ Check certificate
     │                                     │ Compute DH shared secret
     │                                     │
     │  AS-REP with PA-PK-AS-REP           │
     │  (KDC's DH public key + nonce)      │
     │<────────────────────────────────────│
     │                                     │
     │ Compute DH shared secret            │
     │ Derive session key                  │
     │ Decrypt EncASRepPart                │
     │                                     │
     ▼                                     ▼
   TGT obtained!
```

## Key Implementation Details

### 1. Diffie-Hellman Parameters

Active Directory requires specific 1024-bit DH parameters (OID 2.16.840.1.101.2.1.1.22):

```go
// Static DH parameters - AD requires these exact values
var dhPrime = /* 1024-bit prime from RFC 2409 */
var dhGenerator = big.NewInt(2)
```

Using dynamically generated parameters will fail!

### 2. AuthPack Signing

The AuthPack contains:

- Current timestamp (PKAuthenticator)
- Client's DH public key
- Supported CMS algorithms

This is signed with the client's certificate using CMS/PKCS7:

```go
// SignAuthPack(data, cert, privateKey, wrapInContentInfo)
signedAuthPack, err := SignAuthPack(authPackBytes, certificate, privateKey, true)
```

### 3. Shared Secret Derivation

After receiving the KDC's DH public key:

```go
// Compute shared secret: g^(xy) mod p
sharedSecret := new(big.Int).Exp(kdcPublicKey, clientPrivateKey, dhPrime)

// CRITICAL: Zero-pad to modulus size (128 bytes)
// big.Int.Bytes() strips leading zeros!
paddedSecret := zeroPad(sharedSecret.Bytes(), 128)

// Derive key using octetstring2key from gokrb5
sessionKey := etype.DeriveKey(paddedSecret, usage)
```

### 4. AS-REP Key

The AS-REP encryption key is derived from the DH shared secret and is needed later for `getnthash`:

```go
// truncateKey: iterative SHA1 hash-and-concatenate, then truncate to key size
// SHA1(0x00 || value) || SHA1(0x01 || value) || ... truncated to keySize
asRepKey := truncateKey(sharedSecret, keySize)
```

## Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `KDC_ERR_PREAUTH_FAILED` | Certificate not trusted | Ensure CA is in NTAuth store |
| `KDC_ERR_CLIENT_NOT_TRUSTED` | Certificate revoked/expired | Check certificate validity |
| `Clock skew too great` | Time not synchronized | Run `ntpdate <dc-ip>` |
| `KDC_ERR_C_PRINCIPAL_UNKNOWN` | Wrong username | Username must match certificate UPN/SAN |

## Usage Examples

```bash
# Basic usage
./gettgtpkinit -cert-pfx user.pfx -dc-ip 10.0.0.1 DOMAIN.COM/user output.ccache

# With password-protected PFX
./gettgtpkinit -cert-pfx user.pfx -pfx-pass "password" -dc-ip 10.0.0.1 DOMAIN.COM/user output.ccache

# Through SOCKS proxy
./gettgtpkinit -cert-pfx user.pfx -proxy 127.0.0.1:1080 -dc-ip 10.0.0.1 DOMAIN.COM/user output.ccache
```

## Output

The tool outputs:

1. **ccache file** - MIT Kerberos credential cache with the TGT
2. **AS-REP key** - Hex string needed for `getnthash`

```
AS-REP encryption key (you might need this later):
c0ffee1234567890abcdef1234567890c0ffee1234567890abcdef1234567890
Saved TGT to file
```

## References

- [RFC 4556 - PKINIT](https://datatracker.ietf.org/doc/html/rfc4556)
- [RFC 2409 - IKE DH Groups](https://datatracker.ietf.org/doc/html/rfc2409)
- [Certified Pre-Owned](https://posts.specterops.io/certified-pre-owned-d95910965cd2) - AD CS attack research
