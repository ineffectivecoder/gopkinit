# gopkinit Implementation Plan

## Status: ✅ **COMPLETE & WORKING**

All implementation phases completed. Tool successfully tested against Active Directory and works with Impacket/native Kerberos tools.

---

## Final Implementation Status (Dec 15, 2025)

### ✅ All Phases Complete

| Phase | Component | Status | 
|-------|-----------|--------|
| 1 | Project Setup + Cert Loading | ✅ Complete |
| 2 | Diffie-Hellman | ✅ Complete |
| 3 | ASN.1 Structures | ✅ Complete |
| 4 | CMS Signing | ✅ Complete |
| 5 | AS-REQ Builder | ✅ Complete |
| 6 | AS-REP Decryption | ✅ Complete |
| 7 | Network Client | ✅ Complete |
| 8 | ccache Output | ✅ Complete |
| 9 | PKINIT Client | ✅ Complete |
| 10 | CLI Tool | ✅ Complete |
| 11 | SOCKS5 Proxy | ✅ Complete |

### ✅ Production Testing

**Successfully tested with:**
- Active Directory (Windows Server 2019)
- Impacket tools (`smbclient.py`, `secretsdump.py`)
- Native Kerberos tools (`klist`, `kinit`)
- Real service authentication (SMB, LDAP)

**Test Results:**
```bash
$ ./gettgtpkinit -cert-pfx slacker.pfx -dc-ip 10.1.1.10 spinninglikea.top/slacker output.ccache
AS-REP encryption key: 95ba4cf1622f464d4fd5110797d24ea6c12dc0bea44eb19e9bb1242e4abb7207
Saved TGT to file

$ klist -c output.ccache
Valid starting       Expires              Service principal
12/15/2025 00:01:34  12/15/2025 10:01:34  krbtgt/SPINNINGLIKEA.TOP@SPINNINGLIKEA.TOP

$ KRB5CCNAME=output.ccache smbclient.py -k tip.spinninglikea.top
# Successfully connected with admin access ✅
```

---

## Critical Bugs Fixed

### 🐛 Bug #1: ServerDHNonce Not Extracted (CRITICAL)

**Severity**: CRITICAL - Prevented all authentication  
**Symptoms**:
- HMAC verification failed: "integrity verification failed"
- Full key length: 160 bytes (should be 192)
- ServerDHNonce extraction: 0 bytes (should be 32)

**Root Cause**:
ASN.1 struct definition incorrectly marked `ServerDHNonce` as `implicit`:
```go
// WRONG
ServerDHNonce []byte `asn1:"optional,implicit,tag:1"`
```

RFC 4556 specifies explicit tagging:
```asn1
DHRepInfo ::= SEQUENCE {
    dhSignedData      [0] IMPLICIT OCTET STRING,
    serverDHNonce     [1] DHNonce OPTIONAL    -- EXPLICIT
}
```

**Solution**:
Two-step parsing with `RawValue` to handle mixed implicit/explicit tags:
```go
type DHRepInfoRaw struct {
    DHSignedData  asn1.RawValue `asn1:"tag:0"`
    ServerDHNonce asn1.RawValue `asn1:"optional,tag:1"`
}

// Extract dhSignedData (implicit - Bytes = raw data)
dhSignedData := dhRepInfoRaw.DHSignedData.Bytes

// Extract serverDHNonce (explicit - contains OCTET STRING)
var serverDHNonce []byte
if dhRepInfoRaw.ServerDHNonce.Bytes != nil {
    asn1.Unmarshal(dhRepInfoRaw.ServerDHNonce.Bytes, &serverDHNonce)
}
```

**Result**:
- ✅ ServerDHNonce: 32 bytes extracted
- ✅ Full key: 192 bytes (128 shared + 32 client + 32 server)
- ✅ HMAC verification: SUCCESS
- ✅ TGT obtained successfully

**Files Modified**: `pkg/pkinit/asrep.go`

---

### 🐛 Bug #2: DH Shared Secret Padding (HIGH)

**Severity**: HIGH - Intermittent failures  
**Symptoms**:
- Decryption failures depending on shared secret value
- Shared secret length varied (123-128 bytes)
- Not reproducible on every run

**Root Cause**:
`big.Int.Bytes()` strips leading zeros:
```go
// If shared secret starts with 0x00, returns 127 bytes instead of 128
secretBytes := sharedSecret.Bytes()  // Variable length!
```

**Solution**:
Explicit padding to modulus size:
```go
func (d *DirtyDH) Exchange(serverPubKey *big.Int) []byte {
    sharedSecret := new(big.Int).Exp(serverPubKey, d.PrivKey, d.P)
    expectedLen := (d.P.BitLen() + 7) / 8  // 128 bytes for 1024-bit
    secretBytes := sharedSecret.Bytes()
    
    if len(secretBytes) < expectedLen {
        padded := make([]byte, expectedLen)
        copy(padded[expectedLen-len(secretBytes):], secretBytes)
        return padded
    }
    return secretBytes
}
```

**Result**:
- ✅ Shared secret: Always 128 bytes
- ✅ Consistent key derivation
- ✅ No more intermittent failures

**Files Modified**: `pkg/pkinit/dh.go`

---

### 🐛 Bug #3: ccache Key Format (MEDIUM)

**Severity**: MEDIUM - ccache not usable  
**Symptoms**:
- `klist` error: "Bad format in credentials cache"
- File created but tools rejected it
- Impacket couldn't read ccache

**Root Cause**:
Missing 2-byte `etype` field in MIT ccache v4 key encoding.

Python ccache (working):
```
00 12 00 00 00 20 [key data...]
^     ^     ^
keytype  etype keylen
```

Go ccache (broken):
```
00 12 00 20 [key data...]
^     ^
keytype keylen (missing etype!)
```

**Solution**:
```go
// Key format: keytype (2) + etype (2) + keylen (2) + data
binary.Write(f, binary.BigEndian, uint16(key.KeyType))
binary.Write(f, binary.BigEndian, uint16(0))  // etype (required!)
binary.Write(f, binary.BigEndian, uint16(len(key.KeyValue)))
f.Write(key.KeyValue)
```

**Result**:
- ✅ `klist` displays TGT correctly
- ✅ Impacket tools can read ccache
- ✅ Native Kerberos tools work

**Files Modified**: `pkg/ccache/ccache.go`

---

### 🐛 Bug #4: EncASRepPart APPLICATION Tag (LOW)

**Severity**: LOW - After fixing bugs 1-3  
**Symptoms**: ASN.1 parse error after successful HMAC verification

**Root Cause**:
Decrypted AS-REP enc-part has `[APPLICATION 25]` wrapper per RFC 4120.

**Solution**:
```go
// Parse APPLICATION 25 wrapper first
var encASRepPartApp asn1.RawValue
asn1.Unmarshal(decrypted, &encASRepPartApp)

// Then parse actual content
var encASRepPart EncASRepPart
asn1.Unmarshal(encASRepPartApp.Bytes, &encASRepPart)
```

**Files Modified**: `pkg/pkinit/asrep.go`

---

### 🐛 Bug #5: Ticket APPLICATION Tag (LOW)

**Severity**: LOW  
**Symptoms**: Ticket parse error in GetTGT

**Root Cause**:
Ticket has `[APPLICATION 1]` wrapper in AS-REP.

**Solution**:
```go
// Extract as RawValue first
TicketRaw asn1.RawValue `asn1:"explicit,tag:5"`

// Then unwrap APPLICATION 1
var ticketApp asn1.RawValue
asn1.Unmarshal(rawASRep.TicketRaw.Bytes, &ticketApp)

var ticket messages.Ticket
asn1.Unmarshal(ticketApp.Bytes, &ticket)
```

**Files Modified**: `pkg/pkinit/pkinit.go`

---

## Additional Fixes (AS-REQ Encoding)

Early debugging fixed multiple ASN.1 encoding issues that caused KDC timeout:

### Fix #6: AS-REQ APPLICATION Tag
- **Issue**: Used CONTEXT tag (0x4a) instead of APPLICATION (0x6a)
- **Fix**: Manual tag construction with correct class

### Fix #7: Digest Algorithm NULL Parameters
- **Issue**: SHA1 algorithm missing NULL parameters
- **Fix**: Added explicit NULL: `300906052b0e03021a0500`

### Fix #8: Signature Algorithm NULL
- **Issue**: RSA algorithm missing NULL parameters  
- **Fix**: Added NULL to rsaEncryption OID

### Fix #9: DH Public Key Encoding
- **Issue**: Raw bytes in BIT STRING
- **Fix**: Encode as INTEGER first: `02 81 80 <128 bytes>`

### Fix #10: EncapsulatedContentInfo
- **Issue**: Raw AuthPack bytes
- **Fix**: Wrap in OCTET STRING: `04 82 01 8a <AuthPack>`

**Files Modified**: `pkg/pkinit/asreq.go`, `pkg/pkinit/cms.go`, `pkg/pkinit/dh.go`

---

## Feature Addition: SOCKS5 Proxy Support

**Purpose**: Enable tool use through proxies for pivoting/tunneling

**Implementation**:
```go
// pkg/krb/client.go
type KDCClient struct {
    ProxyAddr string  // SOCKS5 proxy address
}

func (c *KDCClient) SendASReq(req []byte) ([]byte, error) {
    if c.ProxyAddr != "" {
        dialer, _ := proxy.SOCKS5("tcp", c.ProxyAddr, nil, proxy.Direct)
        conn, _ = dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", addr)
    } else {
        conn, _ = net.DialTimeout("tcp", addr, c.Timeout)
    }
}
```

**CLI Usage**:
```bash
./gettgtpkinit -cert-pfx cert.pfx -proxy 127.0.0.1:1080 -dc-ip 10.0.0.1 domain/user out.ccache
```

**Files Modified**: `pkg/krb/client.go`, `pkg/pkinit/pkinit.go`, `cmd/gettgtpkinit/main.go`

---

## Debugging Journey Summary (RESOLVED)

### Phase 1: KDC Timeout (Bugs #6-10) - ✅ RESOLVED
- **Duration**: Early implementation
- **Problem**: KDC accepted connection but no response
- **Method**: Byte-by-byte comparison with Python
- **Result**: Fixed 5 ASN.1 encoding issues
- **Status**: All ASN.1 IMPLICIT tag issues resolved

### Phase 2: HMAC Failure (Bugs #1-2) - ✅ RESOLVED  
- **Duration**: Dec 14-15, 2025
- **Problem**: "integrity verification failed"
- **Method**: 
  - Implemented manual Python-style decryption
  - Added extensive debug logging (removed in production)
  - Compared key derivation with minikerberos
  - Analyzed PA_PK_AS_REP with openssl asn1parse
- **Breakthrough**: OpenSSL showed ServerDHNonce present but not extracted
- **Result**: Fixed explicit/implicit tag handling, added DH padding
- **Status**: ServerDHNonce extraction working, DH padding fixed

### Phase 3: ccache Format (Bug #3) - ✅ RESOLVED
- **Duration**: Dec 15, 2025 (post-decryption fix)
- **Problem**: TGT obtained but ccache rejected by tools
- **Method**: Hexdump comparison with Python ccache
- **Result**: Added missing etype field
- **Status**: ccache fully compatible with klist and Impacket

### Phase 4: Production Testing - ✅ COMPLETE
- **Duration**: Dec 15, 2025
- **Testing**: Impacket smbclient.py with Kerberos auth
- **Result**: ✅ **FULL SUCCESS**
- **Status**: Production-ready, all debug code removed

---

## Key Technical Decisions

1. **Manual CMS Construction**: No suitable Go library for PKCS7/CMS with full control
2. **Static DH Parameters**: AD rejects dynamically generated params
3. **gokrb5 for Base Only**: Used only for structures, not PKINIT
4. **Explicit ASN.1 Handling**: Many manual tag unwrapping operations
5. **Extensive Logging**: Debug output crucial for troubleshooting

---

## Comparison: Python vs Go

| Aspect | Python | Go | Notes |
|--------|--------|-----|-------|
| AS-REQ Size | 1841 bytes | 1842 bytes | 1-byte difference acceptable |
| Server DHNonce | ✓ 32 bytes | ✓ 32 bytes | After Bug #1 fix |
| Full Key | ✓ 192 bytes | ✓ 192 bytes | After Bug #1 fix |
| Ki/Ke Derivation | ✓ Match | ✓ Match | Verified identical |
| HMAC | ✓ Success | ✓ Success | After Bug #1 fix |
| ccache Format | ✓ Works | ✓ Works | After Bug #3 fix |
| TGT Validity | ✓ 10 hours | ✓ 10 hours | Same from AD |
| Service Auth | ✓ Works | ✓ Works | SMB tested |

---

## Dependencies

```go
require (
    github.com/jcmturner/gokrb5/v8           v8.4.4
    software.sslmate.com/src/go-pkcs12       v0.4.0
    golang.org/x/net/proxy                   latest
    golang.org/x/crypto                      latest
)
```

---

## Future Work

- **getnthash**: U2U for NT hash extraction
- **gets4uticket**: S4U2Self implementation  
- **PEM Support**: Load certificates from PEM files
- **PAC Parsing**: Extract PAC structures

---

## References

- [RFC 4556 - PKINIT](https://datatracker.ietf.org/doc/html/rfc4556)
- [RFC 4120 - Kerberos V5](https://datatracker.ietf.org/doc/html/rfc4120)
- [PKINITtools](https://github.com/dirkjanm/PKINITtools)
- [minikerberos](https://github.com/skelsec/minikerberos)
- [gokrb5](https://github.com/jcmturner/gokrb5)

---

**Implementation Complete**: Dec 15, 2025  
**Status**: Production Ready ✅
