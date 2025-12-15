# gopkinit

A complete Go implementation of PKINIT (Public Key Cryptography for Initial Authentication in Kerberos), providing certificate-based authentication to Active Directory.

## 🎉 Status: **FULLY WORKING**

Successfully tested against Active Directory - obtains valid TGTs and authenticates to services (SMB, LDAP, etc.)

## Overview

This project implements RFC 4556 (PKINIT) in Go, providing both a reusable library and a CLI tool. Unlike `gokrb5`, which lacks PKINIT support, this implementation adds the complete PKINIT layer for certificate-based Kerberos authentication.

## Features

- ✅ **PKINIT Authentication**: Request TGT using X.509 certificate authentication
- ✅ **Certificate Support**: Load certificates from PFX/PKCS12 files
- ✅ **Diffie-Hellman Key Exchange**: Implements DH with static parameters for AD compatibility
- ✅ **CMS/PKCS7 Signing**: Native Go implementation of AuthPack signing
- ✅ **ccache Output**: Generates MIT Kerberos ccache v4 files (compatible with all tools)
- ✅ **AS-REP Key Export**: Outputs encryption key needed for getnthash
- ✅ **SOCKS5 Proxy**: Support for proxying connections through SOCKS5
- ✅ **Production Ready**: Successfully tested with Impacket, native Kerberos tools

## Installation

```bash
# Clone and build
git clone <repo>
cd gopkinit
go build -o gettgtpkinit ./cmd/gettgtpkinit

# Or install directly
go install github.com/ineffectivecoder/gopkinit/cmd/gettgtpkinit@latest
```

## Usage

### Basic Usage

```bash
# Request TGT with certificate
./gettgtpkinit -cert-pfx user.pfx DOMAIN.COM/user output.ccache

# With password-protected PFX
./gettgtpkinit -cert-pfx user.pfx -pfx-pass password DOMAIN.COM/user output.ccache

# Specify DC IP address
./gettgtpkinit -cert-pfx user.pfx -dc-ip 10.0.0.1 DOMAIN.COM/user output.ccache

# Through SOCKS5 proxy
./gettgtpkinit -cert-pfx user.pfx -proxy 127.0.0.1:1080 -dc-ip 10.0.0.1 DOMAIN.COM/user output.ccache

# Verbose output
./gettgtpkinit -cert-pfx user.pfx -v DOMAIN.COM/user output.ccache
```

### Using the Obtained TGT

```bash
# Verify the TGT
klist -c output.ccache

# Use with Impacket tools
export KRB5CCNAME=output.ccache
smbclient.py -k target.domain.com
secretsdump.py -k domain/user@dc.domain.com -no-pass

# Use with native Kerberos tools
kinit -c output.ccache
```

### Example Output

```
$ ./gettgtpkinit -cert-pfx slacker.pfx -dc-ip 10.1.1.10 spinninglikea.top/slacker output.ccache
AS-REP encryption key (you might need this later):
95ba4cf1622f464d4fd5110797d24ea6c12dc0bea44eb19e9bb1242e4abb7207
2025/12/15 00:01:40 Saved TGT to file

$ klist -c output.ccache
Ticket cache: FILE:output.ccache
Default principal: slacker@SPINNINGLIKEA.TOP

Valid starting       Expires              Service principal
12/15/2025 00:01:34  12/15/2025 10:01:34  krbtgt/SPINNINGLIKEA.TOP@SPINNINGLIKEA.TOP
        renew until 12/16/2025 00:01:40, Etype: aes256-cts-hmac-sha1-96

$ KRB5CCNAME=output.ccache smbclient.py -k tip.spinninglikea.top
# Connected successfully with admin access!
```

## Library Usage

```go
import "github.com/ineffectivecoder/gopkinit/pkg/pkinit"

// Load certificate from PFX
client, err := pkinit.NewFromPFX("user.pfx", "password")
if err != nil {
    log.Fatal(err)
}

// Request TGT (last parameter is SOCKS5 proxy, empty string for no proxy)
result, err := client.GetTGT("DOMAIN.COM", "user", "dc.domain.com", "")
if err != nil {
    log.Fatal(err)
}

// Use result.ASRepKey for getnthash
fmt.Println("AS-REP Key:", result.ASRepKey)

// result.Ticket and result.SessionKey available for further operations
```

## Project Structure

```
gopkinit/
├── cmd/
│   └── gettgtpkinit/     # CLI tool
│       └── main.go
├── pkg/
│   ├── cert/             # Certificate loading
│   │   └── loader.go
│   ├── pkinit/           # PKINIT implementation
│   │   ├── pkinit.go     # Main client
│   │   ├── dh.go         # Diffie-Hellman
│   │   ├── authpack.go   # ASN.1 structures
│   │   ├── cms.go        # CMS/PKCS7 signing
│   │   ├── asreq.go      # AS-REQ builder
│   │   ├── asrep.go      # AS-REP decryption
│   │   └── manual_decrypt.go  # Manual AES-CTS decryption
│   ├── krb/              # Kerberos network client
│   │   └── client.go
│   └── ccache/           # ccache file writer
│       └── ccache.go
```

## Bugs Fixed During Development

### Critical Bug #1: ServerDHNonce Not Extracted

**Problem**: The `serverDHNonce` field (32 bytes) in PA_PK_AS_REP was not being extracted, causing wrong encryption key and HMAC verification failures.

**Fix**: Two-step parsing with explicit tag handling for mixed implicit/explicit ASN.1 tags.

**Impact**: Full key changed from 160 bytes → 192 bytes, HMAC now verifies ✅

### Critical Bug #2: DH Shared Secret Padding

**Problem**: `big.Int.Bytes()` strips leading zeros, causing variable-length shared secrets.

**Fix**: Always pad to modulus size (128 bytes for 1024-bit DH).

### Bug #3: ccache Key Format

**Problem**: Missing 2-byte `etype` field between keytype and keylen in MIT ccache v4 format.

**Fix**: Added etype field (always 0) - ccache files now work with all Kerberos tools ✅

### Additional Fixes

- APPLICATION tag wrapper for AS-REQ
- NULL parameters in CMS digest/signature algorithms  
- DH public key INTEGER encoding
- EncapsulatedContentInfo OCTET STRING wrapper
- EncASRepPart APPLICATION 25 tag unwrapping
- Ticket APPLICATION 1 tag unwrapping

See [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for complete technical details.

## Testing & Verification

### Successful Tests

✅ **TGT Retrieval**: Successfully obtains valid TGTs from Active Directory  
✅ **ccache Compatibility**: Works with `klist`, `kinit`, and all native tools  
✅ **Impacket Integration**: Tested with `smbclient.py`, `secretsdump.py`, `ldapdomaindump`  
✅ **Production Use**: TGTs usable for real authentication

### Test Results

- **Domain**: spinninglikea.top  
- **DC**: Windows Server 2019 (10.1.1.10)
- **Certificate**: AD CS enrolled user certificate
- **Verification**: SMB admin share access, LDAP queries, service authentication

## Dependencies

```go
require (
    github.com/jcmturner/gokrb5/v8           // Kerberos structures
    software.sslmate.com/src/go-pkcs12       // PKCS12 parsing
    golang.org/x/net/proxy                   // SOCKS5 support
    golang.org/x/crypto                      // Crypto primitives
)
```

## Known Limitations

- PEM certificate format not yet supported (use PFX)
- RC4 encryption not supported (AES256/AES128 only)
- No smart card/hardware token support

## Future Enhancements

- **getnthash**: U2U (User-to-User) for NT hash extraction
- **gets4uticket**: S4U2Self implementation
- **PEM Support**: Load certificates from PEM files

## References

- [RFC 4556 - PKINIT](https://datatracker.ietf.org/doc/html/rfc4556)
- [PKINITtools](https://github.com/dirkjanm/PKINITtools) by @_dirkjan
- [gokrb5](https://github.com/jcmturner/gokrb5)

## License

Based on PKINITtools by Dirk-jan Mollema (@_dirkjan).

---

**Built for the security community** 🔐
