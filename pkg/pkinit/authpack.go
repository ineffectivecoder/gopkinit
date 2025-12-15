package pkinit

import (
	"encoding/asn1"
	"time"
)

// RFC 4556 ASN.1 Structures for PKINIT

//	PKAuthenticator ::= SEQUENCE {
//	   cusec        [0] INTEGER (0..999999),
//	   ctime        [1] KerberosTime,
//	   nonce        [2] INTEGER (0..4294967295),
//	   paChecksum   [3] OCTET STRING OPTIONAL
//	}
type PKAuthenticator struct {
	Cusec      int       `asn1:"explicit,tag:0"`
	Ctime      time.Time `asn1:"generalized,explicit,tag:1"`
	Nonce      int       `asn1:"explicit,tag:2"`
	PaChecksum []byte    `asn1:"explicit,optional,tag:3"`
}

//	AuthPack ::= SEQUENCE {
//	   pkAuthenticator   [0] PKAuthenticator,
//	   clientPublicValue [1] SubjectPublicKeyInfo OPTIONAL,
//	   supportedCMSTypes [2] SEQUENCE OF AlgorithmIdentifier OPTIONAL,
//	   clientDHNonce     [3] DHNonce OPTIONAL
//	}
type AuthPack struct {
	PKAuthenticator   PKAuthenticator      `asn1:"explicit,tag:0"`
	ClientPublicValue SubjectPublicKeyInfo `asn1:"explicit,optional,tag:1"`
	ClientDHNonce     []byte               `asn1:"explicit,optional,tag:3"`
}

//	PA_PK_AS_REQ ::= SEQUENCE {
//	   signedAuthPack          [0] IMPLICIT OCTET STRING,
//	   trustedCertifiers       [1] SEQUENCE OF ExternalPrincipalIdentifier OPTIONAL,
//	   kdcPkId                 [2] IMPLICIT OCTET STRING OPTIONAL
//	}
type PA_PK_AS_REQ struct {
	SignedAuthPack []byte `asn1:"implicit,tag:0"`
}

//	PA_PK_AS_REP ::= CHOICE {
//	   dhInfo                  [0] DHRepInfo,
//	   encKeyPack              [1] IMPLICIT OCTET STRING
//	}
//
// We only support DH mode (encKeyPack is RSA mode, not implemented)
type PA_PK_AS_REP struct {
	DHSignedData  []byte `asn1:"optional,tag:0"`
	ServerDHNonce []byte `asn1:"optional,tag:1"`
}

//	KDCDHKeyInfo ::= SEQUENCE {
//	   subjectPublicKey        [0] BIT STRING,
//	   nonce                   [1] INTEGER OPTIONAL,
//	   dhKeyExpiration         [2] KerberosTime OPTIONAL
//	}
type KDCDHKeyInfo struct {
	SubjectPublicKey asn1.BitString `asn1:"explicit,tag:0"`
	Nonce            int            `asn1:"explicit,optional,tag:1"`
	DHKeyExpiration  time.Time      `asn1:"generalized,explicit,optional,tag:2"`
}

// ContentInfo for CMS structures
type ContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// EncapsulatedContentInfo from CMS
type EncapsulatedContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}
