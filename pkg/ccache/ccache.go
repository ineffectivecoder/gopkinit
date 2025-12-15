package ccache

import (
	"encoding/binary"
	"fmt"
	"os"
	"time"

	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// WriteCCache writes a TGT to a ccache file in MIT ccache format version 4
func WriteCCache(path string, ticket messages.Ticket, encPart messages.EncKDCRepPart, sessionKey types.EncryptionKey, realm string, cname types.PrincipalName) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("failed to create ccache file: %w", err)
	}
	defer f.Close()

	// Marshal ticket to bytes
	ticketBytes, err := ticket.Marshal()
	if err != nil {
		return fmt.Errorf("failed to marshal ticket: %w", err)
	}

	// File format version 0x0504 (version 4)
	binary.Write(f, binary.BigEndian, uint16(0x0504))

	// Header length (12 bytes for version 4)
	binary.Write(f, binary.BigEndian, uint16(12))

	// Tag 1: DeltaTime (8 bytes, set to 0)
	binary.Write(f, binary.BigEndian, uint16(1))
	binary.Write(f, binary.BigEndian, uint16(8))
	binary.Write(f, binary.BigEndian, uint64(0))

	// Default principal
	writePrincipal(f, cname, realm)

	// Credential
	writeCredential(f, cname, realm, encPart.SName, encPart.SRealm, sessionKey, encPart, ticketBytes)

	return nil
}

func writePrincipal(f *os.File, name types.PrincipalName, realm string) error {
	// Name type
	binary.Write(f, binary.BigEndian, uint32(name.NameType))

	// Number of components
	binary.Write(f, binary.BigEndian, uint32(len(name.NameString)))

	// Realm
	writeCountedString(f, realm)

	// Components
	for _, comp := range name.NameString {
		writeCountedString(f, comp)
	}

	return nil
}

func writeCountedString(f *os.File, s string) {
	binary.Write(f, binary.BigEndian, uint32(len(s)))
	f.Write([]byte(s))
}

func writeCredential(f *os.File, client types.PrincipalName, clientRealm string, server types.PrincipalName, serverRealm string, key types.EncryptionKey, encPart messages.EncKDCRepPart, ticketBytes []byte) error {
	// Client principal
	writePrincipal(f, client, clientRealm)

	// Server principal
	writePrincipal(f, server, serverRealm)

	// Key: keytype (2 bytes), etype (2 bytes), keylen (2 bytes), keydata
	binary.Write(f, binary.BigEndian, uint16(key.KeyType))
	binary.Write(f, binary.BigEndian, uint16(0)) // etype field (always 0 in ccache v4)
	binary.Write(f, binary.BigEndian, uint16(len(key.KeyValue)))
	f.Write(key.KeyValue)

	// Times
	writeTime(f, encPart.AuthTime)
	writeTime(f, encPart.StartTime)
	writeTime(f, encPart.EndTime)
	writeTime(f, encPart.RenewTill)

	// Is_skey (0 = false)
	f.Write([]byte{0})

	// Ticket flags
	flagBytes := encPart.Flags.Bytes
	if len(flagBytes) < 4 {
		tmp := make([]byte, 4)
		copy(tmp[4-len(flagBytes):], flagBytes)
		flagBytes = tmp
	}
	binary.Write(f, binary.BigEndian, binary.BigEndian.Uint32(flagBytes))

	// Addresses (count = 0)
	binary.Write(f, binary.BigEndian, uint32(0))

	// Authdata (count = 0)
	binary.Write(f, binary.BigEndian, uint32(0))

	// Ticket
	binary.Write(f, binary.BigEndian, uint32(len(ticketBytes)))
	f.Write(ticketBytes)

	// Second ticket (empty)
	binary.Write(f, binary.BigEndian, uint32(0))

	return nil
}

func writeTime(f *os.File, t time.Time) {
	if t.IsZero() {
		binary.Write(f, binary.BigEndian, uint32(0))
	} else {
		binary.Write(f, binary.BigEndian, uint32(t.Unix()))
	}
}
