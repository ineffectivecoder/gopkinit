package ccache

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// CCache represents a parsed credential cache
type CCache struct {
	Version          uint16
	DefaultPrincipal Principal
	Credentials      []Credential
}

// Principal represents a Kerberos principal
type Principal struct {
	NameType   int32
	Realm      string
	Components []string
}

// Credential represents a cached credential
type Credential struct {
	Client      Principal
	Server      Principal
	Key         types.EncryptionKey
	AuthTime    time.Time
	StartTime   time.Time
	EndTime     time.Time
	RenewTill   time.Time
	IsSKey      bool
	TicketFlags uint32
	Ticket      []byte
}

// ReadCCache reads and parses a ccache file
func ReadCCache(path string) (*CCache, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read ccache file: %w", err)
	}

	return ParseCCache(data)
}

// ParseCCache parses ccache data
func ParseCCache(data []byte) (*CCache, error) {
	r := bytes.NewReader(data)
	cc := &CCache{}

	// Read file format version
	if err := binary.Read(r, binary.BigEndian, &cc.Version); err != nil {
		return nil, fmt.Errorf("failed to read version: %w", err)
	}

	if cc.Version != 0x0504 {
		return nil, fmt.Errorf("unsupported ccache version: 0x%04x (only version 4/0x0504 supported)", cc.Version)
	}

	// Read header length
	var headerLen uint16
	if err := binary.Read(r, binary.BigEndian, &headerLen); err != nil {
		return nil, fmt.Errorf("failed to read header length: %w", err)
	}

	// Skip header tags
	if headerLen > 0 {
		if _, err := r.Seek(int64(headerLen), io.SeekCurrent); err != nil {
			return nil, fmt.Errorf("failed to skip header: %w", err)
		}
	}

	// Read default principal
	defaultPrinc, err := readPrincipal(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read default principal: %w", err)
	}
	cc.DefaultPrincipal = defaultPrinc

	// Read credentials until EOF
	for {
		cred, err := readCredential(r)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("failed to read credential: %w", err)
		}
		cc.Credentials = append(cc.Credentials, cred)
	}

	return cc, nil
}

func readPrincipal(r io.Reader) (Principal, error) {
	var p Principal

	// Name type
	var nameType uint32
	if err := binary.Read(r, binary.BigEndian, &nameType); err != nil {
		return p, err
	}
	p.NameType = int32(nameType)

	// Number of components
	var numComponents uint32
	if err := binary.Read(r, binary.BigEndian, &numComponents); err != nil {
		return p, err
	}

	// Realm
	realm, err := readCountedString(r)
	if err != nil {
		return p, err
	}
	p.Realm = realm

	// Components
	for i := uint32(0); i < numComponents; i++ {
		comp, err := readCountedString(r)
		if err != nil {
			return p, err
		}
		p.Components = append(p.Components, comp)
	}

	return p, nil
}

func readCountedString(r io.Reader) (string, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return "", err
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}

	return string(buf), nil
}

func readCredential(r io.Reader) (Credential, error) {
	var cred Credential

	// Client principal
	client, err := readPrincipal(r)
	if err != nil {
		return cred, err
	}
	cred.Client = client

	// Server principal
	server, err := readPrincipal(r)
	if err != nil {
		return cred, err
	}
	cred.Server = server

	// Key: keytype (2), etype (2), keylen (2), keydata
	var keyType, etype, keyLen uint16
	if err := binary.Read(r, binary.BigEndian, &keyType); err != nil {
		return cred, err
	}
	if err := binary.Read(r, binary.BigEndian, &etype); err != nil {
		return cred, err
	}
	if err := binary.Read(r, binary.BigEndian, &keyLen); err != nil {
		return cred, err
	}

	keyData := make([]byte, keyLen)
	if _, err := io.ReadFull(r, keyData); err != nil {
		return cred, err
	}

	cred.Key = types.EncryptionKey{
		KeyType:  int32(keyType),
		KeyValue: keyData,
	}

	// Times
	authTime, err := readTime(r)
	if err != nil {
		return cred, err
	}
	cred.AuthTime = authTime

	startTime, err := readTime(r)
	if err != nil {
		return cred, err
	}
	cred.StartTime = startTime

	endTime, err := readTime(r)
	if err != nil {
		return cred, err
	}
	cred.EndTime = endTime

	renewTill, err := readTime(r)
	if err != nil {
		return cred, err
	}
	cred.RenewTill = renewTill

	// Is_skey
	var isSKey byte
	if err := binary.Read(r, binary.BigEndian, &isSKey); err != nil {
		return cred, err
	}
	cred.IsSKey = isSKey != 0

	// Ticket flags
	if err := binary.Read(r, binary.BigEndian, &cred.TicketFlags); err != nil {
		return cred, err
	}

	// Addresses (count)
	var numAddresses uint32
	if err := binary.Read(r, binary.BigEndian, &numAddresses); err != nil {
		return cred, err
	}

	// Skip addresses
	for i := uint32(0); i < numAddresses; i++ {
		var addrType uint16
		if err := binary.Read(r, binary.BigEndian, &addrType); err != nil {
			return cred, err
		}
		addrData, err := readCountedOctetString(r)
		if err != nil {
			return cred, err
		}
		_ = addrData
	}

	// Authdata (count)
	var numAuthData uint32
	if err := binary.Read(r, binary.BigEndian, &numAuthData); err != nil {
		return cred, err
	}

	// Skip authdata
	for i := uint32(0); i < numAuthData; i++ {
		var authType uint16
		if err := binary.Read(r, binary.BigEndian, &authType); err != nil {
			return cred, err
		}
		authData, err := readCountedOctetString(r)
		if err != nil {
			return cred, err
		}
		_ = authData
	}

	// Ticket
	ticketData, err := readCountedOctetString(r)
	if err != nil {
		return cred, err
	}
	cred.Ticket = ticketData

	// Second ticket (usually empty)
	_, err = readCountedOctetString(r)
	if err != nil {
		return cred, err
	}

	return cred, nil
}

func readCountedOctetString(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}

	if length == 0 {
		return nil, nil
	}

	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}

	return buf, nil
}

func readTime(r io.Reader) (time.Time, error) {
	var timestamp uint32
	if err := binary.Read(r, binary.BigEndian, &timestamp); err != nil {
		return time.Time{}, err
	}

	if timestamp == 0 {
		return time.Time{}, nil
	}

	return time.Unix(int64(timestamp), 0), nil
}

// GetTGT returns the TGT from the ccache
func (cc *CCache) GetTGT() (*Credential, error) {
	realm := cc.DefaultPrincipal.Realm
	krbtgtName := "krbtgt/" + realm

	for i := range cc.Credentials {
		cred := &cc.Credentials[i]
		if len(cred.Server.Components) == 2 &&
			cred.Server.Components[0] == "krbtgt" &&
			cred.Server.Components[1] == realm {
			return cred, nil
		}
		// Also check single component
		if len(cred.Server.Components) == 1 &&
			cred.Server.Components[0] == krbtgtName {
			return cred, nil
		}
	}

	return nil, fmt.Errorf("TGT not found in ccache")
}

// ToTicket converts credential ticket bytes to gokrb5 Ticket
func (c *Credential) ToTicket() (messages.Ticket, error) {
	var ticket messages.Ticket
	if err := ticket.Unmarshal(c.Ticket); err != nil {
		return ticket, fmt.Errorf("failed to unmarshal ticket: %w", err)
	}
	return ticket, nil
}

// ToPrincipalName converts Principal to gokrb5 PrincipalName
func (p *Principal) ToPrincipalName() types.PrincipalName {
	return types.PrincipalName{
		NameType:   p.NameType,
		NameString: p.Components,
	}
}
