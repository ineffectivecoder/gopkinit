package krb

import (
	"context"
	"encoding/asn1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/jcmturner/gokrb5/v8/messages"
	"golang.org/x/net/proxy"
)

// KDCClient handles communication with the KDC
type KDCClient struct {
	Address   string
	Port      int
	Timeout   time.Duration
	ProxyAddr string // SOCKS proxy address (e.g., "127.0.0.1:1080")
}

// NewKDCClient creates a new KDC client
func NewKDCClient(address string) *KDCClient {
	return &KDCClient{
		Address: address,
		Port:    88,
		Timeout: 30 * time.Second,
	}
}

// SetProxy configures SOCKS5 proxy for KDC connections
func (c *KDCClient) SetProxy(proxyAddr string) {
	c.ProxyAddr = proxyAddr
}

// SendASReq sends an AS-REQ to the KDC and returns the AS-REP
func (c *KDCClient) SendASReq(req []byte) ([]byte, error) {
	// Try UDP first if request is small enough (< 1400 bytes)
	if len(req) < 1400 {
		resp, err := c.sendUDP(req)
		if err == nil {
			return resp, nil
		}
		// If UDP fails, fall back to TCP
	}

	// Connect to KDC via TCP (with optional SOCKS proxy)
	addr := fmt.Sprintf("%s:%d", c.Address, c.Port)
	var conn net.Conn
	var err error
	if c.ProxyAddr != "" {
		// Use SOCKS5 proxy
		var dialer proxy.Dialer
		dialer, err = proxy.SOCKS5("tcp", c.ProxyAddr, nil, proxy.Direct)
		if err != nil {
			return nil, fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), c.Timeout)
		defer cancel()
		conn, err = dialer.(proxy.ContextDialer).DialContext(ctx, "tcp", addr)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to KDC via proxy: %w", err)
		}
	} else {
		// Direct connection
		conn, err = net.DialTimeout("tcp", addr, c.Timeout)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to KDC: %w", err)
		}
	}
	defer conn.Close()

	// Set read/write deadlines
	conn.SetDeadline(time.Now().Add(c.Timeout))

	// Kerberos TCP messages are prefixed with 4-byte length (big-endian)
	reqLen := make([]byte, 4)
	binary.BigEndian.PutUint32(reqLen, uint32(len(req)))

	// Concatenate length prefix + request and send in one write
	// (AD KDC may be sensitive to fragmentation)
	fullReq := append(reqLen, req...)
	if _, err := conn.Write(fullReq); err != nil {
		return nil, fmt.Errorf("failed to write request: %w", err)
	}

	// Read response length
	respLen := make([]byte, 4)
	n, err := io.ReadFull(conn, respLen)
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("KDC closed connection without responding (sent %d bytes)", n)
		}
		return nil, fmt.Errorf("failed to read response length: %w", err)
	}

	length := binary.BigEndian.Uint32(respLen)
	if length > 1024*1024 { // Sanity check: 1MB max
		return nil, fmt.Errorf("response too large: %d bytes", length)
	}

	// Read response
	resp := make([]byte, length)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	return resp, nil
}

// sendUDP sends an AS-REQ via UDP
func (c *KDCClient) sendUDP(req []byte) ([]byte, error) {
	addr := fmt.Sprintf("%s:%d", c.Address, c.Port)
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve UDP address: %w", err)
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial UDP: %w", err)
	}
	defer conn.Close()

	// Set deadline
	conn.SetDeadline(time.Now().Add(c.Timeout))

	// Send request (no length prefix for UDP)
	if _, err := conn.Write(req); err != nil {
		return nil, fmt.Errorf("failed to write UDP request: %w", err)
	}

	// Read response
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read UDP response: %w", err)
	}

	return buf[:n], nil
}

// ParseASRep parses an AS-REP or KRB-ERROR from raw bytes
func ParseASRep(data []byte) (*messages.ASRep, error) {
	var asRep messages.ASRep
	err := asRep.Unmarshal(data)
	if err != nil {
		// Try to parse as KRB-ERROR
		var krbErr messages.KRBError
		if err2 := krbErr.Unmarshal(data); err2 == nil {
			return nil, fmt.Errorf("KDC returned error: %s (code %d)", krbErr.EText, krbErr.ErrorCode)
		}
		return nil, fmt.Errorf("failed to parse AS-REP: %w", err)
	}

	return &asRep, nil
}

// RawASRep is a raw AS-REP structure for custom parsing
type RawASRep struct {
	PVNO    int           `asn1:"explicit,tag:0"`
	MsgType int           `asn1:"explicit,tag:1"`
	PAData  []RawPAData   `asn1:"optional,explicit,tag:2"`
	CRealm  string        `asn1:"generalstring,explicit,tag:3"`
	CName   asn1.RawValue `asn1:"explicit,tag:4"`
	Ticket  asn1.RawValue `asn1:"explicit,tag:5"`
	EncPart asn1.RawValue `asn1:"explicit,tag:6"`
}

// RawPAData represents raw padata
type RawPAData struct {
	PADataType  int32  `asn1:"explicit,tag:1"`
	PADataValue []byte `asn1:"explicit,tag:2"`
}

// ParseRawASRep parses AS-REP into a raw structure for custom processing
func ParseRawASRep(data []byte) (*RawASRep, error) {
	var asRep RawASRep
	_, err := asn1.Unmarshal(data, &asRep)
	if err != nil {
		return nil, fmt.Errorf("failed to parse raw AS-REP: %w", err)
	}

	return &asRep, nil
}
