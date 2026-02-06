package krb

import (
	"testing"
)

// TestNewKDCClient verifies default client construction.
func TestNewKDCClient(t *testing.T) {
	client := NewKDCClient("10.0.0.1")

	if client.Address != "10.0.0.1" {
		t.Errorf("Address = %q, want %q", client.Address, "10.0.0.1")
	}

	if client.Port != 88 {
		t.Errorf("Port = %d, want 88", client.Port)
	}

	if client.Timeout != 30*1e9 { // 30 seconds in nanoseconds
		t.Errorf("Timeout = %v, want 30s", client.Timeout)
	}

	if client.ProxyAddr != "" {
		t.Errorf("ProxyAddr = %q, want empty", client.ProxyAddr)
	}
}

// TestSetProxy verifies proxy configuration.
func TestSetProxy(t *testing.T) {
	client := NewKDCClient("kdc.test.com")
	client.SetProxy("127.0.0.1:1080")

	if client.ProxyAddr != "127.0.0.1:1080" {
		t.Errorf("ProxyAddr = %q, want %q", client.ProxyAddr, "127.0.0.1:1080")
	}
}

// TestParseASRepInvalidData tests error handling for garbage data.
func TestParseASRepInvalidData(t *testing.T) {
	_, err := ParseASRep([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Fatal("ParseASRep() should fail on invalid data")
	}
}

// TestParseRawASRepInvalidData tests error handling for garbage data.
func TestParseRawASRepInvalidData(t *testing.T) {
	_, err := ParseRawASRep([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Fatal("ParseRawASRep() should fail on invalid data")
	}
}

// TestParseTGSRepInvalidData tests error handling for garbage data.
func TestParseTGSRepInvalidData(t *testing.T) {
	_, err := ParseTGSRep([]byte{0x00, 0x01, 0x02})
	if err == nil {
		t.Fatal("ParseTGSRep() should fail on invalid data")
	}
}

// TestRawASRepFieldTypes verifies the RawASRep struct can be used correctly.
func TestRawASRepFieldTypes(t *testing.T) {
	raw := RawASRep{
		PVNO:    5,
		MsgType: 11,
		CRealm:  "TEST.COM",
	}

	if raw.PVNO != 5 {
		t.Errorf("PVNO = %d, want 5", raw.PVNO)
	}
	if raw.MsgType != 11 {
		t.Errorf("MsgType = %d, want 11", raw.MsgType)
	}
	if raw.CRealm != "TEST.COM" {
		t.Errorf("CRealm = %q, want %q", raw.CRealm, "TEST.COM")
	}
}

// TestSendASReqConnectionRefused tests error handling when KDC is unreachable.
func TestSendASReqConnectionRefused(t *testing.T) {
	client := NewKDCClient("127.0.0.1")
	client.Port = 1 // unlikely to have a service on port 1

	_, err := client.SendASReq([]byte{0x6a, 0x03, 0x02, 0x01, 0x05})
	if err == nil {
		t.Fatal("SendASReq() should fail when KDC is unreachable")
	}
}

// TestSendTGSReqUsesASReqTransport verifies TGS-REQ uses same transport.
func TestSendTGSReqConnectionRefused(t *testing.T) {
	client := NewKDCClient("127.0.0.1")
	client.Port = 1

	_, err := client.SendTGSReq([]byte{0x6c, 0x03, 0x02, 0x01, 0x05})
	if err == nil {
		t.Fatal("SendTGSReq() should fail when KDC is unreachable")
	}
}
