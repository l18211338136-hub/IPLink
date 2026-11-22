package codec

import (
	"bytes"
	"testing"

	"iplink/internal/protocol/message"
	"iplink/pkg/protocol"
)

func TestEncodeDecodeJSON(t *testing.T) {
	in := message.TunnelCreate{
		Name:       "web",
		Protocol:   "tcp",
		LocalAddr:  "127.0.0.1:8080",
		RemoteAddr: "0.0.0.0:18080",
	}
	f, err := EncodeJSON(protocol.MsgTunnelCreate, 7, 11, in)
	if err != nil {
		t.Fatalf("EncodeJSON: %v", err)
	}
	var out message.TunnelCreate
	if err := DecodeJSON(f, &out); err != nil {
		t.Fatalf("DecodeJSON: %v", err)
	}
	if out != in {
		t.Fatalf("got %+v, want %+v", out, in)
	}
}

func TestEncodeDecodeTunnelData(t *testing.T) {
	payload := []byte("hello iplink")
	f := EncodeTunnelData(1, 2, 123456789, payload)
	connID, got, err := DecodeTunnelData(f.Payload)
	if err != nil {
		t.Fatalf("DecodeTunnelData: %v", err)
	}
	if connID != 123456789 {
		t.Fatalf("connID = %d, want 123456789", connID)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
}

// TunnelDataFrame must produce a byte-identical frame to EncodeTunnelData,
// but reference the caller's buffer instead of copying it.
func TestTunnelDataFrameZeroCopy(t *testing.T) {
	payload := []byte("zero copy payload")
	buf := make([]byte, 8+len(payload))
	EncodeTunnelDataPrefix(buf, 42)
	copy(buf[8:], payload)

	f := TunnelDataFrame(3, 9, buf)
	ref := EncodeTunnelData(3, 9, 42, payload)

	if !bytes.Equal(f.Payload, ref.Payload) {
		t.Fatalf("payload mismatch: got %x, want %x", f.Payload, ref.Payload)
	}
	if f.Header.Type != ref.Header.Type || f.Header.Length != ref.Header.Length ||
		f.Header.SessionID != 9 || f.Header.RequestID != 3 {
		t.Fatalf("header mismatch: got %+v, want %+v", f.Header, ref.Header)
	}
	// The frame must reference the original buffer, not a copy.
	f.Payload[8] = 'X'
	if buf[8] != 'X' {
		t.Fatal("TunnelDataFrame copied the buffer instead of referencing it")
	}
	connID, got, err := DecodeTunnelData(f.Payload)
	if err != nil || connID != 42 {
		t.Fatalf("DecodeTunnelData: connID=%d err=%v", connID, err)
	}
	if string(got) != "Xero copy payload" {
		t.Fatalf("unexpected payload after mutation: %q", got)
	}
}
