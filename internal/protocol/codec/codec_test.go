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
