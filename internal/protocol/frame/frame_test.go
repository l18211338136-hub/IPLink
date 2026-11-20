package frame

import (
	"bytes"
	"errors"
	"testing"

	"iplink/pkg/protocol"
)

type chunkedReader struct {
	data      []byte
	chunkSize int
}

func (c *chunkedReader) Read(p []byte) (int, error) {
	if len(c.data) == 0 {
		return 0, errors.New("EOF")
	}
	n := c.chunkSize
	if n > len(c.data) {
		n = len(c.data)
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, c.data[:n])
	c.data = c.data[n:]
	return n, nil
}

func TestWriteAndReadFramePartialReads(t *testing.T) {
	var buf bytes.Buffer
	want := Frame{
		Header: protocol.MessageHeader{
			Type:      protocol.MsgHeartbeatPing,
			Flags:     protocol.FlagNone,
			RequestID: 42,
			SessionID: 99,
		},
		Payload: []byte(`{"sent_at":123456}`),
	}
	if err := WriteFrame(&buf, want); err != nil {
		t.Fatalf("WriteFrame failed: %v", err)
	}

	// Simulate fragmented TCP reads (3 bytes at a time).
	r := &chunkedReader{data: buf.Bytes(), chunkSize: 3}
	got, err := ReadFrame(r)
	if err != nil {
		t.Fatalf("ReadFrame failed: %v", err)
	}
	if got.Header.Version != protocol.ProtocolVersion {
		t.Fatalf("version = %d, want %d", got.Header.Version, protocol.ProtocolVersion)
	}
	if got.Header.Type != want.Header.Type || got.Header.RequestID != 42 || got.Header.SessionID != 99 {
		t.Fatalf("unexpected header: %+v", got.Header)
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("payload = %q, want %q", got.Payload, want.Payload)
	}
}

func TestReadFrameRejectsOversizedPayload(t *testing.T) {
	hdr := MarshalHeader(protocol.MessageHeader{
		Version: protocol.ProtocolVersion,
		Type:    protocol.MsgTunnelData,
		Length:  protocol.MaxFramePayloadSize + 1,
	})
	_, err := ReadFrame(bytes.NewReader(hdr[:]))
	if !errors.Is(err, protocol.ErrFrameTooLarge) {
		t.Fatalf("expected ErrFrameTooLarge, got %v", err)
	}
}
