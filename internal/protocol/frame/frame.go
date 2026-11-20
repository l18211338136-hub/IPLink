package frame

import (
	"encoding/binary"
	"fmt"
	"io"

	"iplink/pkg/protocol"
)

// Frame pairs a validated MessageHeader with its raw payload bytes.
type Frame struct {
	Header  protocol.MessageHeader
	Payload []byte
}

// MarshalHeader encodes a MessageHeader into a 26-byte big-endian slice.
func MarshalHeader(h protocol.MessageHeader) [protocol.HeaderSize]byte {
	var buf [protocol.HeaderSize]byte
	binary.BigEndian.PutUint16(buf[0:2], h.Version)
	binary.BigEndian.PutUint16(buf[2:4], uint16(h.Type))
	binary.BigEndian.PutUint16(buf[4:6], h.Flags)
	binary.BigEndian.PutUint32(buf[6:10], h.Length)
	binary.BigEndian.PutUint64(buf[10:18], h.RequestID)
	binary.BigEndian.PutUint64(buf[18:26], h.SessionID)
	return buf
}

// UnmarshalHeader decodes a 26-byte big-endian slice into a MessageHeader.
func UnmarshalHeader(buf []byte) (protocol.MessageHeader, error) {
	if len(buf) < protocol.HeaderSize {
		return protocol.MessageHeader{}, fmt.Errorf("short header: got %d bytes, want %d", len(buf), protocol.HeaderSize)
	}
	return protocol.MessageHeader{
		Version:   binary.BigEndian.Uint16(buf[0:2]),
		Type:      protocol.MessageType(binary.BigEndian.Uint16(buf[2:4])),
		Flags:     binary.BigEndian.Uint16(buf[4:6]),
		Length:    binary.BigEndian.Uint32(buf[6:10]),
		RequestID: binary.BigEndian.Uint64(buf[10:18]),
		SessionID: binary.BigEndian.Uint64(buf[18:26]),
	}, nil
}

// ReadFrame reads a complete length-prefixed frame from r, handling partial reads.
func ReadFrame(r io.Reader) (Frame, error) {
	var hdrBuf [protocol.HeaderSize]byte
	if _, err := io.ReadFull(r, hdrBuf[:]); err != nil {
		return Frame{}, err
	}
	hdr, err := UnmarshalHeader(hdrBuf[:])
	if err != nil {
		return Frame{}, err
	}
	if hdr.Version != protocol.ProtocolVersion {
		return Frame{}, fmt.Errorf("%w: %d", protocol.ErrUnsupportedProto, hdr.Version)
	}
	if hdr.Length > protocol.MaxFramePayloadSize {
		return Frame{}, fmt.Errorf("%w: %d bytes", protocol.ErrFrameTooLarge, hdr.Length)
	}
	payload := make([]byte, hdr.Length)
	if hdr.Length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return Frame{}, err
		}
	}
	return Frame{Header: hdr, Payload: payload}, nil
}

// WriteFrame writes a complete header + payload frame to w.
func WriteFrame(w io.Writer, f Frame) error {
	if uint32(len(f.Payload)) > protocol.MaxFramePayloadSize {
		return fmt.Errorf("%w: %d bytes", protocol.ErrFrameTooLarge, len(f.Payload))
	}
	f.Header.Version = protocol.ProtocolVersion
	f.Header.Length = uint32(len(f.Payload))
	hdrBuf := MarshalHeader(f.Header)
	if err := writeAll(w, hdrBuf[:]); err != nil {
		return err
	}
	if len(f.Payload) > 0 {
		if err := writeAll(w, f.Payload); err != nil {
			return err
		}
	}
	return nil
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
