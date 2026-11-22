package codec

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"iplink/internal/protocol/frame"
	"iplink/pkg/protocol"
)

// EncodeJSON marshals v into a Frame with the given MessageType, RequestID, and SessionID.
func EncodeJSON(msgType protocol.MessageType, reqID, sessionID uint64, v any) (frame.Frame, error) {
	payload, err := json.Marshal(v)
	if err != nil {
		return frame.Frame{}, fmt.Errorf("marshal %d: %w", msgType, err)
	}
	return frame.Frame{
		Header: protocol.MessageHeader{
			Version:   protocol.ProtocolVersion,
			Type:      msgType,
			Flags:     protocol.FlagNone,
			Length:    uint32(len(payload)),
			RequestID: reqID,
			SessionID: sessionID,
		},
		Payload: payload,
	}, nil
}

// DecodeJSON unmarshals a Frame's JSON payload into target.
func DecodeJSON(f frame.Frame, target any) error {
	if err := json.Unmarshal(f.Payload, target); err != nil {
		return fmt.Errorf("unmarshal type %d: %w", f.Header.Type, err)
	}
	return nil
}

// EncodeTunnelData packs a binary TunnelData frame: [8-byte big-endian ConnID][raw data].
func EncodeTunnelData(reqID, sessionID, connID uint64, data []byte) frame.Frame {
	payload := make([]byte, 8+len(data))
	binary.BigEndian.PutUint64(payload[0:8], connID)
	copy(payload[8:], data)
	return frame.Frame{
		Header: protocol.MessageHeader{
			Version:   protocol.ProtocolVersion,
			Type:      protocol.MsgTunnelData,
			Flags:     protocol.FlagNone,
			Length:    uint32(len(payload)),
			RequestID: reqID,
			SessionID: sessionID,
		},
		Payload: payload,
	}
}

// TunnelDataFrame builds a MsgTunnelData frame that references data directly,
// avoiding the extra copy in EncodeTunnelData. The caller must lay out data as
// [8-byte big-endian ConnID][payload] and must not mutate it until the frame
// has been written (both Session.SendFrame and Client.sendFrame write synchronously).
func TunnelDataFrame(reqID, sessionID uint64, data []byte) frame.Frame {
	return frame.Frame{
		Header: protocol.MessageHeader{
			Version:   protocol.ProtocolVersion,
			Type:      protocol.MsgTunnelData,
			Flags:     protocol.FlagNone,
			Length:    uint32(len(data)),
			RequestID: reqID,
			SessionID: sessionID,
		},
		Payload: data,
	}
}

// EncodeTunnelDataPrefix writes an 8-byte big-endian ConnID at the head of a
// reusable buffer, so the payload can be framed without an allocation.
func EncodeTunnelDataPrefix(dst []byte, connID uint64) {
	binary.BigEndian.PutUint64(dst[:8], connID)
}

// DecodeTunnelData unpacks a binary TunnelData frame into ConnID and raw data slice.
func DecodeTunnelData(payload []byte) (uint64, []byte, error) {
	if len(payload) < 8 {
		return 0, nil, fmt.Errorf("short tunnel data frame: %d bytes", len(payload))
	}
	connID := binary.BigEndian.Uint64(payload[0:8])
	return connID, payload[8:], nil
}
