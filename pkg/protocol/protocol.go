package protocol

import "errors"

// ProtocolVersion is the current wire protocol version, independent of software version.
// v2: UDP datagrams (NAT discovery, P2P punching, peer channels, relay payloads)
// are encrypted with AES-256-GCM keyed from the shared token.
// v3: relay sessions use random IDs and a per-session HMAC token; v2 peers are
// incompatible at the relay data plane and must be upgraded together.
const ProtocolVersion uint16 = 3

// HeaderSize is the fixed byte length of MessageHeader on the wire.
const HeaderSize = 26

// MaxFramePayloadSize caps a single frame payload to 1 MiB to prevent memory exhaustion.
const MaxFramePayloadSize uint32 = 1 << 20

// MaxUDPPacketSize caps UDP tunnel/NAT datagrams to a safe MTU-friendly limit.
const MaxUDPPacketSize = 64 * 1024

// MessageType identifies the control or data message kind.
type MessageType uint16

const (
	MsgAuthChallenge MessageType = 0x0001
	MsgAuthRequest   MessageType = 0x0002
	MsgAuthResponse  MessageType = 0x0003

	MsgHeartbeatPing MessageType = 0x0010
	MsgHeartbeatPong MessageType = 0x0011

	MsgTunnelCreate      MessageType = 0x0020
	MsgTunnelCreateAck   MessageType = 0x0021
	MsgTunnelOpenConn    MessageType = 0x0022
	MsgTunnelOpenConnAck MessageType = 0x0023
	MsgTunnelData        MessageType = 0x0024
	MsgTunnelClose       MessageType = 0x0025
	MsgUDPDatagram       MessageType = 0x0026

	// 0x0030 / 0x0031 reserved (old NAT-over-TCP probe, unused since v2).
	MsgPeerListReq     MessageType = 0x0032
	MsgPeerListResp    MessageType = 0x0033
	MsgPeerConnectReq  MessageType = 0x0034
	MsgPeerConnectInfo MessageType = 0x0035

	MsgRelayAllocReq    MessageType = 0x0040
	MsgRelayAllocAck    MessageType = 0x0041
	MsgRelayAllocNotify MessageType = 0x0042

	MsgInfoReq  MessageType = 0x0043
	MsgInfoResp MessageType = 0x0044

	MsgError MessageType = 0x00FF
)

// Frame flags.
const (
	FlagNone       uint16 = 0
	FlagCompressed uint16 = 1 << 0
)

// ErrorCode represents protocol-level error codes.
type ErrorCode uint16

const (
	ErrNone               ErrorCode = 0
	ErrInvalidFrame       ErrorCode = 1001
	ErrUnsupportedVersion ErrorCode = 1002
	ErrAuthFailed         ErrorCode = 2001
	ErrUnauthorized       ErrorCode = 2002
	ErrTunnelCreateFailed ErrorCode = 3001
	ErrTunnelNotFound     ErrorCode = 3002
	ErrTargetDenied       ErrorCode = 3003
	ErrPeerNotFound       ErrorCode = 4001
	ErrRelayUnavailable   ErrorCode = 5001
	ErrInternal           ErrorCode = 9000
)

var (
	ErrFrameTooLarge    = errors.New("protocol: frame payload exceeds maximum allowed size")
	ErrUnsupportedProto = errors.New("protocol: unsupported protocol version")
)

// MessageHeader is the 26-byte big-endian header preceding every TCP frame payload.
// Wire layout:
//
//	[0:2]   Version   (uint16)
//	[2:4]   Type      (uint16)
//	[4:6]   Flags     (uint16)
//	[6:10]  Length    (uint32)
//	[10:18] RequestID (uint64)
//	[18:26] SessionID (uint64)
type MessageHeader struct {
	Version   uint16
	Type      MessageType
	Flags     uint16
	Length    uint32
	RequestID uint64
	SessionID uint64
}
