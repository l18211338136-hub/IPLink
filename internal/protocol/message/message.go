package message

import (
	"iplink/internal/metrics"
	"iplink/pkg/protocol"
)

// AuthChallenge is sent by the server immediately upon TCP connection.
type AuthChallenge struct {
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
}

// AuthRequest is sent by the client with an HMAC-SHA256 signature of the challenge.
type AuthRequest struct {
	ClientID  string `json:"client_id"`
	Nonce     string `json:"nonce"`
	Timestamp int64  `json:"timestamp"`
	Signature string `json:"signature"`
	LocalAddr string `json:"local_addr,omitempty"`
}

// ServerCapabilities advertises which optional services the server actually bound.
// Ports come from the live listeners so dynamically assigned ports are reported correctly.
type ServerCapabilities struct {
	ProtocolVersion  uint16 `json:"protocol_version"`
	RelayEnabled     bool   `json:"relay_enabled"`
	RelayPort        int    `json:"relay_port,omitempty"`
	NATEnabled       bool   `json:"nat_enabled"`
	NATPort          int    `json:"nat_port,omitempty"`
	HTTPProxyEnabled bool   `json:"http_proxy_enabled"`
	HTTPProxyPort    int    `json:"http_proxy_port,omitempty"`
	MetricsEnabled   bool   `json:"metrics_enabled"`
	MetricsPort      int    `json:"metrics_port,omitempty"`
}

// ServerInfo is the response to an on-demand runtime query.
type ServerInfo struct {
	Capabilities ServerCapabilities `json:"capabilities"`
	Metrics      metrics.Snapshot   `json:"metrics"`
}

// AuthResponse acknowledges client authentication and assigns a numeric SessionID.
type AuthResponse struct {
	Success      bool               `json:"success"`
	SessionID    uint64             `json:"session_id"`
	ErrorCode    protocol.ErrorCode `json:"error_code,omitempty"`
	Message      string             `json:"message,omitempty"`
	Capabilities ServerCapabilities `json:"capabilities,omitempty"`
}

// HeartbeatPing / HeartbeatPong keep control sessions alive.
type HeartbeatPing struct {
	SentAt int64 `json:"sent_at"`
}

type HeartbeatPong struct {
	SentAt     int64 `json:"sent_at"`
	ReceivedAt int64 `json:"received_at"`
}

// TunnelCreate registers a TCP, UDP, or HTTP reverse-proxy tunnel on the server.
type TunnelCreate struct {
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	LocalAddr   string `json:"local_addr"`
	RemoteAddr  string `json:"remote_addr,omitempty"`
	HTTPPath    string `json:"http_path,omitempty"`
	StripPrefix bool   `json:"strip_prefix,omitempty"`
}

// TunnelCreateAck returns the server-assigned TunnelID and bound remote address.
type TunnelCreateAck struct {
	Success   bool               `json:"success"`
	TunnelID  string             `json:"tunnel_id,omitempty"`
	BoundAddr string             `json:"bound_addr,omitempty"`
	ErrorCode protocol.ErrorCode `json:"error_code,omitempty"`
	Error     string             `json:"error,omitempty"`
}

// TunnelOpenConn notifies the client that an external peer connected to a TCP tunnel.
type TunnelOpenConn struct {
	TunnelID   string `json:"tunnel_id"`
	ConnID     uint64 `json:"conn_id"`
	LocalAddr  string `json:"local_addr"`
	RemotePeer string `json:"remote_peer"`
}

// TunnelOpenConnAck reports whether the client successfully dialed the local target.
type TunnelOpenConnAck struct {
	ConnID  uint64 `json:"conn_id"`
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// TunnelClose signals EOF or error teardown for a multiplexed TCP connection.
type TunnelClose struct {
	ConnID uint64 `json:"conn_id"`
	Reason string `json:"reason,omitempty"`
}

// UDPDatagram carries a UDP packet for a registered UDP tunnel.
type UDPDatagram struct {
	TunnelID   string `json:"tunnel_id"`
	PeerAddr   string `json:"peer_addr"`
	PayloadB64 string `json:"payload_b64"`
}

// NATProbe is sent over UDP to the server NAT port to discover public IP:port.
type NATProbe struct {
	ClientID string `json:"client_id"`
	Nonce    string `json:"nonce"`
}

// NATProbeAck reflects the observed public IP:port back to the client.
type NATProbeAck struct {
	PublicAddr string `json:"public_addr"`
	Nonce      string `json:"nonce"`
}

// PeerInfo describes an online peer client for P2P or Relay coordination.
type PeerInfo struct {
	ClientID   string `json:"client_id"`
	SessionID  uint64 `json:"session_id"`
	PublicAddr string `json:"public_addr,omitempty"`
	LocalAddr  string `json:"local_addr,omitempty"`
}

// PeerListReq / PeerListResp query connected peers.
type PeerListReq struct{}

type PeerListResp struct {
	Peers []PeerInfo `json:"peers"`
}

// PeerConnectReq asks the server to coordinate a P2P connection to TargetClientID.
type PeerConnectReq struct {
	TargetClientID string `json:"target_client_id"`
	MyPublicAddr   string `json:"my_public_addr,omitempty"`
	MyLocalAddr    string `json:"my_local_addr,omitempty"`
}

// PeerConnectInfo is delivered to both peers with each other's endpoint candidates.
type PeerConnectInfo struct {
	PeerID         string `json:"peer_id"`
	PeerPublicAddr string `json:"peer_public_addr,omitempty"`
	PeerLocalAddr  string `json:"peer_local_addr,omitempty"`
	PunchToken     string `json:"punch_token"`
}

// RelayAllocReq asks the server to allocate a relay session between two clients.
type RelayAllocReq struct {
	TargetClientID string `json:"target_client_id"`
}

// RelayAllocAck returns the allocated relay session ID and server relay endpoint.
type RelayAllocAck struct {
	Success        bool               `json:"success"`
	RelaySessionID string             `json:"relay_session_id,omitempty"`
	RelayAddr      string             `json:"relay_addr,omitempty"`
	ErrorCode      protocol.ErrorCode `json:"error_code,omitempty"`
	Error          string             `json:"error,omitempty"`
}

// RelayAllocNotify tells the target client that a peer opened a relay session.
type RelayAllocNotify struct {
	FromClientID   string `json:"from_client_id"`
	RelaySessionID string `json:"relay_session_id"`
	RelayAddr      string `json:"relay_addr"`
}

// ErrorMsg conveys a protocol-level error.
type ErrorMsg struct {
	Code    protocol.ErrorCode `json:"code"`
	Message string             `json:"message"`
}
