package metrics

import "sync/atomic"

// Metrics tracks runtime counters for IPLink server and client operations.
type Metrics struct {
	OnlineClients    atomic.Int64
	ActiveSessions   atomic.Int64
	ActiveTunnels    atomic.Int64
	P2PAttempts      atomic.Int64
	P2PSuccesses     atomic.Int64
	RelayConnections atomic.Int64
	BytesSent        atomic.Uint64
	BytesReceived    atomic.Uint64
}

// Snapshot is a point-in-time copy of Metrics values.
type Snapshot struct {
	OnlineClients    int64   `json:"online_clients"`
	ActiveSessions   int64   `json:"active_sessions"`
	ActiveTunnels    int64   `json:"active_tunnels"`
	P2PAttempts      int64   `json:"p2p_attempts"`
	P2PSuccesses     int64   `json:"p2p_successes"`
	P2PSuccessRate   float64 `json:"p2p_success_rate"`
	RelayConnections int64   `json:"relay_connections"`
	BytesSent        uint64  `json:"bytes_sent"`
	BytesReceived    uint64  `json:"bytes_received"`
}

// Snapshot returns a consistent point-in-time snapshot of all counters.
func (m *Metrics) Snapshot() Snapshot {
	attempts := m.P2PAttempts.Load()
	successes := m.P2PSuccesses.Load()
	var rate float64
	if attempts > 0 {
		rate = float64(successes) / float64(attempts)
	}
	return Snapshot{
		OnlineClients:    m.OnlineClients.Load(),
		ActiveSessions:   m.ActiveSessions.Load(),
		ActiveTunnels:    m.ActiveTunnels.Load(),
		P2PAttempts:      attempts,
		P2PSuccesses:     successes,
		P2PSuccessRate:   rate,
		RelayConnections: m.RelayConnections.Load(),
		BytesSent:        m.BytesSent.Load(),
		BytesReceived:    m.BytesReceived.Load(),
	}
}
