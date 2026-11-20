package metrics

import (
	"sort"
	"sync"
	"sync/atomic"
)

// TunnelStats is a point-in-time copy of a single tunnel's counters and metadata.
type TunnelStats struct {
	TunnelID      string `json:"tunnel_id"`
	Protocol      string `json:"protocol"`
	LocalAddr     string `json:"local_addr"`
	ActiveConns   int64  `json:"active_conns"`
	BytesSent     uint64 `json:"bytes_sent"`
	BytesReceived uint64 `json:"bytes_received"`
}

// TunnelCounters holds atomic counters plus immutable metadata for one tunnel.
type TunnelCounters struct {
	Protocol      string
	LocalAddr     string
	ActiveConns   atomic.Int64
	BytesSent     atomic.Uint64
	BytesReceived atomic.Uint64
}

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

	// Tunnel-level counters. Keyed by server-assigned tunnel ID.
	tunnelMu    sync.RWMutex
	tunnelStats map[string]*TunnelCounters
}

// RegisterTunnel creates the counter set for tunnelID with its metadata.
func (m *Metrics) RegisterTunnel(tunnelID, protocol, localAddr string) {
	m.tunnelMu.Lock()
	if m.tunnelStats == nil {
		m.tunnelStats = make(map[string]*TunnelCounters)
	}
	m.tunnelStats[tunnelID] = &TunnelCounters{Protocol: protocol, LocalAddr: localAddr}
	m.tunnelMu.Unlock()
}

// UnregisterTunnel removes the counter set for tunnelID.
func (m *Metrics) UnregisterTunnel(tunnelID string) {
	m.tunnelMu.Lock()
	delete(m.tunnelStats, tunnelID)
	m.tunnelMu.Unlock()
}

// Tunnel returns the counters for tunnelID, or nil if unknown.
func (m *Metrics) Tunnel(tunnelID string) *TunnelCounters {
	m.tunnelMu.RLock()
	tc := m.tunnelStats[tunnelID]
	m.tunnelMu.RUnlock()
	return tc
}

// Snapshot is a point-in-time copy of Metrics values.
type Snapshot struct {
	OnlineClients    int64         `json:"online_clients"`
	ActiveSessions   int64         `json:"active_sessions"`
	ActiveTunnels    int64         `json:"active_tunnels"`
	P2PAttempts      int64         `json:"p2p_attempts"`
	P2PSuccesses     int64         `json:"p2p_successes"`
	P2PSuccessRate   float64       `json:"p2p_success_rate"`
	RelayConnections int64         `json:"relay_connections"`
	BytesSent        uint64        `json:"bytes_sent"`
	BytesReceived    uint64        `json:"bytes_received"`
	Tunnels          []TunnelStats `json:"tunnels,omitempty"`
}

// Snapshot returns a consistent point-in-time snapshot of all counters.
func (m *Metrics) Snapshot() Snapshot {
	attempts := m.P2PAttempts.Load()
	successes := m.P2PSuccesses.Load()
	var rate float64
	if attempts > 0 {
		rate = float64(successes) / float64(attempts)
	}
	snap := Snapshot{
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
	m.tunnelMu.RLock()
	if len(m.tunnelStats) > 0 {
		snap.Tunnels = make([]TunnelStats, 0, len(m.tunnelStats))
		for id, tc := range m.tunnelStats {
			snap.Tunnels = append(snap.Tunnels, TunnelStats{
				TunnelID:      id,
				Protocol:      tc.Protocol,
				LocalAddr:     tc.LocalAddr,
				ActiveConns:   tc.ActiveConns.Load(),
				BytesSent:     tc.BytesSent.Load(),
				BytesReceived: tc.BytesReceived.Load(),
			})
		}
		sort.Slice(snap.Tunnels, func(i, j int) bool {
			return snap.Tunnels[i].TunnelID < snap.Tunnels[j].TunnelID
		})
	}
	m.tunnelMu.RUnlock()
	return snap
}
