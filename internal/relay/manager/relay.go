package manager

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"iplink/internal/metrics"
	"iplink/pkg/protocol"
)

var (
	ErrRelayDisabled   = errors.New("relay: service is disabled")
	ErrRelayFull       = errors.New("relay: maximum relay sessions reached")
	ErrSessionNotFound = errors.New("relay: session not found")
)

const relaySessionIdleTimeout = 2 * time.Minute

// RelayPacketHeader: [16-byte ASCII/zero-padded sessionID][payload]
const relayHeaderLen = 16

type relaySession struct {
	id         string
	peerA      net.Addr
	peerB      net.Addr
	lastActive time.Time
}

// Manager handles UDP relay session allocation, packet forwarding, and idle cleanup.
type Manager struct {
	enabled     bool
	maxSessions int
	conn        net.PacketConn
	metrics     *metrics.Metrics
	log         *slog.Logger

	mu       sync.RWMutex
	sessions map[string]*relaySession
	nextID   uint64
}

// Start starts the UDP relay listener on addr if enabled.
func Start(ctx context.Context, addr string, enabled bool, maxSessions int, m *metrics.Metrics, log *slog.Logger) (*Manager, error) {
	mgr := &Manager{
		enabled:     enabled,
		maxSessions: maxSessions,
		metrics:     m,
		log:         log,
		sessions:    make(map[string]*relaySession),
	}
	if !enabled {
		return mgr, nil
	}
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen relay UDP %s: %w", addr, err)
	}
	mgr.conn = pc
	go mgr.serve(ctx)
	go mgr.reapIdle(ctx)
	return mgr, nil
}

// Allocate creates a new relay session ID if capacity allows.
func (m *Manager) Allocate() (string, error) {
	if !m.enabled {
		return "", ErrRelayDisabled
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.maxSessions > 0 && len(m.sessions) >= m.maxSessions {
		return "", ErrRelayFull
	}
	m.nextID++
	id := fmt.Sprintf("rly-%012x", m.nextID)
	m.sessions[id] = &relaySession{
		id:         id,
		lastActive: time.Now(),
	}
	m.metrics.RelayConnections.Store(int64(len(m.sessions)))
	return id, nil
}

// Release removes a relay session.
func (m *Manager) Release(id string) {
	m.mu.Lock()
	delete(m.sessions, id)
	m.metrics.RelayConnections.Store(int64(len(m.sessions)))
	m.mu.Unlock()
}

// Addr returns the bound UDP relay address.
func (m *Manager) Addr() string {
	if m.conn == nil {
		return ""
	}
	return m.conn.LocalAddr().String()
}

// Close shuts down the relay listener.
func (m *Manager) Close() error {
	if m.conn != nil {
		return m.conn.Close()
	}
	return nil
}

// EncodeRelayPacket prefixes payload with a 16-byte padded relay session ID.
func EncodeRelayPacket(sessionID string, payload []byte) []byte {
	pkt := make([]byte, relayHeaderLen+len(payload))
	copy(pkt[:relayHeaderLen], sessionID)
	copy(pkt[relayHeaderLen:], payload)
	return pkt
}

func (m *Manager) serve(ctx context.Context) {
	defer m.conn.Close()
	go func() {
		<-ctx.Done()
		_ = m.conn.Close()
	}()

	buf := make([]byte, protocol.MaxUDPPacketSize)
	for {
		n, srcAddr, err := m.conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			m.log.Debug("relay read error", "err", err)
			continue
		}
		if n <= relayHeaderLen {
			continue
		}
		sid := trimZeroRight(buf[:relayHeaderLen])
		payload := buf[relayHeaderLen:n]

		dst := m.bindAndLookupPeer(sid, srcAddr)
		if dst == nil {
			continue
		}
		if _, err := m.conn.WriteTo(buf[:n], dst); err == nil {
			m.metrics.BytesSent.Add(uint64(len(payload)))
			m.metrics.BytesReceived.Add(uint64(len(payload)))
		}
	}
}

func (m *Manager) bindAndLookupPeer(sid string, src net.Addr) net.Addr {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.sessions[sid]
	if !ok {
		return nil
	}
	sess.lastActive = time.Now()
	srcStr := src.String()
	if sess.peerA == nil {
		sess.peerA = src
		return nil
	}
	if sess.peerA.String() == srcStr {
		return sess.peerB
	}
	if sess.peerB == nil {
		sess.peerB = src
		return sess.peerA
	}
	if sess.peerB.String() == srcStr {
		return sess.peerA
	}
	return nil
}

func (m *Manager) reapIdle(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-relaySessionIdleTimeout)
			m.mu.Lock()
			for id, s := range m.sessions {
				if s.lastActive.Before(cutoff) {
					delete(m.sessions, id)
				}
			}
			m.metrics.RelayConnections.Store(int64(len(m.sessions)))
			m.mu.Unlock()
		}
	}
}

func trimZeroRight(b []byte) string {
	end := len(b)
	for end > 0 && b[end-1] == 0 {
		end--
	}
	return string(b[:end])
}
