package session

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"iplink/internal/metrics"
	"iplink/internal/protocol/frame"
	"iplink/internal/protocol/message"
)

var ErrSessionClosed = errors.New("session: closed")

// Session represents an authenticated client control connection.
type Session struct {
	ID         uint64
	ClientID   string
	Conn       net.Conn
	LocalAddr  string
	PublicAddr string

	writeMu sync.Mutex
	mu      sync.Mutex
	closed  bool
	tunnels map[string]io.Closer

	lastHeartbeat atomic.Int64
}

// SendFrame writes a frame safely under writeMu with a write deadline.
func (s *Session) SendFrame(f frame.Frame) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return ErrSessionClosed
	}
	_ = s.Conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	err := frame.WriteFrame(s.Conn, f)
	_ = s.Conn.SetWriteDeadline(time.Time{})
	return err
}

// TouchHeartbeat updates the last seen heartbeat timestamp.
func (s *Session) TouchHeartbeat() {
	s.lastHeartbeat.Store(time.Now().UnixNano())
}

// LastHeartbeat returns the timestamp of the most recent heartbeat or creation.
func (s *Session) LastHeartbeat() time.Time {
	return time.Unix(0, s.lastHeartbeat.Load())
}

// RegisterTunnel attaches a closer (e.g., tunnel listener) to the session lifecycle.
func (s *Session) RegisterTunnel(tunnelID string, c io.Closer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		_ = c.Close()
		return
	}
	if s.tunnels == nil {
		s.tunnels = make(map[string]io.Closer)
	}
	s.tunnels[tunnelID] = c
}

// SetPublicAddr stores the client's observed public UDP address.
func (s *Session) SetPublicAddr(addr string) {
	s.mu.Lock()
	s.PublicAddr = addr
	s.mu.Unlock()
}

// Close closes the underlying connection and all registered tunnels.
func (s *Session) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	tunnels := s.tunnels
	s.tunnels = nil
	s.mu.Unlock()

	for _, t := range tunnels {
		_ = t.Close()
	}
	return s.Conn.Close()
}

// Manager manages active client sessions in a concurrency-safe manner.
// Multiple concurrent sessions may share the same clientID without kicking each other.
type Manager struct {
	mu       sync.RWMutex
	byID     map[uint64]*Session
	byClient map[string][]*Session
	nextID   atomic.Uint64
	metrics  *metrics.Metrics
}

// NewManager creates a new session Manager.
func NewManager(m *metrics.Metrics) *Manager {
	return &Manager{
		byID:     make(map[uint64]*Session),
		byClient: make(map[string][]*Session),
		metrics:  m,
	}
}

// Create registers a new session without closing existing active sessions of the same clientID,
// allowing multiple client instances to stay connected concurrently.
func (m *Manager) Create(clientID string, conn net.Conn, localAddr string) *Session {
	id := m.nextID.Add(1)
	s := &Session{
		ID:        id,
		ClientID:  clientID,
		Conn:      conn,
		LocalAddr: localAddr,
		tunnels:   make(map[string]io.Closer),
	}
	s.TouchHeartbeat()

	m.mu.Lock()
	m.byID[id] = s
	m.byClient[clientID] = append(m.byClient[clientID], s)
	m.updateMetricsLocked()
	m.mu.Unlock()

	return s
}

// Get retrieves a session by its numeric ID.
func (m *Manager) Get(id uint64) (*Session, bool) {
	m.mu.RLock()
	s, ok := m.byID[id]
	m.mu.RUnlock()
	return s, ok
}

// GetByClientID retrieves the most recently created active session for clientID.
func (m *Manager) GetByClientID(clientID string) (*Session, bool) {
	m.mu.RLock()
	list := m.byClient[clientID]
	var s *Session
	if len(list) > 0 {
		s = list[len(list)-1]
	}
	m.mu.RUnlock()
	return s, s != nil
}

// Remove deletes and closes a session if it is still registered.
func (m *Manager) Remove(id uint64) {
	m.mu.Lock()
	s, ok := m.byID[id]
	if ok {
		delete(m.byID, id)
		list := m.byClient[s.ClientID]
		for i, cur := range list {
			if cur.ID == id {
				list = append(list[:i], list[i+1:]...)
				break
			}
		}
		if len(list) == 0 {
			delete(m.byClient, s.ClientID)
		} else {
			m.byClient[s.ClientID] = list
		}
		m.updateMetricsLocked()
	}
	m.mu.Unlock()

	if ok {
		_ = s.Close()
	}
}

// ListPeers returns snapshots of all currently connected clients.
func (m *Manager) ListPeers() []message.PeerInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	peers := make([]message.PeerInfo, 0, len(m.byID))
	for _, s := range m.byID {
		s.mu.Lock()
		pub := s.PublicAddr
		s.mu.Unlock()
		peers = append(peers, message.PeerInfo{
			ClientID:   s.ClientID,
			SessionID:  s.ID,
			PublicAddr: pub,
			LocalAddr:  s.LocalAddr,
		})
	}
	return peers
}

// ReapExpired periodically removes sessions whose heartbeat is older than timeout.
func (m *Manager) ReapExpired(ctx context.Context, timeout time.Duration) {
	ticker := time.NewTicker(timeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-timeout)
			var expired []uint64
			m.mu.RLock()
			for id, s := range m.byID {
				if s.LastHeartbeat().Before(cutoff) {
					expired = append(expired, id)
				}
			}
			m.mu.RUnlock()
			for _, id := range expired {
				m.Remove(id)
			}
		}
	}
}

// CloseAll closes every active session.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.byID))
	for _, s := range m.byID {
		sessions = append(sessions, s)
	}
	m.byID = make(map[uint64]*Session)
	m.byClient = make(map[string][]*Session)
	m.updateMetricsLocked()
	m.mu.Unlock()

	for _, s := range sessions {
		_ = s.Close()
	}
}

func (m *Manager) updateMetricsLocked() {
	if m.metrics == nil {
		return
	}
	n := int64(len(m.byID))
	m.metrics.ActiveSessions.Store(n)
	m.metrics.OnlineClients.Store(n)
}
