package manager

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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

const (
	// RelayPacketHeader: [16-byte sessionID][16-byte MAC][payload]
	relayHeaderLen = 16
	relayMACLen    = 16
	relayPrefixLen = relayHeaderLen + relayMACLen
)

type relaySession struct {
	id         string
	clientA    string
	clientB    string
	key        []byte // HMAC key derived from the per-session relay token
	peerA      net.Addr
	peerB      net.Addr
	lastActive time.Time
}

// tokenBucket 是一个简单的字节令牌桶，用于 Relay 出口限速。
// capacity 至少能容纳一个最大 UDP 包，避免低速率下单个包永远无法通过。
type tokenBucket struct {
	mu       sync.Mutex
	rate     float64
	capacity float64
	tokens   float64
	last     time.Time
}

func newTokenBucket(bytesPerSec int64) *tokenBucket {
	if bytesPerSec <= 0 {
		return nil // 不限速
	}
	cap := float64(bytesPerSec)
	if cap < protocol.MaxUDPPacketSize {
		cap = protocol.MaxUDPPacketSize
	}
	return &tokenBucket{rate: float64(bytesPerSec), capacity: cap, tokens: cap, last: time.Now()}
}

func (b *tokenBucket) allow(n int) bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * b.rate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}
	b.last = now
	if b.tokens >= float64(n) {
		b.tokens -= float64(n)
		return true
	}
	return false
}

// Manager handles UDP relay session allocation, packet forwarding, and idle cleanup.
type Manager struct {
	enabled     bool
	maxSessions int
	conn        net.PacketConn
	metrics     *metrics.Metrics
	log         *slog.Logger
	limiter     *tokenBucket // nil 表示不限速

	mu       sync.RWMutex
	sessions map[string]*relaySession
}

// Start starts the UDP relay listener on addr if enabled.
func Start(ctx context.Context, addr string, enabled bool, maxSessions int, maxBytesPerSec int64, m *metrics.Metrics, log *slog.Logger) (*Manager, error) {
	mgr := &Manager{
		enabled:     enabled,
		maxSessions: maxSessions,
		metrics:     m,
		log:         log,
		limiter:     newTokenBucket(maxBytesPerSec),
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

// Allocate creates a new relay session for the two authorized clients.
// It returns the session ID and a per-session token that must accompany every
// data packet; the token is delivered to both peers over the control channel.
func (m *Manager) Allocate(clientA, clientB string) (string, string, error) {
	if !m.enabled {
		return "", "", ErrRelayDisabled
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.maxSessions > 0 && len(m.sessions) >= m.maxSessions {
		return "", "", ErrRelayFull
	}

	var id, token string
	for {
		// 12 random bytes -> 16 base64url chars, exactly one session-ID header.
		sid, err := randomRelayString(12)
		if err != nil {
			return "", "", fmt.Errorf("relay: generate session ID: %w", err)
		}
		if _, exists := m.sessions[sid]; !exists {
			id = sid
			break
		}
	}
	token, err := randomRelayString(16)
	if err != nil {
		return "", "", fmt.Errorf("relay: generate session token: %w", err)
	}
	m.sessions[id] = &relaySession{
		id:         id,
		clientA:    clientA,
		clientB:    clientB,
		key:        deriveRelayKey(token),
		lastActive: time.Now(),
	}
	m.metrics.RelayConnections.Store(int64(len(m.sessions)))
	return id, token, nil
}

func randomRelayString(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func deriveRelayKey(token string) []byte {
	sum := sha256.Sum256([]byte("iplink/relay-v1/" + token))
	return sum[:]
}

func relayMAC(header, payload, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(header)
	_, _ = mac.Write(payload)
	return mac.Sum(nil)[:relayMACLen]
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

// EncodeRelayPacket prefixes payload with the session ID and a per-session HMAC.
// Packet layout: [16-byte sessionID][16-byte MAC][payload].
func EncodeRelayPacket(sessionID, token string, payload []byte) []byte {
	pkt := make([]byte, relayPrefixLen+len(payload))
	copy(pkt[:relayHeaderLen], sessionID)
	copy(pkt[relayPrefixLen:], payload)
	copy(pkt[relayHeaderLen:relayPrefixLen], relayMAC(pkt[:relayHeaderLen], payload, deriveRelayKey(token)))
	return pkt
}

// DecodeRelayPacket verifies the per-session MAC and returns the session ID and payload.
func DecodeRelayPacket(pkt []byte, token string) (string, []byte, error) {
	if len(pkt) <= relayPrefixLen {
		return "", nil, errors.New("relay: packet shorter than header")
	}
	header := pkt[:relayHeaderLen]
	payload := pkt[relayPrefixLen:]
	want := relayMAC(header, payload, deriveRelayKey(token))
	if !hmac.Equal(pkt[relayHeaderLen:relayPrefixLen], want) {
		return "", nil, errors.New("relay: invalid packet MAC")
	}
	return trimZeroRight(header), payload, nil
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
		if n <= relayPrefixLen {
			continue
		}
		sid := trimZeroRight(buf[:relayHeaderLen])
		payload := buf[relayPrefixLen:n]

		// Only packets carrying the session token may update peers or be forwarded.
		m.mu.RLock()
		sess, ok := m.sessions[sid]
		var key []byte
		if ok {
			key = append([]byte(nil), sess.key...)
		}
		m.mu.RUnlock()
		if !ok || !hmac.Equal(buf[relayHeaderLen:relayPrefixLen], relayMAC(buf[:relayHeaderLen], payload, key)) {
			m.log.Debug("relay packet dropped: unknown session or invalid MAC", "session", sid)
			continue
		}

		if !m.limiter.allow(len(payload)) {
			m.log.Debug("relay packet dropped by rate limit", "session", sid, "bytes", len(payload))
			continue
		}

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
