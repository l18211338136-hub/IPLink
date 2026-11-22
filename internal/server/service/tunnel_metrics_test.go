package service

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"iplink/internal/config"
	"iplink/internal/metrics"
	"iplink/internal/protocol/message"
	"iplink/internal/server/session"
)

func failingSession(t *testing.T) *session.Session {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	_ = clientConn.Close() // make SendFrame fail with ErrClosedPipe
	return &session.Session{ID: 1, ClientID: "metrics-client", Conn: serverConn}
}

func TestTunnelCreateAckFailureRollsBackMetrics(t *testing.T) {
	for _, proto := range []string{"tcp", "udp"} {
		t.Run(proto, func(t *testing.T) {
			s := &Server{
				cfg:            config.DefaultServerConfig(),
				log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
				metrics:        &metrics.Metrics{},
				proxyConns:     make(map[uint64]*proxyConn),
				udpTunnels:     make(map[string]net.PacketConn),
				udpTunnelOwner: make(map[string]uint64),
				udpPeers:       make(map[string]map[string]time.Time),
				httpRoutes:     make(map[string]*httpRoute),
			}
			s.handleTunnelCreate(context.Background(), failingSession(t), 1, message.TunnelCreate{
				Protocol:   proto,
				LocalAddr:  "127.0.0.1:8080",
				RemoteAddr: "127.0.0.1:0",
			})
			if got := s.metrics.ActiveTunnels.Load(); got != 0 {
				t.Fatalf("active_tunnels = %d, want 0 after ack failure", got)
			}
			if tunnels := s.metrics.Snapshot().Tunnels; len(tunnels) != 0 {
				t.Fatalf("tunnel stats = %+v, want empty after ack failure", tunnels)
			}
		})
	}
}

func TestCloseAllProxyConnsReleasesActiveCounter(t *testing.T) {
	s := &Server{
		metrics:    &metrics.Metrics{},
		proxyConns: make(map[uint64]*proxyConn),
	}
	s.metrics.RegisterTunnel("tun-x", "tcp", "127.0.0.1:8080")
	s.metrics.Tunnel("tun-x").ActiveConns.Add(1)

	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()
	pc := &proxyConn{id: 1, tunnelID: "tun-x", conn: pipeB, done: make(chan struct{})}
	pc.active.Store(true)
	s.proxyConns[1] = pc

	s.closeAllProxyConns()
	if got := s.metrics.Tunnel("tun-x").ActiveConns.Load(); got != 0 {
		t.Fatalf("active_conns = %d, want 0 after closeAllProxyConns", got)
	}
	select {
	case <-pc.done:
	default:
		t.Fatal("proxy conn done channel was not closed")
	}
}
