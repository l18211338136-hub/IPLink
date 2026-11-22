package service

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"iplink/internal/metrics"
	"iplink/internal/protocol/codec"
	"iplink/internal/protocol/frame"
	"iplink/internal/protocol/message"
	"iplink/internal/server/session"
	"iplink/pkg/protocol"
)

func testSession(id uint64, clientID string) *session.Session {
	return &session.Session{ID: id, ClientID: clientID}
}

// A client from session B must not be able to inject data into a connection
// owned by session A by guessing the globally incrementing ConnID.
func TestCrossSessionTunnelDataRejected(t *testing.T) {
	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()

	s := &Server{
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics:    &metrics.Metrics{},
		proxyConns: make(map[uint64]*proxyConn),
	}
	const connID uint64 = 12345
	pc := &proxyConn{
		id: connID, tunnelID: "tun-victim", ownerID: 1,
		conn: pipeB, sendCh: make(chan []byte, 4), done: make(chan struct{}),
	}
	s.proxyConns[connID] = pc

	// Session 2 (attacker) sends data targeting session 1's conn.
	f := codec.EncodeTunnelData(0, 2, connID, []byte("INJECTED"))
	s.dispatchFrame(context.Background(), testSession(2, "attacker"), f)

	select {
	case got := <-pc.sendCh:
		t.Fatalf("cross-session data delivered to victim: %q", got)
	default:
	}
}

// A foreign session must not be able to close another session's connection.
func TestCrossSessionTunnelCloseRejected(t *testing.T) {
	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()

	s := &Server{
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics:    &metrics.Metrics{},
		proxyConns: make(map[uint64]*proxyConn),
	}
	const connID uint64 = 99
	pc := &proxyConn{
		id: connID, tunnelID: "tun-victim", ownerID: 1,
		conn: pipeB, sendCh: make(chan []byte, 4), readyCh: make(chan bool, 1), done: make(chan struct{}),
	}
	s.proxyConns[connID] = pc

	f, err := codec.EncodeJSON(protocol.MsgTunnelClose, 0, 2, message.TunnelClose{ConnID: connID})
	if err != nil {
		t.Fatal(err)
	}
	s.dispatchFrame(context.Background(), testSession(2, "attacker"), f)

	if _, ok := s.proxyConns[connID]; !ok {
		t.Fatal("foreign session closed the victim conn")
	}
	select {
	case <-pc.done:
		t.Fatal("foreign session signaled done on the victim conn")
	default:
	}
}

// A foreign session's OpenConnAck must not release the victim's readyCh.
func TestCrossSessionOpenConnAckRejected(t *testing.T) {
	pipeA, pipeB := net.Pipe()
	defer pipeA.Close()
	defer pipeB.Close()

	s := &Server{
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics:    &metrics.Metrics{},
		proxyConns: make(map[uint64]*proxyConn),
	}
	const connID uint64 = 55
	pc := &proxyConn{
		id: connID, tunnelID: "tun-victim", ownerID: 1,
		conn: pipeB, sendCh: make(chan []byte, 4), readyCh: make(chan bool, 1), done: make(chan struct{}),
	}
	s.proxyConns[connID] = pc

	f, err := codec.EncodeJSON(protocol.MsgTunnelOpenConnAck, 0, 2, message.TunnelOpenConnAck{
		ConnID: connID, Success: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	s.dispatchFrame(context.Background(), testSession(2, "attacker"), f)

	select {
	case <-pc.readyCh:
		t.Fatal("foreign session ack reached victim readyCh")
	default:
	}
	if _, ok := s.proxyConns[connID]; !ok {
		t.Fatal("foreign session closed victim conn via failed ack")
	}
}

// A foreign session must not send UDP datagrams through another session's tunnel.
func TestCrossSessionUDPDatagramRejected(t *testing.T) {
	targetPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetPC.Close()
	tunnelPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tunnelPC.Close()

	s := &Server{
		log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics:        &metrics.Metrics{},
		udpTunnels:     map[string]net.PacketConn{"tun-victim": tunnelPC},
		udpTunnelOwner: map[string]uint64{"tun-victim": 1},
		udpPeers:       make(map[string]map[string]time.Time),
	}
	s.rememberUDPPeer("tun-victim", targetPC.LocalAddr())

	f, err := codec.EncodeJSON(protocol.MsgUDPDatagram, 0, 2, message.UDPDatagram{
		TunnelID: "tun-victim", PeerAddr: targetPC.LocalAddr().String(), PayloadB64: "Rk9SRUVE",
	})
	if err != nil {
		t.Fatal(err)
	}
	s.dispatchFrame(context.Background(), testSession(2, "attacker"), f)

	buf := make([]byte, 64)
	_ = targetPC.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	if n, _, err := targetPC.ReadFrom(buf); err == nil {
		t.Fatalf("cross-session UDP delivered: %q", buf[:n])
	}
}

// Sanity: a frame with an unknown message type from any session is a no-op.
func TestDispatchUnknownTypeNoPanic(t *testing.T) {
	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	f := frame.Frame{Header: protocol.MessageHeader{
		Version: protocol.ProtocolVersion, Type: 0xFFFF,
	}}
	s.dispatchFrame(context.Background(), testSession(1, "c"), f)
}
