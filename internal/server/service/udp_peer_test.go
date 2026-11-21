package service

import (
	"encoding/base64"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"iplink/internal/metrics"
	"iplink/internal/protocol/message"
)

func TestUDPReplyRequiresObservedPeer(t *testing.T) {
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

	srv := &Server{
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics:    &metrics.Metrics{},
		udpTunnels: map[string]net.PacketConn{"tun-test": tunnelPC},
		udpPeers:   make(map[string]map[string]time.Time),
	}

	dgram := message.UDPDatagram{
		TunnelID:   "tun-test",
		PeerAddr:   targetPC.LocalAddr().String(),
		PayloadB64: base64.StdEncoding.EncodeToString([]byte("forged")),
	}

	// A client-chosen target that was never observed must be dropped.
	srv.handleUDPFromClient(dgram)
	buf := make([]byte, 64)
	_ = targetPC.SetReadDeadline(time.Now().Add(80 * time.Millisecond))
	if n, _, err := targetPC.ReadFrom(buf); err == nil {
		t.Fatalf("unexpected packet delivered to unobserved peer: %q", buf[:n])
	}

	// Once the address is observed on the tunnel, replies are allowed again.
	srv.rememberUDPPeer("tun-test", targetPC.LocalAddr())
	srv.handleUDPFromClient(dgram)
	_ = targetPC.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := targetPC.ReadFrom(buf)
	if err != nil {
		t.Fatalf("observed peer did not receive reply: %v", err)
	}
	if string(buf[:n]) != "forged" {
		t.Fatalf("reply = %q, want %q", buf[:n], "forged")
	}
}
