package manager

import (
	"io"
	"log/slog"
	"testing"

	"iplink/internal/metrics"
)

func testManager() *Manager {
	return &Manager{
		enabled:  true,
		metrics:  &metrics.Metrics{},
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		sessions: make(map[string]*relaySession),
	}
}

func TestAllocateUsesRandomIDAndSessionToken(t *testing.T) {
	m := testManager()

	id1, token1, err := m.Allocate("client-a", "client-b")
	if err != nil {
		t.Fatal(err)
	}
	id2, token2, err := m.Allocate("client-c", "client-d")
	if err != nil {
		t.Fatal(err)
	}
	if id1 == id2 {
		t.Fatalf("session IDs must be random: got %q twice", id1)
	}
	if token1 == token2 {
		t.Fatalf("session tokens must be random: got %q twice", token1)
	}
	if len(id1) != relayHeaderLen {
		t.Fatalf("session ID length = %d, want %d", len(id1), relayHeaderLen)
	}

	sess := m.sessions[id1]
	if sess == nil {
		t.Fatal("session not stored")
	}
	if sess.clientA != "client-a" || sess.clientB != "client-b" {
		t.Fatalf("authorized clients = (%q, %q), want (client-a, client-b)", sess.clientA, sess.clientB)
	}
}

func TestRelayPacketRequiresSessionToken(t *testing.T) {
	m := testManager()
	id, token, err := m.Allocate("client-a", "client-b")
	if err != nil {
		t.Fatal(err)
	}

	pkt := EncodeRelayPacket(id, token, []byte("payload"))
	gotID, payload, err := DecodeRelayPacket(pkt, token)
	if err != nil {
		t.Fatalf("decode with correct token: %v", err)
	}
	if gotID != id || string(payload) != "payload" {
		t.Fatalf("decoded = (%q, %q), want (%q, payload)", gotID, payload, id)
	}

	if _, _, err := DecodeRelayPacket(pkt, "wrong-token"); err == nil {
		t.Fatal("packet with wrong token must be rejected")
	}

	_, otherToken, err := m.Allocate("client-c", "client-d")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecodeRelayPacket(EncodeRelayPacket(id, otherToken, []byte("x")), token); err == nil {
		t.Fatal("MAC must be bound to the session ID header")
	}
}
