package session

import (
	"net"
	"testing"

	"iplink/internal/metrics"
)

func TestSessionLifecycle(t *testing.T) {
	m := &metrics.Metrics{}
	mgr := NewManager(m)

	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	s1 := mgr.Create("client-a", c1, "127.0.0.1:1111")
	if m.OnlineClients.Load() != 1 || m.ActiveSessions.Load() != 1 {
		t.Fatalf("unexpected metrics after create: %+v", m.Snapshot())
	}

	got, ok := mgr.GetByClientID("client-a")
	if !ok || got.ID != s1.ID {
		t.Fatalf("GetByClientID failed: ok=%v", ok)
	}

	peers := mgr.ListPeers()
	if len(peers) != 1 || peers[0].ClientID != "client-a" {
		t.Fatalf("ListPeers = %+v", peers)
	}

	mgr.Remove(s1.ID)
	if m.OnlineClients.Load() != 0 {
		t.Fatalf("expected 0 online clients after remove, got %d", m.OnlineClients.Load())
	}
}
