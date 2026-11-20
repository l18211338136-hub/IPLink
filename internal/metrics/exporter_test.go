package metrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRenderPrometheus(t *testing.T) {
	m := &Metrics{}
	m.OnlineClients.Store(3)
	m.ActiveTunnels.Store(5)
	m.P2PAttempts.Store(10)
	m.P2PSuccesses.Store(7)
	m.BytesSent.Store(1024)

	text := RenderPrometheus(m.Snapshot())

	for _, want := range []string{
		"# HELP iplink_online_clients",
		"# TYPE iplink_online_clients gauge",
		"iplink_online_clients 3",
		"iplink_active_tunnels 5",
		"iplink_p2p_attempts 10",
		"iplink_p2p_successes 7",
		"iplink_p2p_success_rate 0.700000",
		"iplink_bytes_sent_total 1024",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("prometheus output missing %q\n---\n%s", want, text)
		}
	}
}

func TestHandlerMetricsText(t *testing.T) {
	m := &Metrics{}
	m.OnlineClients.Store(2)
	ts := httptest.NewServer(Handler(m))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type = %q", ct)
	}
}

func TestHandlerMetricsJSON(t *testing.T) {
	m := &Metrics{}
	m.OnlineClients.Store(4)
	ts := httptest.NewServer(Handler(m))
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/metrics/json")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var snap Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if snap.OnlineClients != 4 {
		t.Fatalf("online_clients = %d, want 4", snap.OnlineClients)
	}
}

func TestHandlerMethodAndPath(t *testing.T) {
	ts := httptest.NewServer(Handler(&Metrics{}))
	defer ts.Close()

	resp, err := http.Post(ts.URL+"/metrics", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST status = %d, want 405", resp.StatusCode)
	}

	resp, err = http.Get(ts.URL + "/unknown")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown path status = %d, want 404", resp.StatusCode)
	}
}

func TestHandlerRequiresToken(t *testing.T) {
	m := &Metrics{}
	m.OnlineClients.Store(1)
	const token = "s3cr3t"
	ts := httptest.NewServer(Handler(m, token))
	defer ts.Close()

	// No credentials -> 401.
	resp, err := http.Get(ts.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("no-token status = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
		t.Fatalf("WWW-Authenticate = %q", got)
	}

	// Wrong token -> 401.
	resp, err = http.Get(ts.URL + "/metrics?token=wrong")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-token status = %d, want 401", resp.StatusCode)
	}

	// Bearer header -> 200.
	req, _ := http.NewRequest(http.MethodGet, ts.URL+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bearer status = %d, want 200", resp.StatusCode)
	}

	// Query token -> 200.
	resp, err = http.Get(ts.URL + "/metrics/json?token=" + token)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("query-token status = %d, want 200", resp.StatusCode)
	}
}

func TestTunnelStatsSnapshot(t *testing.T) {
	m := &Metrics{}
	m.RegisterTunnel("tun-2", "udp", "127.0.0.1:53")
	m.RegisterTunnel("tun-1", "tcp", "127.0.0.1:8080")
	m.RegisterTunnel("tun-1", "tcp", "127.0.0.1:9999") // re-register overwrites metadata

	tc := m.Tunnel("tun-1")
	tc.ActiveConns.Add(3)
	tc.BytesSent.Add(1024)
	tc.BytesReceived.Add(512)
	m.Tunnel("tun-2").BytesReceived.Add(64)

	snap := m.Snapshot()
	if len(snap.Tunnels) != 2 {
		t.Fatalf("tunnels = %d, want 2", len(snap.Tunnels))
	}
	// Sorted by TunnelID for deterministic output.
	if snap.Tunnels[0].TunnelID != "tun-1" || snap.Tunnels[1].TunnelID != "tun-2" {
		t.Fatalf("tunnel order = %s, %s", snap.Tunnels[0].TunnelID, snap.Tunnels[1].TunnelID)
	}
	first := snap.Tunnels[0]
	if first.ActiveConns != 3 || first.BytesSent != 1024 || first.BytesReceived != 512 {
		t.Fatalf("tun-1 counters = %+v", first)
	}
	if first.LocalAddr != "127.0.0.1:9999" || first.Protocol != "tcp" {
		t.Fatalf("tun-1 metadata = %+v", first)
	}

	// Prometheus output includes labeled per-tunnel metrics.
	text := RenderPrometheus(snap)
	for _, want := range []string{
		`iplink_tunnel_active_conns{tunnel_id="tun-1",protocol="tcp"} 3`,
		`iplink_tunnel_bytes_sent{tunnel_id="tun-1",protocol="tcp"} 1024`,
		`iplink_tunnel_bytes_received{tunnel_id="tun-2",protocol="udp"} 64`,
		"# TYPE iplink_tunnel_active_conns gauge",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("prometheus output missing %q\n---\n%s", want, text)
		}
	}

	m.UnregisterTunnel("tun-1")
	if m.Tunnel("tun-1") != nil {
		t.Fatal("tun-1 should be unregistered")
	}
	if n := len(m.Snapshot().Tunnels); n != 1 {
		t.Fatalf("tunnels after unregister = %d, want 1", n)
	}
}
