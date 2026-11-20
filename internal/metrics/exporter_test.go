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
