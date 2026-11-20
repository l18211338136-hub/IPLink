package metrics

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// Handler exposes runtime metrics over HTTP.
// GET /metrics      -> Prometheus text exposition format
// GET /metrics/json -> JSON Snapshot
//
// If token is non-empty, requests must authenticate either with
// "Authorization: Bearer <token>" or "?token=<token>". An empty token
// disables authentication (intended for loopback-only deployments).
func Handler(m *Metrics, token ...string) http.Handler {
	expected := ""
	if len(token) > 0 {
		expected = token[0]
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if expected != "" && !metricsAuthenticated(r, expected) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="iplink-metrics"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		snap := m.Snapshot()
		switch r.URL.Path {
		case "/metrics":
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			_, _ = w.Write([]byte(RenderPrometheus(snap)))
		case "/metrics/json":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_ = json.NewEncoder(w).Encode(snap)
		default:
			http.NotFound(w, r)
		}
	})
}

// metricsAuthenticated reports whether r carries the expected metrics token.
// It accepts "Authorization: Bearer <token>" or "?token=<token>".
func metricsAuthenticated(r *http.Request, expected string) bool {
	if auth := r.Header.Get("Authorization"); auth != "" {
		parts := strings.Fields(auth)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			return false
		}
		return subtle.ConstantTimeCompare([]byte(parts[1]), []byte(expected)) == 1
	}
	return subtle.ConstantTimeCompare([]byte(r.URL.Query().Get("token")), []byte(expected)) == 1
}

// Prometheus 指标定义：名称、帮助文本、类型（gauge / counter）与取值。
type promMetric struct {
	name  string
	help  string
	typ   string
	value string
}

// RenderPrometheus renders a snapshot in the Prometheus text exposition format 0.0.4.
func RenderPrometheus(s Snapshot) string {
	metrics := []promMetric{
		{"iplink_online_clients", "Number of clients currently online.", "gauge", strconv.FormatInt(s.OnlineClients, 10)},
		{"iplink_active_sessions", "Number of active control sessions.", "gauge", strconv.FormatInt(s.ActiveSessions, 10)},
		{"iplink_active_tunnels", "Number of active tunnels.", "gauge", strconv.FormatInt(s.ActiveTunnels, 10)},
		{"iplink_relay_connections", "Number of active relay sessions.", "gauge", strconv.FormatInt(s.RelayConnections, 10)},
		{"iplink_p2p_attempts", "Total number of P2P connection attempts.", "counter", strconv.FormatInt(s.P2PAttempts, 10)},
		{"iplink_p2p_successes", "Total number of successful P2P connections.", "counter", strconv.FormatInt(s.P2PSuccesses, 10)},
		{"iplink_p2p_success_rate", "Ratio of successful P2P connections to attempts.", "gauge", strconv.FormatFloat(s.P2PSuccessRate, 'f', 6, 64)},
		{"iplink_bytes_sent_total", "Total bytes sent by the server.", "counter", strconv.FormatUint(s.BytesSent, 10)},
		{"iplink_bytes_received_total", "Total bytes received by the server.", "counter", strconv.FormatUint(s.BytesReceived, 10)},
	}

	var b strings.Builder
	for _, m := range metrics {
		b.WriteString("# HELP ")
		b.WriteString(m.name)
		b.WriteString(" ")
		b.WriteString(m.help)
		b.WriteString("\n# TYPE ")
		b.WriteString(m.name)
		b.WriteString(" ")
		b.WriteString(m.typ)
		b.WriteString("\n")
		b.WriteString(m.name)
		b.WriteString(" ")
		b.WriteString(m.value)
		b.WriteString("\n")
	}

	// Per-tunnel gauges/counters with identifying labels.
	if len(s.Tunnels) > 0 {
		writeLabeled := func(name, typ, value, tunnelID, protocol string) {
			b.WriteString("# TYPE ")
			b.WriteString(name)
			b.WriteString(" ")
			b.WriteString(typ)
			b.WriteString("\n")
			b.WriteString(name)
			b.WriteString("{tunnel_id=")
			b.WriteString(strconv.Quote(tunnelID))
			b.WriteString(",protocol=")
			b.WriteString(strconv.Quote(protocol))
			b.WriteString("} ")
			b.WriteString(value)
			b.WriteString("\n")
		}
		for _, t := range s.Tunnels {
			writeLabeled("iplink_tunnel_active_conns", "gauge", strconv.FormatInt(t.ActiveConns, 10), t.TunnelID, t.Protocol)
			writeLabeled("iplink_tunnel_bytes_sent", "counter", strconv.FormatUint(t.BytesSent, 10), t.TunnelID, t.Protocol)
			writeLabeled("iplink_tunnel_bytes_received", "counter", strconv.FormatUint(t.BytesReceived, 10), t.TunnelID, t.Protocol)
		}
	}
	return b.String()
}
