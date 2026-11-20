package metrics

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
)

// Handler exposes runtime metrics over HTTP.
// GET /metrics      -> Prometheus text exposition format
// GET /metrics/json -> JSON Snapshot
func Handler(m *Metrics) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	return b.String()
}
