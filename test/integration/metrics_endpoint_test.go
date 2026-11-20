package integration

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"iplink/internal/config"
	"iplink/internal/logger"
	serverservice "iplink/internal/server/service"
)

func TestMetricsEndpointAndCapability(t *testing.T) {
	const token = "metrics-secret"
	cfg := config.DefaultServerConfig()
	cfg.Server.ListenIP = "127.0.0.1"
	cfg.Server.ControlPort = 0
	cfg.Server.RelayPort = 0
	cfg.Server.NATPort = 0
	cfg.Server.HTTPProxyPort = 0
	cfg.Metrics.Enabled = true
	cfg.Metrics.Port = 0
	cfg.Security.Token = token

	srv := serverservice.New(cfg, logger.New("warn", "text", io.Discard))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && srv.MetricsAddr() == "" {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.MetricsAddr() == "" {
		t.Fatal("metrics server failed to bind")
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + srv.MetricsAddr() + "/metrics")
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "iplink_online_clients") {
		t.Fatalf("metrics body missing expected metric:\n%s", body)
	}

	// 认证时下发的 capabilities 应报告同一个实际绑定端口。
	cli, done := startCapabilityClient(t, ctx, token, mustPort(t, srv.ControlAddr()), mustPort(t, srv.NATAddr()), "metrics-client")
	defer func() { cancel(); <-done }()
	caps, known := cli.ServerCapabilities()
	if !known {
		t.Fatal("capabilities not advertised")
	}
	if !caps.MetricsEnabled || caps.MetricsPort != mustPort(t, srv.MetricsAddr()) {
		t.Fatalf("metrics capability = (enabled=%v, port=%d), want port %d",
			caps.MetricsEnabled, caps.MetricsPort, mustPort(t, srv.MetricsAddr()))
	}
}

func TestMetricsDisabledByConfig(t *testing.T) {
	const token = "no-metrics-secret"
	cfg := config.DefaultServerConfig()
	cfg.Server.ListenIP = "127.0.0.1"
	cfg.Server.ControlPort = 0
	cfg.Server.RelayPort = 0
	cfg.Server.NATPort = 0
	cfg.Metrics.Enabled = false
	cfg.Security.Token = token

	srv := serverservice.New(cfg, logger.New("warn", "text", io.Discard))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && srv.ControlAddr() == "" {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.ControlAddr() == "" {
		t.Fatal("server failed to bind control address")
	}
	if srv.MetricsAddr() != "" {
		t.Fatalf("metrics should be disabled, got addr %s", srv.MetricsAddr())
	}
}

func TestMetricsEndpointRequiresToken(t *testing.T) {
	const token = "metrics-auth-secret"
	cfg := config.DefaultServerConfig()
	cfg.Server.ListenIP = "127.0.0.1"
	cfg.Server.ControlPort = 0
	cfg.Server.RelayPort = 0
	cfg.Server.NATPort = 0
	cfg.Metrics.Enabled = true
	cfg.Metrics.Port = 0
	cfg.Metrics.ListenIP = "127.0.0.1"
	cfg.Metrics.Token = token
	cfg.Security.Token = "client-token"

	srv := serverservice.New(cfg, logger.New("warn", "text", io.Discard))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && srv.MetricsAddr() == "" {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.MetricsAddr() == "" {
		t.Fatal("metrics server failed to bind")
	}
	// Default listen IP must be loopback, never 0.0.0.0.
	if host, _, _ := net.SplitHostPort(srv.MetricsAddr()); host != "127.0.0.1" {
		t.Fatalf("metrics bound to %q, want loopback", host)
	}

	client := &http.Client{Timeout: 3 * time.Second}

	// Anonymous request rejected.
	resp, err := client.Get("http://" + srv.MetricsAddr() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous status = %d, want 401", resp.StatusCode)
	}

	// With token accepted.
	req, _ := http.NewRequest(http.MethodGet, "http://"+srv.MetricsAddr()+"/metrics", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated status = %d, want 200", resp.StatusCode)
	}
	if !strings.Contains(string(body), "iplink_online_clients") {
		t.Fatalf("metrics body missing expected metric:/n%s", body)
	}
}

func TestMetricsConfigRejectsPublicListenWithoutToken(t *testing.T) {
	cfg := config.DefaultServerConfig()
	cfg.Security.Token = "client-token"
	cfg.Metrics.ListenIP = "0.0.0.0"
	cfg.Metrics.Token = ""
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for public metrics without token")
	}
	// With token set it should pass (ports are defaults, all distinct).
	cfg.Metrics.Token = "some-token"
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected validation error with token: %v", err)
	}
}
