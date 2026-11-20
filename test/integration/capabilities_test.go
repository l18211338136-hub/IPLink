package integration

import (
	"context"
	"io"
	"testing"
	"time"

	clientservice "iplink/internal/client/service"
	"iplink/internal/config"
	"iplink/internal/logger"
	serverservice "iplink/internal/server/service"
)

func startCapabilityClient(t *testing.T, ctx context.Context, token string, ctrlPort, natPort int, id string) (*clientservice.Client, <-chan error) {
	t.Helper()
	cfg := config.DefaultClientConfig()
	cfg.Client.ID = id
	cfg.Server.Address = "127.0.0.1"
	cfg.Server.Port = ctrlPort
	cfg.Server.NATPort = natPort
	cfg.Security.Token = token
	cfg.Tunnels = nil

	cli, err := clientservice.New(cfg, logger.New("warn", "text", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	done, err := cli.Start(ctx)
	if err != nil {
		t.Fatalf("client %s start: %v", id, err)
	}
	return cli, done
}

func TestServerCapabilitiesDiscoveredAtAuth(t *testing.T) {
	const token = "capability-secret"
	_, ctrlPort, relayPort, natPort, stopSrv := startTestServer(t, token)
	defer stopSrv()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cli, done := startCapabilityClient(t, ctx, token, ctrlPort, natPort, "client-a")
	defer func() {
		cancel()
		<-done
	}()

	caps, known := cli.ServerCapabilities()
	if !known {
		t.Fatal("server capabilities were not advertised")
	}
	if caps.ProtocolVersion == 0 {
		t.Fatal("protocol version is zero")
	}
	if !caps.RelayEnabled || caps.RelayPort != relayPort {
		t.Fatalf("relay capability = (enabled=%v, port=%d), want (true, %d)", caps.RelayEnabled, caps.RelayPort, relayPort)
	}
	if !caps.NATEnabled || caps.NATPort != natPort {
		t.Fatalf("NAT capability = (enabled=%v, port=%d), want (true, %d)", caps.NATEnabled, caps.NATPort, natPort)
	}
	if caps.HTTPProxyEnabled {
		t.Fatalf("HTTP proxy should be disabled by default, got port %d", caps.HTTPProxyPort)
	}
}

func TestServerInfoReturnsLiveMetrics(t *testing.T) {
	const token = "info-secret"
	_, ctrlPort, _, natPort, stopSrv := startTestServer(t, token)
	defer stopSrv()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cli, done := startCapabilityClient(t, ctx, token, ctrlPort, natPort, "client-a")
	defer func() {
		cancel()
		<-done
	}()

	queryCtx, queryCancel := context.WithTimeout(ctx, 3*time.Second)
	defer queryCancel()
	info, err := cli.ServerInfo(queryCtx)
	if err != nil {
		t.Fatalf("ServerInfo: %v", err)
	}
	if info.Metrics.OnlineClients < 1 || info.Metrics.ActiveSessions < 1 {
		t.Fatalf("unexpected metrics snapshot: %+v", info.Metrics)
	}
	if !info.Capabilities.RelayEnabled {
		t.Fatal("info response is missing relay capability")
	}
}

func TestRelayDisabledAdvertisedAndPeerFailsFast(t *testing.T) {
	const token = "no-relay-secret"
	cfg := config.DefaultServerConfig()
	cfg.Server.ListenIP = "127.0.0.1"
	cfg.Server.ControlPort = 0
	cfg.Server.RelayPort = 0
	cfg.Server.NATPort = 0
	cfg.Server.HTTPProxyPort = 0
	cfg.Metrics.Port = 0 // 动态分配，避免测试间端口冲突
	cfg.Security.Token = token
	cfg.Relay.Enabled = false

	log := logger.New("warn", "text", io.Discard)
	srv := serverservice.New(cfg, log)
	srvCtx, stopSrv := context.WithCancel(context.Background())
	defer stopSrv()
	go func() { _ = srv.Start(srvCtx) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && srv.ControlAddr() == "" {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.ControlAddr() == "" {
		t.Fatal("server failed to bind control address")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cli, done := startCapabilityClient(t, ctx, token, mustPort(t, srv.ControlAddr()), mustPort(t, srv.NATAddr()), "client-a")
	defer func() {
		cancel()
		<-done
	}()

	caps, known := cli.ServerCapabilities()
	if !known {
		t.Fatal("capabilities not advertised")
	}
	if caps.RelayEnabled || caps.RelayPort != 0 {
		t.Fatalf("relay should be disabled, got %+v", caps)
	}
	if !caps.NATEnabled {
		t.Fatal("NAT should still be enabled")
	}

	queryCtx, queryCancel := context.WithTimeout(ctx, 3*time.Second)
	defer queryCancel()
	_, err := cli.ConnectPeer(queryCtx, "offline-peer")
	if err == nil {
		t.Fatal("expected error when relay disabled and peer unreachable")
	}
}
