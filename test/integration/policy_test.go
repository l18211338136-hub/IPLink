package integration

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	clientservice "iplink/internal/client/service"
	"iplink/internal/config"
	"iplink/internal/logger"
	serverservice "iplink/internal/server/service"
)

// startPolicyServer 启动一台可注入安全策略的服务端，返回控制端口与停止函数。
func startPolicyServer(t *testing.T, token string, allowedTargets []string) (int, context.CancelFunc) {
	t.Helper()
	cfg := config.DefaultServerConfig()
	cfg.Server.ListenIP = "127.0.0.1"
	cfg.Server.ControlPort = 0
	cfg.Server.RelayPort = 0
	cfg.Server.NATPort = 0
	cfg.Server.HTTPProxyPort = 0
	cfg.Metrics.Port = 0 // 动态分配，避免测试间端口冲突
	cfg.Security.Token = token
	cfg.Security.AllowedTargets = allowedTargets

	srv := serverservice.New(cfg, logger.New("warn", "text", io.Discard))
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Start(ctx) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && srv.ControlAddr() == "" {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.ControlAddr() == "" {
		cancel()
		t.Fatal("server failed to bind control address")
	}
	return mustPort(t, srv.ControlAddr()), cancel
}

func policyClient(t *testing.T, token string, ctrlPort int, id string, cfgMut func(*config.ClientConfig)) *clientservice.Client {
	t.Helper()
	cfg := config.DefaultClientConfig()
	cfg.Client.ID = id
	cfg.Server.Address = "127.0.0.1"
	cfg.Server.Port = ctrlPort
	cfg.Security.Token = token
	cfg.Tunnels = nil
	if cfgMut != nil {
		cfgMut(&cfg)
	}
	cli, err := clientservice.New(cfg, logger.New("warn", "text", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	return cli
}

func TestNetworkSwitchSkipsDisabledTunnels(t *testing.T) {
	const token = "switch-secret"
	_, ctrlPort, _, natPort, stopSrv := startTestServer(t, token)
	defer stopSrv()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 禁用 TCP，但配置里同时有 tcp 与 udp 隧道：tcp 被跳过，udp 正常注册。
	cli := policyClient(t, token, ctrlPort, "switch-client", func(cfg *config.ClientConfig) {
		cfg.Server.NATPort = natPort
		cfg.Network.EnableTCP = false
		cfg.Network.EnableUDP = true
		cfg.Tunnels = []config.TunnelConfig{
			{Name: "tcp-tun", Protocol: "tcp", LocalAddr: "127.0.0.1:1", RemoteAddr: "127.0.0.1:0"},
			{Name: "udp-tun", Protocol: "udp", LocalAddr: "127.0.0.1:2", RemoteAddr: "127.0.0.1:0"},
		}
	})
	done, err := cli.Start(ctx)
	if err != nil {
		t.Fatalf("client start: %v", err)
	}
	defer func() { cancel(); <-done }()

	tunnels := cli.ActiveTunnels()
	if len(tunnels) != 1 || tunnels[0].Protocol != "udp" {
		t.Fatalf("expected only udp tunnel, got %+v", tunnels)
	}
	if !cli.Connected() {
		t.Fatal("client should report connected")
	}
}

func TestRegisterTunnelRejectsDisabledProtocol(t *testing.T) {
	const token = "reject-secret"
	_, ctrlPort, _, natPort, stopSrv := startTestServer(t, token)
	defer stopSrv()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cli := policyClient(t, token, ctrlPort, "reject-client", func(cfg *config.ClientConfig) {
		cfg.Server.NATPort = natPort
		cfg.Network.EnableTCP = false
	})
	done, err := cli.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); <-done }()

	_, err = cli.RegisterTunnel(ctx, config.TunnelConfig{
		Name: "blocked", Protocol: "tcp", LocalAddr: "127.0.0.1:8080", RemoteAddr: "127.0.0.1:0",
	})
	if err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatalf("expected disabled-protocol error, got %v", err)
	}
}

func TestServerAllowedTargetsDeniesOutOfPolicy(t *testing.T) {
	const token = "allowlist-secret"
	ctrlPort, stopSrv := startPolicyServer(t, token, []string{"10.0.0.0/8:8080"})
	defer stopSrv()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cli := policyClient(t, token, ctrlPort, "allowlist-client", func(cfg *config.ClientConfig) {
		// 放宽客户端本地白名单，确保这里测的是服务端策略而非客户端侧拦截。
		cfg.Security.AllowedTargets = []string{"*:*"}
	})
	done, err := cli.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); <-done }()

	// 客户端默认白名单允许 127.0.0.1，但服务端策略只放行 10.0.0.0/8。
	_, err = cli.RegisterTunnel(ctx, config.TunnelConfig{
		Name: "denied", Protocol: "tcp", LocalAddr: "127.0.0.1:8080", RemoteAddr: "127.0.0.1:0",
	})
	if err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("expected target-denied error from server, got %v", err)
	}

	// 白名单内的目标应被接受（注册本身会尝试绑定 127.0.0.1:0 作为远端）。
	_, err = cli.RegisterTunnel(ctx, config.TunnelConfig{
		Name: "allowed", Protocol: "tcp", LocalAddr: "10.0.0.5:8080", RemoteAddr: "127.0.0.1:0",
	})
	if err != nil {
		t.Fatalf("in-policy target should be accepted: %v", err)
	}
}

func TestConnectedFalseAfterDisconnect(t *testing.T) {
	const token = "connected-secret"
	_, ctrlPort, _, natPort, stopSrv := startTestServer(t, token)
	defer stopSrv()

	ctx, cancel := context.WithCancel(context.Background())
	cli := policyClient(t, token, ctrlPort, "connected-client", func(cfg *config.ClientConfig) {
		cfg.Server.NATPort = natPort
	})
	done, err := cli.Start(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !cli.Connected() {
		t.Fatal("should be connected right after start")
	}
	cancel()
	<-done
	if cli.Connected() {
		t.Fatal("should not be connected after shutdown")
	}
}
