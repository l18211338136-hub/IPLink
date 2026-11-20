package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadServerAndClientConfig(t *testing.T) {
	t.Setenv("IPLINK_TEST_TOKEN", "tok-123")
	dir := t.TempDir()

	srvPath := filepath.Join(dir, "server.json")
	if err := os.WriteFile(srvPath, []byte(`{
		"server": {"listen_ip": "127.0.0.1", "control_port": 9000, "relay_port": 9001, "nat_port": 9002},
		"security": {"token": "${IPLINK_TEST_TOKEN}"}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	srvCfg, err := LoadServerConfig(srvPath)
	if err != nil {
		t.Fatalf("LoadServerConfig: %v", err)
	}
	if srvCfg.Security.Token != "tok-123" {
		t.Fatalf("token = %q, want tok-123", srvCfg.Security.Token)
	}

	cliPath := filepath.Join(dir, "client.json")
	if err := os.WriteFile(cliPath, []byte(`{
		"client": {"id": "c1"},
		"server": {"address": "127.0.0.1", "port": 9000},
		"security": {"token": "${IPLINK_TEST_TOKEN}"}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cliCfg, err := LoadClientConfig(cliPath)
	if err != nil {
		t.Fatalf("LoadClientConfig: %v", err)
	}
	if cliCfg.Client.ID != "c1" {
		t.Fatalf("client id = %q, want c1", cliCfg.Client.ID)
	}
}

func TestServerConfigMetricsPortValidation(t *testing.T) {
	base := func() ServerConfig {
		cfg := DefaultServerConfig()
		cfg.Security.Token = "tok"
		return cfg
	}

	t.Run("port zero is dynamic allocation", func(t *testing.T) {
		cfg := base()
		cfg.Metrics.Port = 0
		if err := cfg.Validate(); err != nil {
			t.Fatalf("metrics.port=0 should be allowed: %v", err)
		}
	})

	t.Run("collision with server port rejected", func(t *testing.T) {
		cfg := base()
		cfg.Metrics.Port = cfg.Server.ControlPort
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected metrics port collision to be rejected")
		}
	})

	t.Run("invalid port rejected", func(t *testing.T) {
		cfg := base()
		cfg.Metrics.Port = 70000
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected invalid metrics port to be rejected")
		}
	})

	t.Run("disabled skips port validation", func(t *testing.T) {
		cfg := base()
		cfg.Metrics.Enabled = false
		cfg.Metrics.Port = -1
		if err := cfg.Validate(); err != nil {
			t.Fatalf("disabled metrics should skip port validation: %v", err)
		}
	})

	t.Run("default listen ip is loopback", func(t *testing.T) {
		cfg := base()
		if cfg.Metrics.ListenIP != "127.0.0.1" {
			t.Fatalf("default metrics.listen_ip = %q, want 127.0.0.1", cfg.Metrics.ListenIP)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("default config should validate: %v", err)
		}
	})

	t.Run("invalid listen ip rejected", func(t *testing.T) {
		cfg := base()
		cfg.Metrics.ListenIP = "not-an-ip"
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected invalid metrics.listen_ip to be rejected")
		}
	})

	t.Run("public listen requires token", func(t *testing.T) {
		cfg := base()
		cfg.Metrics.ListenIP = "0.0.0.0"
		cfg.Metrics.Token = ""
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected public metrics listen without token to be rejected")
		}
		cfg.Metrics.Token = "tok"
		if err := cfg.Validate(); err != nil {
			t.Fatalf("public listen with token should validate: %v", err)
		}
	})
}

func TestClientConfigRejectsDomainName(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.Client.ID = "c1"
	cfg.Server.Address = "example.com"
	cfg.Security.Token = "tok"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected domain name to be rejected by IP-first validation")
	}
}
