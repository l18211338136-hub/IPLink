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

func TestClientConfigRejectsDomainName(t *testing.T) {
	cfg := DefaultClientConfig()
	cfg.Client.ID = "c1"
	cfg.Server.Address = "example.com"
	cfg.Security.Token = "tok"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected domain name to be rejected by IP-first validation")
	}
}
