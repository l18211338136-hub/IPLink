package integration

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	clientservice "iplink/internal/client/service"
	"iplink/internal/config"
	"iplink/internal/logger"
	serverservice "iplink/internal/server/service"
)

// writeSelfSignedCert 生成临时自签证书/私钥，返回服务端配置所需的文件路径。
func writeSelfSignedCert(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "iplink-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func waitForServer(t *testing.T, srv *serverservice.Server) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && srv.ControlAddr() == "" {
		time.Sleep(10 * time.Millisecond)
	}
	if srv.ControlAddr() == "" {
		t.Fatal("server failed to bind control address")
	}
}

func TestTLSEncryptedControlHTTPProxyAndMetrics(t *testing.T) {
	const token = "tls-secret-token"
	certFile, keyFile := writeSelfSignedCert(t)

	cfg := config.DefaultServerConfig()
	cfg.Server.ListenIP = "127.0.0.1"
	cfg.Server.ControlPort = 0
	cfg.Server.RelayPort = 0
	cfg.Server.NATPort = 0
	// 让 HTTP 代理与 metrics 用动态端口，避免冲突。
	cfg.Server.HTTPProxyPort = freeTCPPort(t)
	cfg.Metrics.Port = 0
	cfg.Security.Token = token
	cfg.Security.TLSEnabled = true
	cfg.Security.TLSCertFile = certFile
	cfg.Security.TLSKeyFile = keyFile

	srv := serverservice.New(cfg, logger.New("warn", "text", io.Discard))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Start(ctx) }()
	waitForServer(t, srv)

	// metrics 端点在 TLS 下应只接受 HTTPS。
	httpsClient := &http.Client{
		Timeout:   3 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec // 测试自签证书
	}
	resp, err := httpsClient.Get("https://" + srv.MetricsAddr() + "/metrics")
	if err != nil {
		t.Fatalf("HTTPS GET /metrics: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTPS metrics status = %d", resp.StatusCode)
	}

	// HTTP 代理端口同样是 HTTPS：明文 HTTP 客户端不应拿到 200 响应。
	plainClient := &http.Client{Timeout: 2 * time.Second}
	plainResp, plainErr := plainClient.Get("http://" + srv.HTTPProxyAddr() + "/")
	if plainErr == nil {
		plainResp.Body.Close()
		if plainResp.StatusCode == http.StatusOK {
			t.Fatal("plain HTTP request to TLS-enabled proxy unexpectedly succeeded")
		}
	}

	// 带 TLS 的客户端能连上控制面并发现能力。
	cliCfg := config.DefaultClientConfig()
	cliCfg.Client.ID = "tls-client"
	cliCfg.Server.Address = "127.0.0.1"
	cliCfg.Server.Port = mustPort(t, srv.ControlAddr())
	cliCfg.Server.NATPort = mustPort(t, srv.NATAddr())
	cliCfg.Security.Token = token
	cliCfg.Security.TLSEnabled = true
	cliCfg.Security.TLSInsecureSkipVerify = true
	cliCfg.Tunnels = nil
	cli, err := clientservice.New(cliCfg, logger.New("warn", "text", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	done, err := cli.Start(ctx)
	if err != nil {
		t.Fatalf("TLS client start: %v", err)
	}
	defer func() { cancel(); <-done }()
	if !cli.Connected() {
		t.Fatal("TLS client should be connected")
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}
