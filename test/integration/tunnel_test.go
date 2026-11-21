package integration

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	clientservice "iplink/internal/client/service"
	"iplink/internal/config"
	"iplink/internal/logger"
	"iplink/internal/metrics"
	"iplink/internal/nat/discovery"
	dgramcrypto "iplink/internal/security/crypto"
	serverservice "iplink/internal/server/service"
)

func startTestServer(t *testing.T, token string) (*serverservice.Server, int, int, int, context.CancelFunc) {
	t.Helper()
	srvCfg := config.DefaultServerConfig()
	srvCfg.Server.ListenIP = "127.0.0.1"
	srvCfg.Server.ControlPort = 0
	srvCfg.Server.RelayPort = 0
	srvCfg.Server.NATPort = 0
	srvCfg.Metrics.Port = 0 // 动态分配，避免测试间端口冲突
	srvCfg.Security.Token = token

	log := logger.New("warn", "text", io.Discard)
	srv := serverservice.New(srvCfg, log)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		_ = srv.Start(ctx)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.ControlAddr() != "" && srv.NATAddr() != "" && srv.RelayAddr() != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv.ControlAddr() == "" {
		cancel()
		t.Fatal("server failed to bind control address")
	}

	return srv, mustPort(t, srv.ControlAddr()), mustPort(t, srv.RelayAddr()), mustPort(t, srv.NATAddr()), cancel
}

func mustPort(t *testing.T, addr string) int {
	t.Helper()
	_, pStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	p, err := strconv.Atoi(pStr)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", pStr, err)
	}
	return p
}

func TestEndToEndTCPAndUDPTunnels(t *testing.T) {
	const token = "integration-secret-token"
	srv, ctrlPort, relayPort, natPort, stopSrv := startTestServer(t, token)
	defer stopSrv()

	// 1. Start local TCP echo server.
	tcpEchoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEchoLn.Close()
	go func() {
		for {
			c, err := tcpEchoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	// 2. Start local UDP echo server.
	udpEchoPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer udpEchoPC.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			n, addr, err := udpEchoPC.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = udpEchoPC.WriteTo(buf[:n], addr)
		}
	}()

	// 3. Reject invalid token.
	badCfg := config.DefaultClientConfig()
	badCfg.Client.ID = "bad-client"
	badCfg.Server.Address = "127.0.0.1"
	badCfg.Server.Port = ctrlPort
	badCfg.Server.RelayPort = relayPort
	badCfg.Server.NATPort = natPort
	badCfg.Security.Token = "wrong-token"
	badCli, err := clientservice.New(badCfg, logger.New("warn", "text", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	badCtx, badCancel := context.WithTimeout(context.Background(), 2*time.Second)
	if err := badCli.ConnectOnce(badCtx); err == nil {
		badCancel()
		t.Fatal("expected authentication failure with wrong token")
	}
	badCancel()

	// 4. Connect valid client with TCP + UDP tunnels.
	cliCfg := config.DefaultClientConfig()
	cliCfg.Client.ID = "client-a"
	cliCfg.Server.Address = "127.0.0.1"
	cliCfg.Server.Port = ctrlPort
	cliCfg.Server.RelayPort = relayPort
	cliCfg.Server.NATPort = natPort
	cliCfg.Security.Token = token
	cliCfg.Tunnels = []config.TunnelConfig{
		{
			Name:       "tcp-echo",
			Protocol:   "tcp",
			LocalAddr:  tcpEchoLn.Addr().String(),
			RemoteAddr: "127.0.0.1:0",
		},
		{
			Name:       "udp-echo",
			Protocol:   "udp",
			LocalAddr:  udpEchoPC.LocalAddr().String(),
			RemoteAddr: "127.0.0.1:0",
		},
	}

	cli, err := clientservice.New(cliCfg, logger.New("warn", "text", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	cliCtx, cliCancel := context.WithCancel(context.Background())
	defer cliCancel()

	doneCh, err := cli.Start(cliCtx)
	if err != nil {
		t.Fatalf("client Start: %v", err)
	}
	defer func() {
		cliCancel()
		<-doneCh
	}()

	var tcpBound, udpBound string
	for _, at := range cli.ActiveTunnels() {
		if at.Protocol == "tcp" {
			tcpBound = at.BoundAddr
		} else if at.Protocol == "udp" {
			udpBound = at.BoundAddr
		}
	}
	if tcpBound == "" || udpBound == "" {
		t.Fatalf("missing bound tunnel addresses: tcp=%q udp=%q", tcpBound, udpBound)
	}

	// 5. Verify TCP tunnel end-to-end forwarding.
	extTCP, err := net.DialTimeout("tcp", tcpBound, 2*time.Second)
	if err != nil {
		t.Fatalf("dial TCP tunnel %s: %v", tcpBound, err)
	}
	defer extTCP.Close()
	wantTCP := []byte("hello-tcp-tunnel-payload")
	if _, err := extTCP.Write(wantTCP); err != nil {
		t.Fatal(err)
	}
	gotTCP := make([]byte, len(wantTCP))
	_ = extTCP.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(extTCP, gotTCP); err != nil {
		t.Fatalf("read TCP tunnel echo: %v", err)
	}
	if !bytes.Equal(gotTCP, wantTCP) {
		t.Fatalf("TCP echo = %q, want %q", gotTCP, wantTCP)
	}

	// 6. Verify UDP tunnel end-to-end forwarding.
	extUDP, err := net.DialTimeout("udp", udpBound, 2*time.Second)
	if err != nil {
		t.Fatalf("dial UDP tunnel %s: %v", udpBound, err)
	}
	defer extUDP.Close()
	wantUDP := []byte("hello-udp-tunnel-payload")
	if _, err := extUDP.Write(wantUDP); err != nil {
		t.Fatal(err)
	}
	bufUDP := make([]byte, 1024)
	_ = extUDP.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := extUDP.Read(bufUDP)
	if err != nil {
		t.Fatalf("read UDP tunnel echo: %v", err)
	}
	if !bytes.Equal(bufUDP[:n], wantUDP) {
		t.Fatalf("UDP echo = %q, want %q", bufUDP[:n], wantUDP)
	}

	// 7. Verify NAT public address discovery.
	natCipher, err := dgramcrypto.NewDatagramCipher(token)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := discovery.DiscoverPublicAddr(cliCtx, nil, srv.NATAddr(), "client-a", "nonce-1", natCipher)
	if err != nil {
		t.Fatalf("DiscoverPublicAddr: %v", err)
	}
	if pub == "" {
		t.Fatal("expected non-empty public address from NAT discovery")
	}

	// 8. Verify multi-client PeerList & Relay fallback.
	cliBCfg := cliCfg
	cliBCfg.Client.ID = "client-b"
	cliBCfg.Tunnels = nil
	cliBCfg.Network.EnableP2P = false
	cliB, err := clientservice.New(cliBCfg, logger.New("warn", "text", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	doneB, err := cliB.Start(cliCtx)
	if err != nil {
		t.Fatalf("client-b Start: %v", err)
	}
	defer func() {
		cliCancel()
		<-doneB
	}()

	peers, err := cliB.ListPeers(cliCtx)
	if err != nil || len(peers) < 2 {
		t.Fatalf("ListPeers = %+v, err=%v", peers, err)
	}

	ch, err := cliB.ConnectPeer(cliCtx, "client-a")
	if err != nil {
		t.Fatalf("ConnectPeer relay fallback: %v", err)
	}
	defer ch.Conn.Close()
	if ch.Mode != "relay" {
		t.Fatalf("expected relay mode when P2P disabled, got %q", ch.Mode)
	}

	// The server notifies client-a, which joins the same relay session automatically.
	peerACh := waitIncomingPeer(t, cli, "client-b")
	defer peerACh.Close()

	if err := ch.Send([]byte("relay-ping")); err != nil {
		t.Fatal(err)
	}
	recvCtx, cancelRecv := context.WithTimeout(cliCtx, 2*time.Second)
	defer cancelRecv()
	got, err := peerACh.Receive(recvCtx)
	if err != nil || !bytes.Equal(got, []byte("relay-ping")) {
		t.Fatalf("relay payload = %q, err = %v", got, err)
	}
}

func TestConcurrentTCPTunnelStreams(t *testing.T) {
	const token = "concurrent-secret-token"
	_, ctrlPort, relayPort, natPort, stopSrv := startTestServer(t, token)
	defer stopSrv()

	tcpEchoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEchoLn.Close()
	go func() {
		for {
			c, err := tcpEchoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	cliCfg := config.DefaultClientConfig()
	cliCfg.Client.ID = "concurrent-client"
	cliCfg.Server.Address = "127.0.0.1"
	cliCfg.Server.Port = ctrlPort
	cliCfg.Server.RelayPort = relayPort
	cliCfg.Server.NATPort = natPort
	cliCfg.Security.Token = token
	cliCfg.Tunnels = []config.TunnelConfig{
		{
			Name:       "tcp-stress",
			Protocol:   "tcp",
			LocalAddr:  tcpEchoLn.Addr().String(),
			RemoteAddr: "127.0.0.1:0",
		},
	}

	cli, err := clientservice.New(cliCfg, logger.New("warn", "text", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	cliCtx, cliCancel := context.WithCancel(context.Background())
	defer cliCancel()

	doneCh, err := cli.Start(cliCtx)
	if err != nil {
		t.Fatalf("client Start: %v", err)
	}
	defer func() {
		cliCancel()
		<-doneCh
	}()

	tunnels := cli.ActiveTunnels()
	if len(tunnels) != 1 {
		t.Fatalf("expected 1 active tunnel, got %d", len(tunnels))
	}
	bound := tunnels[0].BoundAddr

	const workers = 20
	var wg sync.WaitGroup
	errCh := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			conn, err := net.DialTimeout("tcp", bound, 3*time.Second)
			if err != nil {
				errCh <- err
				return
			}
			defer conn.Close()
			msg := []byte(fmt.Sprintf("concurrent-stream-payload-%02d", idx))
			if _, err := conn.Write(msg); err != nil {
				errCh <- err
				return
			}
			got := make([]byte, len(msg))
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			if _, err := io.ReadFull(conn, got); err != nil {
				errCh <- err
				return
			}
			if !bytes.Equal(got, msg) {
				errCh <- fmt.Errorf("worker %d: got %q, want %q", idx, got, msg)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("concurrent stream error: %v", err)
	}
}

func TestHTTPReverseProxyMultiRoutes(t *testing.T) {
	const token = "http-proxy-secret"

	// Pick a free port for HTTPProxyPort.
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	httpPort := mustPort(t, probeLn.Addr().String())
	_ = probeLn.Close()

	srvCfg := config.DefaultServerConfig()
	srvCfg.Server.ListenIP = "127.0.0.1"
	srvCfg.Server.ControlPort = 0
	srvCfg.Server.RelayPort = 0
	srvCfg.Server.NATPort = 0
	srvCfg.Server.HTTPProxyPort = httpPort
	srvCfg.Metrics.Port = 0 // 动态分配，避免测试间端口冲突
	srvCfg.Security.Token = token

	srv := serverservice.New(srvCfg, logger.New("warn", "text", io.Discard))
	srvCtx, stopSrv := context.WithCancel(context.Background())
	defer stopSrv()
	go func() {
		_ = srv.Start(srvCtx)
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if srv.ControlAddr() != "" && srv.HTTPProxyAddr() != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if srv.HTTPProxyAddr() == "" {
		t.Fatal("server failed to bind HTTPProxyAddr")
	}

	// Start two local HTTP services on different local ports.
	app1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "app1:%s:host=%s:prefix=%s", r.URL.Path, r.Host, r.Header.Get("X-Forwarded-Prefix"))
	}))
	defer app1.Close()

	app2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, "app2:%s", r.URL.Path)
	}))
	defer app2.Close()

	stripTrue := true
	stripFalse := false
	cliCfg := config.DefaultClientConfig()
	cliCfg.Client.ID = "http-client"
	cliCfg.Server.Address = "127.0.0.1"
	cliCfg.Server.Port = mustPort(t, srv.ControlAddr())
	cliCfg.Server.RelayPort = mustPort(t, srv.RelayAddr())
	cliCfg.Server.NATPort = mustPort(t, srv.NATAddr())
	cliCfg.Security.Token = token
	cliCfg.Tunnels = []config.TunnelConfig{
		{
			Name:        "app1",
			Protocol:    "http",
			LocalAddr:   app1.Listener.Addr().String(),
			HTTPPath:    "/app1",
			StripPrefix: &stripTrue,
		},
		{
			Name:        "app2",
			Protocol:    "http",
			LocalAddr:   app2.Listener.Addr().String(),
			HTTPPath:    "/app2",
			StripPrefix: &stripFalse,
		},
	}

	cli, err := clientservice.New(cliCfg, logger.New("warn", "text", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	cliCtx, cliCancel := context.WithCancel(context.Background())
	defer cliCancel()

	doneCh, err := cli.Start(cliCtx)
	if err != nil {
		t.Fatalf("client Start: %v", err)
	}
	defer func() {
		cliCancel()
		<-doneCh
	}()

	baseURL := "http://" + srv.HTTPProxyAddr()
	httpClient := &http.Client{Timeout: 3 * time.Second}

	// 1. /app1/users -> stripped to /users with X-Forwarded-Prefix=/app1
	resp1, err := httpClient.Get(baseURL + "/app1/users")
	if err != nil {
		t.Fatalf("GET /app1/users: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()
	wantHost := fmt.Sprintf("app1:/users:host=%s:prefix=/app1", app1.Listener.Addr().String())
	if string(body1) != wantHost {
		t.Fatalf("app1 body = %q, want %q", string(body1), wantHost)
	}

	// 2. /app2/health -> preserved as /app2/health
	resp2, err := httpClient.Get(baseURL + "/app2/health")
	if err != nil {
		t.Fatalf("GET /app2/health: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if string(body2) != "app2:/app2/health" {
		t.Fatalf("app2 body = %q, want %q", string(body2), "app2:/app2/health")
	}

	// 3. Unknown path -> 404
	resp404, err := httpClient.Get(baseURL + "/unknown")
	if err != nil {
		t.Fatalf("GET /unknown: %v", err)
	}
	_ = resp404.Body.Close()
	if resp404.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown path status = %d, want 404", resp404.StatusCode)
	}
}

func TestTunnelRuntimeStats(t *testing.T) {
	const token = "stats-secret-token"
	srv, ctrlPort, relayPort, natPort, stopSrv := startTestServer(t, token)
	defer stopSrv()

	// Local TCP echo target.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	cliCfg := config.DefaultClientConfig()
	cliCfg.Client.ID = "stats-client"
	cliCfg.Server.Address = "127.0.0.1"
	cliCfg.Server.Port = ctrlPort
	cliCfg.Server.RelayPort = relayPort
	cliCfg.Server.NATPort = natPort
	cliCfg.Security.Token = token
	cliCfg.Tunnels = []config.TunnelConfig{{
		Name:       "stats-tcp",
		Protocol:   "tcp",
		LocalAddr:  echoLn.Addr().String(),
		RemoteAddr: "127.0.0.1:0",
	}}

	cli, err := clientservice.New(cliCfg, logger.New("warn", "text", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	doneCh, err := cli.Start(ctx)
	if err != nil {
		t.Fatalf("client Start: %v", err)
	}
	defer func() { cancel(); <-doneCh }()

	var bound string
	for _, at := range cli.ActiveTunnels() {
		if at.Protocol == "tcp" {
			bound = at.BoundAddr
		}
	}
	if bound == "" {
		t.Fatal("no TCP tunnel bound")
	}

	// No connections yet: tunnel registered with zero counters.
	findTunnel := func() metrics.TunnelStats {
		t.Helper()
		for _, ts := range srv.Metrics().Tunnels {
			if ts.Protocol == "tcp" {
				return ts
			}
		}
		t.Fatal("no TCP tunnel stats in snapshot")
		return metrics.TunnelStats{}
	}
	if initial := findTunnel(); initial.ActiveConns != 0 || initial.BytesSent != 0 || initial.BytesReceived != 0 {
		t.Fatalf("initial stats = %+v, want all zero", initial)
	}

	// Open a connection and send data through the tunnel.
	conn, err := net.DialTimeout("tcp", bound, 2*time.Second)
	if err != nil {
		t.Fatalf("dial tunnel: %v", err)
	}
	payload := []byte("hello-tunnel-stats")
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("echo = %q, want %q", buf, payload)
	}

	// Active connection should be counted. Bytes may lag slightly behind the
	// echo due to async forwarding, so poll with a deadline.
	deadline := time.Now().Add(2 * time.Second)
	var got metrics.TunnelStats
	for time.Now().Before(deadline) {
		got = findTunnel()
		if got.ActiveConns == 1 && got.BytesReceived >= uint64(len(payload)) && got.BytesSent >= uint64(len(payload)) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got.ActiveConns != 1 {
		t.Fatalf("active_conns = %d, want 1", got.ActiveConns)
	}
	if got.BytesReceived < uint64(len(payload)) || got.BytesSent < uint64(len(payload)) {
		t.Fatalf("bytes tx=%d rx=%d, want both >= %d", got.BytesSent, got.BytesReceived, len(payload))
	}
	if got.LocalAddr != echoLn.Addr().String() || got.Protocol != "tcp" {
		t.Fatalf("stats metadata = %+v", got)
	}

	// Close the connection; active count should return to zero.
	conn.Close()
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if findTunnel().ActiveConns == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if final := findTunnel(); final.ActiveConns != 0 {
		t.Fatalf("active_conns after close = %d, want 0", final.ActiveConns)
	}
}
