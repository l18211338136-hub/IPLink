package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"iplink/pkg/iplinkclient"
)

// RDPConfig persists server and target settings for the standalone remote desktop client.
type RDPConfig struct {
	ServerAddress  string `json:"server_address"`
	ServerPort     int    `json:"server_port"`
	Token          string `json:"token"`
	ClientID       string `json:"client_id"`
	TLSEnabled     bool   `json:"tls_enabled"`
	TLSInsecure    bool   `json:"tls_insecure"`
	TargetClientID string `json:"target_client_id"`
	RemoteAddr     string `json:"remote_addr"`
}

// PeerItem represents an online peer returned by the server.
type PeerItem struct {
	ClientID   string `json:"client_id"`
	PublicAddr string `json:"public_addr"`
	HasNAT     bool   `json:"has_nat"`
}

// RDPState reports the live connection and P2P tunnel status to the UI.
type RDPState struct {
	ServerState    string   `json:"server_state"` // "disconnected" | "connecting" | "connected"
	ServerError    string   `json:"server_error,omitempty"`
	TunnelActive   bool     `json:"tunnel_active"`
	TunnelMode     string   `json:"tunnel_mode,omitempty"` // "p2p" | "relay"
	ListenAddr     string   `json:"listen_addr,omitempty"`
	RTTMs          int64    `json:"rtt_ms,omitempty"`
	TargetClientID string   `json:"target_client_id,omitempty"`
	RemoteAddr     string   `json:"remote_addr,omitempty"`
	Logs           []string `json:"logs"`
}

// App exposes P2P remote desktop operations to the Wails frontend.
type App struct {
	ctx             context.Context
	configPath      string
	defaultClientID string

	mu         sync.Mutex
	serverStat string
	serverErr  string
	client     *iplinkclient.Client
	cancelRun  context.CancelFunc
	runDone    chan struct{}

	fwd       *iplinkclient.PeerForwarder
	fwdTarget string
	fwdRemote string

	logMu sync.Mutex
	logs  []string
	buf   bytes.Buffer
}

// NewApp creates a new App instance.
func NewApp() *App {
	cfgDir, err := os.UserConfigDir()
	if err != nil || cfgDir == "" {
		cfgDir = "."
	}
	return &App{
		configPath:      filepath.Join(cfgDir, "IPLink", "rdp.json"),
		defaultClientID: generateClientID(),
		serverStat:      "disconnected",
	}
}

// generateClientID derives a per-startup unique client ID from the machine's MAC addresses and random bytes.
func generateClientID() string {
	macTag := "000000"
	if ifaces, err := net.Interfaces(); err == nil {
		var macs []string
		for _, iface := range ifaces {
			if iface.Flags&net.FlagLoopback != 0 || len(iface.HardwareAddr) == 0 {
				continue
			}
			macs = append(macs, iface.HardwareAddr.String())
		}
		if len(macs) > 0 {
			sort.Strings(macs)
			sum := sha256.Sum256([]byte(strings.Join(macs, ",")))
			macTag = hex.EncodeToString(sum[:3])
		}
	}

	var rnd [3]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		now := time.Now().UnixNano()
		rnd[0] = byte(now)
		rnd[1] = byte(now >> 8)
		rnd[2] = byte(now >> 16)
	}
	return fmt.Sprintf("rdp-%s-%s", macTag, hex.EncodeToString(rnd[:]))
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) shutdown(_ context.Context) {
	_ = a.DisconnectRemoteDesktop()
	_ = a.DisconnectServer()
}

// GetConfig returns the saved configuration or falls back to IPLink desktop's client.json / defaults.
func (a *App) GetConfig() RDPConfig {
	data, err := os.ReadFile(a.configPath)
	if err == nil {
		var cfg RDPConfig
		if json.Unmarshal(data, &cfg) == nil {
			if cfg.ServerPort <= 0 {
				cfg.ServerPort = 29000
			}
			if strings.TrimSpace(cfg.RemoteAddr) == "" {
				cfg.RemoteAddr = "127.0.0.1:3389"
			}
			cfg.ClientID = a.defaultClientID
			return cfg
		}
	}

	def := RDPConfig{
		ServerPort:  29000,
		ClientID:    a.defaultClientID,
		TLSEnabled:  false,
		TLSInsecure: false,
		RemoteAddr:  "127.0.0.1:3389",
	}
	// Pre-fill server/token/TLS from existing desktop client.json if present.
	desktopCfgPath := filepath.Join(filepath.Dir(a.configPath), "client.json")
	if dData, dErr := os.ReadFile(desktopCfgPath); dErr == nil {
		if dCfg, pErr := iplinkclient.ParseConfig(dData); pErr == nil {
			if dCfg.Server.Address != "" {
				def.ServerAddress = dCfg.Server.Address
			}
			if dCfg.Server.Port > 0 {
				def.ServerPort = dCfg.Server.Port
			}
			def.Token = dCfg.Security.Token
			def.TLSEnabled = dCfg.Security.TLSEnabled
			def.TLSInsecure = dCfg.Security.TLSInsecureSkipVerify
		}
	}
	return def
}

func (a *App) saveConfig(cfg RDPConfig) error {
	if err := os.MkdirAll(filepath.Dir(a.configPath), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(a.configPath, append(data, '\n'), 0o600)
}

// ConnectServer connects to the IPLink signaling/relay server.
func (a *App) ConnectServer(cfg RDPConfig) error {
	if strings.TrimSpace(cfg.ServerAddress) == "" {
		return fmt.Errorf("请填写服务端地址")
	}
	if cfg.ServerPort <= 0 {
		cfg.ServerPort = 7000
	}
	if strings.TrimSpace(cfg.ClientID) == "" {
		cfg.ClientID = a.defaultClientID
	}
	if strings.TrimSpace(cfg.RemoteAddr) == "" {
		cfg.RemoteAddr = "127.0.0.1:3389"
	}

	cCfg := iplinkclient.DefaultConfig()
	cCfg.Server.Address = strings.TrimSpace(cfg.ServerAddress)
	cCfg.Server.Port = cfg.ServerPort
	cCfg.Client.ID = strings.TrimSpace(cfg.ClientID)
	cCfg.Security.Token = cfg.Token
	cCfg.Security.TLSEnabled = cfg.TLSEnabled
	cCfg.Security.TLSInsecureSkipVerify = cfg.TLSInsecure
	cCfg.Network.EnableP2P = true
	cCfg.Network.EnableTCP = true
	cCfg.Network.EnableUDP = true

	expanded, err := iplinkclient.ExpandAndValidate(cCfg)
	if err != nil {
		return err
	}
	_ = a.saveConfig(cfg)

	a.mu.Lock()
	if a.cancelRun != nil {
		a.mu.Unlock()
		return fmt.Errorf("已连接或正在连接服务端")
	}
	cli, err := iplinkclient.New(expanded, a)
	if err != nil {
		a.mu.Unlock()
		return err
	}
	runCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	a.client = cli
	a.cancelRun = cancel
	a.runDone = done
	a.serverStat = "connecting"
	a.serverErr = ""
	a.mu.Unlock()

	a.appendLog(fmt.Sprintf("正在连接服务端 %s:%d (client_id=%s)...", expanded.Server.Address, expanded.Server.Port, expanded.Client.ID))

	go func() {
		defer close(done)
		err := cli.Run(runCtx)
		cancel()

		a.mu.Lock()
		a.cancelRun = nil
		a.client = nil
		a.runDone = nil
		a.serverStat = "disconnected"
		if err != nil && runCtx.Err() == nil {
			a.serverErr = err.Error()
		}
		a.mu.Unlock()

		if err != nil && runCtx.Err() == nil {
			a.appendLog(fmt.Sprintf("服务端连接断开: %v", err))
		} else {
			a.appendLog("已断开服务端连接")
		}
	}()

	return nil
}

// DisconnectServer disconnects from the IPLink server and closes any active P2P forwarder.
func (a *App) DisconnectServer() error {
	_ = a.DisconnectRemoteDesktop()

	a.mu.Lock()
	cancel := a.cancelRun
	done := a.runDone
	a.mu.Unlock()
	if cancel == nil {
		return nil
	}
	cancel()
	if done != nil {
		select {
		case <-done:
		case <-time.After(3 * time.Second):
		}
	}
	return nil
}

// ListPeers returns currently online clients on the server (excluding self).
func (a *App) ListPeers() ([]PeerItem, error) {
	a.mu.Lock()
	cli := a.client
	a.mu.Unlock()
	if cli == nil || !cli.Connected() {
		return nil, fmt.Errorf("尚未连上服务端")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peers, err := cli.ListPeers(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]PeerItem, 0, len(peers))
	for _, p := range peers {
		out = append(out, PeerItem{
			ClientID:   p.ClientID,
			PublicAddr: p.PublicAddr,
			HasNAT:     p.PublicAddr != "",
		})
	}
	return out, nil
}

// ConnectRemoteDesktop establishes a P2P (or Relay fallback) tunnel to targetClientID's
// remoteAddr (default 127.0.0.1:3389) and launches Windows mstsc.exe.
func (a *App) ConnectRemoteDesktop(targetClientID, remoteAddr string) (RDPState, error) {
	targetClientID = strings.TrimSpace(targetClientID)
	if targetClientID == "" {
		return a.GetState(), fmt.Errorf("请填写目标设备 ID")
	}
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		remoteAddr = "127.0.0.1:3389"
	}

	a.mu.Lock()
	cli := a.client
	a.mu.Unlock()
	if cli == nil || !cli.Connected() {
		return a.GetState(), fmt.Errorf("请先连接服务端")
	}

	_ = a.DisconnectRemoteDesktop()

	cfg := a.GetConfig()
	cfg.TargetClientID = targetClientID
	cfg.RemoteAddr = remoteAddr
	_ = a.saveConfig(cfg)

	a.appendLog(fmt.Sprintf("正在向 %s 发起 P2P 打洞 (目标 %s)...", targetClientID, remoteAddr))

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	fwd, err := cli.ForwardPeerTCP(ctx, targetClientID, "127.0.0.1:0", remoteAddr)
	if err != nil {
		a.appendLog(fmt.Sprintf("P2P 远程桌面通道建立失败: %v", err))
		return a.GetState(), err
	}

	a.mu.Lock()
	a.fwd = fwd
	a.fwdTarget = targetClientID
	a.fwdRemote = remoteAddr
	a.mu.Unlock()

	a.appendLog(fmt.Sprintf("通道就绪 [%s] 本地入口 %s -> %s (RTT: %dms)",
		strings.ToUpper(fwd.Mode), fwd.ListenAddr, remoteAddr, fwd.RTT.Milliseconds()))

	if err := exec.Command("mstsc.exe", "/v:"+fwd.ListenAddr).Start(); err != nil {
		a.appendLog(fmt.Sprintf("自动启动 mstsc.exe 失败 (%v)，请手动连接 %s", err, fwd.ListenAddr))
	} else {
		a.appendLog(fmt.Sprintf("已启动系统远程桌面 (mstsc.exe /v:%s)", fwd.ListenAddr))
	}

	return a.GetState(), nil
}

// DisconnectRemoteDesktop closes the active P2P forwarder.
func (a *App) DisconnectRemoteDesktop() error {
	a.mu.Lock()
	fwd := a.fwd
	a.fwd = nil
	a.fwdTarget = ""
	a.fwdRemote = ""
	a.mu.Unlock()
	if fwd != nil {
		_ = fwd.Close()
		a.appendLog("已关闭 P2P 远程桌面通道")
	}
	return nil
}

// GetState returns the current server and P2P tunnel status.
func (a *App) GetState() RDPState {
	a.mu.Lock()
	stat := a.serverStat
	if a.client != nil && a.client.Connected() {
		stat = "connected"
	}
	state := RDPState{
		ServerState: stat,
		ServerError: a.serverErr,
	}
	if a.fwd != nil {
		state.TunnelActive = true
		state.TunnelMode = a.fwd.Mode
		state.ListenAddr = a.fwd.ListenAddr
		state.RTTMs = a.fwd.RTT.Milliseconds()
		state.TargetClientID = a.fwdTarget
		state.RemoteAddr = a.fwdRemote
	}
	a.mu.Unlock()

	a.logMu.Lock()
	state.Logs = make([]string, len(a.logs))
	copy(state.Logs, a.logs)
	a.logMu.Unlock()
	return state
}

// Write implements io.Writer so iplinkclient logs appear in the UI.
func (a *App) Write(p []byte) (int, error) {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	a.buf.Write(p)
	for {
		line, err := a.buf.ReadString('\n')
		if err != nil {
			a.buf.WriteString(line)
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line != "" {
			a.logs = append(a.logs, line)
			if len(a.logs) > 300 {
				a.logs = a.logs[len(a.logs)-300:]
			}
		}
	}
	return len(p), nil
}

func (a *App) appendLog(msg string) {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	ts := time.Now().Format("15:04:05")
	a.logs = append(a.logs, fmt.Sprintf("[%s] %s", ts, msg))
	if len(a.logs) > 300 {
		a.logs = a.logs[len(a.logs)-300:]
	}
}

