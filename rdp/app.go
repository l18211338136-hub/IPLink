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

	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// RDPConfig persists server and target settings for the standalone remote desktop client.
type RDPConfig struct {
	ServerAddress      string `json:"server_address"`
	ServerPort         int    `json:"server_port"`
	Token              string `json:"token"`
	ClientID           string `json:"client_id"`
	TLSEnabled         bool   `json:"tls_enabled"`
	TLSInsecure        bool   `json:"tls_insecure"`
	TargetClientID     string `json:"target_client_id"`
	RemoteAddr         string `json:"remote_addr"`
	AllowRemoteControl *bool  `json:"allow_remote_control,omitempty"`
}

// PeerItem represents an online peer returned by the server.
type PeerItem struct {
	ClientID   string `json:"client_id"`
	PublicAddr string `json:"public_addr"`
	HasNAT     bool   `json:"has_nat"`
}

// RDPState reports the live connection and P2P tunnel status to the UI.
type RDPState struct {
	ServerState       string   `json:"server_state"` // "disconnected" | "connecting" | "connected"
	ServerError       string   `json:"server_error,omitempty"`
	HostActive        bool     `json:"host_active"`
	TunnelActive      bool     `json:"tunnel_active"`
	TunnelKind        string   `json:"tunnel_kind,omitempty"` // "rdp" | "builtin"
	TunnelMode        string   `json:"tunnel_mode,omitempty"` // "p2p" | "relay"
	ListenAddr        string   `json:"listen_addr,omitempty"`
	ViewerWSURL       string   `json:"viewer_ws_url,omitempty"`
	RTTMs             int64    `json:"rtt_ms,omitempty"`
	TargetClientID    string   `json:"target_client_id,omitempty"`
	RemoteAddr        string   `json:"remote_addr,omitempty"`
	TransferActive    bool     `json:"transfer_active"`
	TransferFile      string   `json:"transfer_file,omitempty"`
	TransferPercent   int      `json:"transfer_percent,omitempty"`
	TransferSpeedKBps int64    `json:"transfer_speed_kbps,omitempty"`
	TransferText      string   `json:"transfer_text,omitempty"`
	Logs              []string `json:"logs"`
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

	host *ScreenHost

	fwd          *iplinkclient.PeerForwarder
	fwdKind      string
	fwdTarget    string
	fwdRemote    string
	viewerBridge *ScreenViewerBridge

	xferActive    bool
	xferFile      string
	xferPercent   int
	xferSpeedKBps int64
	xferText      string

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
	cfg := a.GetConfig()
	if cfg.AllowRemoteControl == nil || *cfg.AllowRemoteControl {
		_, _ = a.SetRemoteControlHost(true)
	}
}

func (a *App) shutdown(_ context.Context) {
	_ = a.DisconnectRemoteDesktop()
	_ = a.DisconnectServer()
	a.mu.Lock()
	h := a.host
	a.host = nil
	a.mu.Unlock()
	if h != nil {
		_ = h.Close()
	}
}

// SetRemoteControlHost starts or stops the local built-in screen sharing host (127.0.0.1:29389).
func (a *App) SetRemoteControlHost(enabled bool) (RDPState, error) {
	cfg := a.GetConfig()
	v := enabled
	cfg.AllowRemoteControl = &v
	_ = a.saveConfig(cfg)

	a.mu.Lock()
	cur := a.host
	a.mu.Unlock()

	if !enabled {
		if cur != nil {
			a.mu.Lock()
			a.host = nil
			a.mu.Unlock()
			_ = cur.Close()
			a.appendLog("已关闭本机内置同屏受控服务")
		}
		return a.GetState(), nil
	}

	if cur != nil {
		return a.GetState(), nil
	}
	h, err := StartScreenHost(a.appendLog)
	if err != nil {
		a.appendLog(fmt.Sprintf("启动本机内置同屏受控服务失败: %v", err))
		return a.GetState(), err
	}
	a.mu.Lock()
	a.host = h
	a.mu.Unlock()
	a.appendLog(fmt.Sprintf("本机内置同屏受控服务已就绪 (%s)", builtinScreenAddr))
	return a.GetState(), nil
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
			if cfg.AllowRemoteControl == nil {
				t := true
				cfg.AllowRemoteControl = &t
			}
			cfg.ClientID = a.defaultClientID
			return cfg
		}
	}

	allowDefault := true
	def := RDPConfig{
		ServerPort:         29000,
		ClientID:           a.defaultClientID,
		TLSEnabled:         false,
		TLSInsecure:        false,
		RemoteAddr:         "127.0.0.1:3389",
		AllowRemoteControl: &allowDefault,
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
	a.fwdKind = "rdp"
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

// ConnectBuiltinScreen establishes a P2P (or Relay fallback) tunnel to targetClientID's
// built-in screen host (127.0.0.1:29389) and starts a local WebSocket bridge for the Canvas viewer.
func (a *App) ConnectBuiltinScreen(targetClientID string) (RDPState, error) {
	targetClientID = strings.TrimSpace(targetClientID)
	if targetClientID == "" {
		return a.GetState(), fmt.Errorf("请填写目标设备 ID")
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
	_ = a.saveConfig(cfg)

	a.appendLog(fmt.Sprintf("正在向 %s 发起内置 P2P 同屏远控 (%s)...", targetClientID, builtinScreenAddr))

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()

	fwd, err := cli.ForwardPeerTCP(ctx, targetClientID, "127.0.0.1:0", builtinScreenAddr)
	if err != nil {
		a.appendLog(fmt.Sprintf("内置 P2P 同屏通道建立失败: %v", err))
		return a.GetState(), err
	}

	bridge, err := StartScreenViewerBridge(fwd.ListenAddr, a.appendLog)
	if err != nil {
		_ = fwd.Close()
		a.appendLog(fmt.Sprintf("启动本地画面桥接失败: %v", err))
		return a.GetState(), err
	}

	a.mu.Lock()
	a.fwd = fwd
	a.fwdKind = "builtin"
	a.fwdTarget = targetClientID
	a.fwdRemote = builtinScreenAddr
	a.viewerBridge = bridge
	a.mu.Unlock()

	a.appendLog(fmt.Sprintf("内置同屏通道就绪 [%s] 目标 %s (RTT: %dms)",
		strings.ToUpper(fwd.Mode), targetClientID, fwd.RTT.Milliseconds()))

	return a.GetState(), nil
}

// DisconnectRemoteDesktop closes the active P2P forwarder and any built-in screen viewer bridge.
func (a *App) DisconnectRemoteDesktop() error {
	a.mu.Lock()
	fwd := a.fwd
	bridge := a.viewerBridge
	a.fwd = nil
	a.fwdKind = ""
	a.fwdTarget = ""
	a.fwdRemote = ""
	a.viewerBridge = nil
	a.mu.Unlock()
	if bridge != nil {
		_ = bridge.Close()
	}
	if fwd != nil {
		_ = fwd.Close()
		a.appendLog("已关闭 P2P 远程桌面通道")
	}
	return nil
}

// OpenReceiveFolder opens ~/Downloads/IPLink in Windows Explorer.
func (a *App) OpenReceiveFolder() error {
	dir, err := defaultReceiveDir()
	if err != nil {
		return err
	}
	return exec.Command("explorer.exe", dir).Start()
}

// PickAndSendFile opens a native file chooser and streams the selected file to targetClientID over P2P/Relay.
func (a *App) PickAndSendFile(targetClientID string) error {
	targetClientID = strings.TrimSpace(targetClientID)

	a.mu.Lock()
	cli := a.client
	if targetClientID == "" {
		targetClientID = a.fwdTarget
	}
	busy := a.xferActive
	reuseAddr := ""
	if a.fwd != nil && a.fwdKind == "builtin" && a.fwdTarget == targetClientID {
		reuseAddr = a.fwd.ListenAddr
	}
	a.mu.Unlock()

	if cli == nil || !cli.Connected() {
		return fmt.Errorf("请先连接服务端")
	}
	if targetClientID == "" {
		return fmt.Errorf("请先选择目标设备 Client ID")
	}
	if busy {
		return fmt.Errorf("当前已有文件正在传输中，请稍候")
	}

	filePath, err := wailsruntime.OpenFileDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "选择要发送到远端电脑的文件",
	})
	if err != nil {
		return err
	}
	if strings.TrimSpace(filePath) == "" {
		return nil // user cancelled
	}

	fileName := filepath.Base(filePath)
	a.mu.Lock()
	if a.xferActive {
		a.mu.Unlock()
		return fmt.Errorf("当前已有文件正在传输中，请稍候")
	}
	reuseAddr = ""
	if a.fwd != nil && a.fwdKind == "builtin" && a.fwdTarget == targetClientID {
		reuseAddr = a.fwd.ListenAddr
	}
	a.xferActive = true
	a.xferFile = fileName
	a.xferPercent = 0
	a.xferSpeedKBps = 0
	a.xferText = fmt.Sprintf("正在连接 %s 准备发送 %s...", targetClientID, fileName)
	a.mu.Unlock()

	go func() {
		var tempFwd *iplinkclient.PeerForwarder
		defer func() {
			if tempFwd != nil {
				_ = tempFwd.Close()
			}
			a.mu.Lock()
			a.xferActive = false
			a.mu.Unlock()
		}()

		listenAddr := reuseAddr
		if listenAddr == "" {
			a.appendLog(fmt.Sprintf("正在向 %s 建立 P2P 文件传输通道...", targetClientID))
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			fwd, fErr := cli.ForwardPeerTCP(ctx, targetClientID, "127.0.0.1:0", builtinScreenAddr)
			cancel()
			if fErr != nil {
				a.appendLog(fmt.Sprintf("建立文件传输通道失败: %v", fErr))
				a.mu.Lock()
				a.xferText = fmt.Sprintf("发送失败: %v", fErr)
				a.mu.Unlock()
				return
			}
			tempFwd = fwd
			listenAddr = fwd.ListenAddr
			a.appendLog(fmt.Sprintf("文件通道就绪 [%s] 开始发送 %s", strings.ToUpper(fwd.Mode), fileName))
		} else {
			a.appendLog(fmt.Sprintf("复用当前 P2P 通道发送文件: %s -> %s", fileName, targetClientID))
		}

		var (
			savedPath string
			sErr      error
		)
		const maxResumeRetries = 3
		for attempt := 1; attempt <= maxResumeRetries; attempt++ {
			savedPath, sErr = sendFileOverAddr(listenAddr, filePath, func(sent, total, speedKBps int64, resumed bool) {
				pct := 100
				if total > 0 {
					pct = int(sent * 100 / total)
				}
				prefix := "发送"
				if resumed {
					prefix = "续传"
				}
				a.mu.Lock()
				a.xferPercent = pct
				a.xferSpeedKBps = speedKBps
				a.xferText = fmt.Sprintf("%s %s: %d%% (%s / %s, %d KB/s)",
					prefix, fileName, pct, formatByteSize(sent), formatByteSize(total), speedKBps)
				a.mu.Unlock()
			})
			if sErr == nil {
				break
			}
			if attempt < maxResumeRetries {
				a.appendLog(fmt.Sprintf("文件传输中断，2秒后自动断点续传 (%d/%d): %v", attempt, maxResumeRetries-1, sErr))
				a.mu.Lock()
				a.xferText = fmt.Sprintf("传输中断，正在自动续传 (%d/%d)...", attempt, maxResumeRetries-1)
				a.mu.Unlock()
				time.Sleep(2 * time.Second)
			}
		}
		if sErr != nil {
			a.appendLog(fmt.Sprintf("文件发送失败 (%s，已保留断点，重新选择同一文件可继续续传): %v", fileName, sErr))
			a.mu.Lock()
			a.xferText = fmt.Sprintf("发送失败（可重选文件断点续传）: %v", sErr)
			a.mu.Unlock()
			return
		}

		a.appendLog(fmt.Sprintf("文件发送成功: %s -> 对端 %s", fileName, savedPath))
		a.mu.Lock()
		a.xferPercent = 100
		a.xferText = fmt.Sprintf("已发送 %s -> 对端 %s", fileName, savedPath)
		a.mu.Unlock()
	}()

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
		ServerState:       stat,
		ServerError:       a.serverErr,
		HostActive:        a.host != nil,
		TransferActive:    a.xferActive,
		TransferFile:      a.xferFile,
		TransferPercent:   a.xferPercent,
		TransferSpeedKBps: a.xferSpeedKBps,
		TransferText:      a.xferText,
	}
	if a.fwd != nil {
		state.TunnelActive = true
		state.TunnelKind = a.fwdKind
		state.TunnelMode = a.fwd.Mode
		state.ListenAddr = a.fwd.ListenAddr
		state.RTTMs = a.fwd.RTT.Milliseconds()
		state.TargetClientID = a.fwdTarget
		state.RemoteAddr = a.fwdRemote
		if a.viewerBridge != nil {
			state.ViewerWSURL = a.viewerBridge.URL
		}
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
