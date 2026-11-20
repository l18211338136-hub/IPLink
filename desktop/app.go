package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
	"iplink/pkg/iplinkclient"
)

const maxLogLines = 500

// StatusInfo represents the live connection state sent to the frontend.
type StatusInfo struct {
	State         string                      `json:"state"` // "disconnected" | "connecting" | "connected" | "reconnecting"
	Error         string                      `json:"error,omitempty"`
	ActiveTunnels []iplinkclient.ActiveTunnel `json:"active_tunnels"`
}

// App exposes IPLink desktop operations to the Wails frontend.
type App struct {
	ctx          context.Context
	configPath   string
	forwardsPath string
	forwards     *LocalForwardManager

	mu        sync.Mutex
	state     string
	lastErr   string
	client    *iplinkclient.Client
	cancelRun context.CancelFunc
	runDone   chan struct{}

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
	app := &App{
		configPath:   filepath.Join(cfgDir, "IPLink", "client.json"),
		forwardsPath: filepath.Join(cfgDir, "IPLink", "local_forwards.json"),
		state:        "disconnected",
	}
	app.forwards = NewLocalForwardManager(app.appendLog)
	return app
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	rules := a.GetLocalForwards()
	a.forwards.Apply(rules)
}

func (a *App) shutdown(_ context.Context) {
	a.forwards.StopAll()
	_ = a.Disconnect()
}

// GetConfig loads the saved configuration or returns sensible defaults.
func (a *App) GetConfig() iplinkclient.Config {
	data, err := os.ReadFile(a.configPath)
	if err == nil {
		if cfg, parseErr := iplinkclient.ParseConfig(data); parseErr == nil {
			return cfg
		}
	}
	cfg := iplinkclient.DefaultConfig()
	cfg.Client.ID = "windows-client-001"
	cfg.Security.AllowedTargets = []string{"127.0.0.1:*"}
	return cfg
}

// SaveConfig persists the configuration to disk.
func (a *App) SaveConfig(cfg iplinkclient.Config) error {
	if err := os.MkdirAll(filepath.Dir(a.configPath), 0o755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	return os.WriteFile(a.configPath, append(data, '\n'), 0o600)
}

// Connect validates the config, persists it, and starts the IPLink client in the background.
func (a *App) Connect(cfg iplinkclient.Config) error {
	// Validate before writing to disk so an invalid config never overwrites
	// the user's last known-good configuration.
	expanded, err := iplinkclient.ExpandAndValidate(cfg)
	if err != nil {
		return err
	}
	if err := a.SaveConfig(cfg); err != nil {
		return err
	}

	a.mu.Lock()
	if a.cancelRun != nil {
		a.mu.Unlock()
		return fmt.Errorf("client is already running")
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
	a.state = "connecting"
	a.lastErr = ""
	a.mu.Unlock()

	a.appendLog(fmt.Sprintf("level=INFO msg=\"starting IPLink client\" server=%s:%d client_id=%s",
		expanded.Server.Address, expanded.Server.Port, expanded.Client.ID))
	a.emitStatus()

	go a.pollStatusLoop(runCtx, cli)

	go func() {
		defer close(done)
		err := cli.Run(runCtx)
		cancel() // 停止状态轮询，避免 goroutine 泄漏

		a.mu.Lock()
		a.cancelRun = nil
		a.client = nil
		a.runDone = nil
		a.state = "disconnected"
		if err != nil && runCtx.Err() == nil {
			a.lastErr = err.Error()
		}
		a.mu.Unlock()

		if err != nil && runCtx.Err() == nil {
			a.appendLog(fmt.Sprintf("level=ERROR msg=\"client stopped\" err=%q", err.Error()))
		} else {
			a.appendLog("level=INFO msg=\"client disconnected\"")
		}
		a.emitStatus()
	}()

	return nil
}

// Disconnect stops the running IPLink client.
func (a *App) Disconnect() error {
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

// GetStatus returns the current connection state and active tunnels.
func (a *App) GetStatus() StatusInfo {
	a.mu.Lock()
	info := StatusInfo{
		State:         a.state,
		Error:         a.lastErr,
		ActiveTunnels: []iplinkclient.ActiveTunnel{},
	}
	cli := a.client
	a.mu.Unlock()

	if cli != nil {
		info.ActiveTunnels = cli.ActiveTunnels()
	}
	return info
}

// GetLogs returns all buffered log lines.
func (a *App) GetLogs() []string {
	a.logMu.Lock()
	defer a.logMu.Unlock()
	out := make([]string, len(a.logs))
	copy(out, a.logs)
	return out
}

// ClearLogs clears the buffered log lines.
func (a *App) ClearLogs() {
	a.logMu.Lock()
	a.logs = nil
	a.logMu.Unlock()
}

// GetLocalForwards loads saved local port forwarding rules.
func (a *App) GetLocalForwards() []LocalForwardRule {
	data, err := os.ReadFile(a.forwardsPath)
	if err != nil {
		return []LocalForwardRule{}
	}
	var rules []LocalForwardRule
	if err := json.Unmarshal(data, &rules); err != nil {
		return []LocalForwardRule{}
	}
	return rules
}

// SaveAndApplyLocalForwards persists local port forwarding rules and restarts listeners.
func (a *App) SaveAndApplyLocalForwards(rules []LocalForwardRule) ([]LocalForwardStatus, error) {
	if err := os.MkdirAll(filepath.Dir(a.forwardsPath), 0o755); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal local forwards: %w", err)
	}
	if err := os.WriteFile(a.forwardsPath, append(data, '\n'), 0o600); err != nil {
		return nil, err
	}
	a.forwards.Apply(rules)
	return a.forwards.Statuses(), nil
}

// GetLocalForwardStatuses returns runtime statuses of local port forwarders.
func (a *App) GetLocalForwardStatuses() []LocalForwardStatus {
	return a.forwards.Statuses()
}

// ImportConfig opens a file dialog to import a client.json file.
func (a *App) ImportConfig() (*iplinkclient.Config, error) {
	if a.ctx == nil {
		return nil, fmt.Errorf("app not ready")
	}
	path, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "导入 client.json 配置",
		Filters: []runtime.FileFilter{
			{DisplayName: "JSON 配置文件 (*.json)", Pattern: "*.json"},
			{DisplayName: "所有文件 (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil || path == "" {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := iplinkclient.ParseConfig(data)
	if err != nil {
		return nil, fmt.Errorf("解析配置失败: %w", err)
	}
	if err := a.SaveConfig(cfg); err != nil {
		return nil, fmt.Errorf("保存配置失败: %w", err)
	}
	return &cfg, nil
}

// ExportConfig opens a save dialog to export client.json.
func (a *App) ExportConfig(cfg iplinkclient.Config) (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("app not ready")
	}
	path, err := runtime.SaveFileDialog(a.ctx, runtime.SaveDialogOptions{
		Title:           "导出 client.json 配置",
		DefaultFilename: "client.json",
		Filters: []runtime.FileFilter{
			{DisplayName: "JSON 配置文件 (*.json)", Pattern: "*.json"},
		},
	})
	if err != nil || path == "" {
		return "", err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// Write implements io.Writer so slog output streams directly to the UI log panel.
func (a *App) Write(p []byte) (int, error) {
	a.logMu.Lock()
	a.buf.Write(p)
	var lines []string
	for {
		line, err := a.buf.ReadString('\n')
		if err != nil {
			if line != "" {
				a.buf.WriteString(line)
			}
			break
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed != "" {
			lines = append(lines, trimmed)
		}
	}
	a.logMu.Unlock()

	for _, line := range lines {
		a.appendLog(line)
	}
	return len(p), nil
}

func (a *App) appendLog(line string) {
	a.logMu.Lock()
	a.logs = append(a.logs, line)
	if len(a.logs) > maxLogLines {
		a.logs = a.logs[len(a.logs)-maxLogLines:]
	}
	a.logMu.Unlock()

	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "iplink:log", line)
	}
}

func (a *App) emitStatus() {
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "iplink:status", a.GetStatus())
	}
}

func (a *App) pollStatusLoop(ctx context.Context, cli *iplinkclient.Client) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// 状态由实时连接健康度决定，不再靠匹配日志文本。
			alive := cli.Connected()
			a.mu.Lock()
			if a.client == cli && a.cancelRun != nil {
				switch {
				case alive:
					if a.state != "connected" {
						a.state = "connected"
						a.lastErr = ""
					}
				case a.state == "connected":
					a.state = "reconnecting"
				}
			}
			a.mu.Unlock()
			a.emitStatus()
		}
	}
}
