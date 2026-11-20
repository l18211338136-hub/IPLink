package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"iplink/internal/config"
	"iplink/internal/logger"
	"iplink/internal/metrics"
	"iplink/internal/server/service"
)

const version = "0.5.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	subcmd := os.Args[1]
	switch subcmd {
	case "start":
		runStart(os.Args[2:])
	case "status":
		runStatus(os.Args[2:])
	case "--version", "-v", "version":
		fmt.Printf("iplink-server %s\n", version)
	case "--help", "-h", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", subcmd)
		printUsage()
		os.Exit(2)
	}
}

func runStart(args []string) {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/server.json", "path to server config file")
	logLevel := fs.String("log-level", "", "override log level (debug|info|warn|error)")
	_ = fs.Parse(args)

	cfg, err := config.LoadServerConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	if *logLevel != "" {
		cfg.Logging.Level = *logLevel
	}
	log := logger.New(cfg.Logging.Level, cfg.Logging.Format, os.Stdout)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := service.New(cfg, log)
	if err := srv.Start(ctx); err != nil {
		log.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/server.json", "path to server config file")
	_ = fs.Parse(args)

	cfg, err := config.LoadServerConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("iplink-server %s\nlisten_ip: %s\ncontrol_port: %d\nrelay_port: %d (enabled=%v)\nnat_port: %d\ntls_enabled: %v\n",
		version, cfg.Server.ListenIP, cfg.Server.ControlPort, cfg.Server.RelayPort, cfg.Relay.Enabled, cfg.Server.NATPort, cfg.Security.TLSEnabled)

	// Query the running server's metrics endpoint for live runtime state.
	// Failure is non-fatal: status still works when the server is stopped or
	// the metrics endpoint is disabled (e.g. dynamic port 0).
	printRuntimeStatus(cfg)
}

// printRuntimeStatus queries the local metrics JSON endpoint and prints a
// runtime snapshot. It silently returns if no server is reachable.
func printRuntimeStatus(cfg config.ServerConfig) {
	if !cfg.Metrics.Enabled || cfg.Metrics.Port == 0 {
		return
	}
	listenIP := cfg.Metrics.ListenIP
	if listenIP == "" || listenIP == "0.0.0.0" || listenIP == "::" {
		listenIP = "127.0.0.1"
	}
	scheme := "http"
	if cfg.Security.TLSEnabled {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/metrics/json", scheme, net.JoinHostPort(listenIP, strconv.Itoa(cfg.Metrics.Port)))

	client := &http.Client{
		Timeout: 2 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // local self-signed server
		},
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return
	}
	if cfg.Metrics.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Metrics.Token)
	}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("runtime: unavailable (server not running or metrics unreachable)")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Printf("runtime: unavailable (metrics endpoint returned %d)\n", resp.StatusCode)
		return
	}
	var snap metrics.Snapshot
	if err := json.NewDecoder(resp.Body).Decode(&snap); err != nil {
		fmt.Printf("runtime: unavailable (bad metrics payload: %v)\n", err)
		return
	}

	fmt.Println("runtime state:")
	fmt.Printf("  online_clients=%d active_sessions=%d active_tunnels=%d relay_sessions=%d\n",
		snap.OnlineClients, snap.ActiveSessions, snap.ActiveTunnels, snap.RelayConnections)
	fmt.Printf("  bytes_sent=%d bytes_received=%d p2p=%d/%d (%.2f)\n",
		snap.BytesSent, snap.BytesReceived, snap.P2PSuccesses, snap.P2PAttempts, snap.P2PSuccessRate)
	if len(snap.Tunnels) == 0 {
		fmt.Println("  tunnels: (none)")
		return
	}
	fmt.Println("  tunnels:")
	for _, t := range snap.Tunnels {
		fmt.Printf("    %s  proto=%s  conns=%d  tx=%d  rx=%d  local=%s\n",
			t.TunnelID, t.Protocol, t.ActiveConns, t.BytesSent, t.BytesReceived, t.LocalAddr)
	}
}

func printUsage() {
	fmt.Println(`IPLink Server - Pure IP Network Tunneling Server

Usage:
  iplink-server <command> [flags]

Commands:
  start       Start the IPLink server
  status      Validate and display server configuration
  version     Print version information
  help        Show this help message`)
}
