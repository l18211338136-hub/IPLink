package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"iplink/internal/client/service"
	"iplink/internal/config"
	"iplink/internal/logger"
)

const version = "0.5.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(2)
	}

	subcmd := os.Args[1]
	switch subcmd {
	case "connect":
		runConnect(os.Args[2:])
	case "status":
		runStatus(os.Args[2:])
	case "peers":
		runPeers(os.Args[2:])
	case "peer":
		runPeer(os.Args[2:])
	case "info":
		runInfo(os.Args[2:])
	case "tunnel":
		runTunnel(os.Args[2:])
	case "--version", "-v", "version":
		fmt.Printf("iplink-client %s\n", version)
	case "--help", "-h", "help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", subcmd)
		printUsage()
		os.Exit(2)
	}
}

func runConnect(args []string) {
	fs := flag.NewFlagSet("connect", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/client.json", "path to client config file")
	logLevel := fs.String("log-level", "", "override log level (debug|info|warn|error)")
	_ = fs.Parse(args)

	cfg, err := config.LoadClientConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	if *logLevel != "" {
		cfg.Logging.Level = *logLevel
	}
	log := logger.New(cfg.Logging.Level, cfg.Logging.Format, os.Stdout)

	cli, err := service.New(cfg, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init client error: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cli.Run(ctx); err != nil && ctx.Err() == nil {
		log.Error("client exited with error", "err", err)
		os.Exit(1)
	}
}

func runStatus(args []string) {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/client.json", "path to client config file")
	_ = fs.Parse(args)

	cfg, err := config.LoadClientConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("iplink-client %s\nclient_id: %s\nserver: %s:%d\ntls_enabled: %v\np2p_enabled: %v\nconfigured_tunnels: %d\n",
		version, cfg.Client.ID, cfg.Server.Address, cfg.Server.Port, cfg.Security.TLSEnabled, cfg.Network.EnableP2P, len(cfg.Tunnels))
}

func runPeers(args []string) {
	fs := flag.NewFlagSet("peers", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/client.json", "path to client config file")
	_ = fs.Parse(args)

	cfg, err := config.LoadClientConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	cfg.Tunnels = nil
	log := logger.New("warn", "text", os.Stderr)
	cli, err := service.New(cfg, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init client error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	doneCh, err := cli.Start(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect error: %v\n", err)
		os.Exit(1)
	}
	peers, err := cli.ListPeers(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "list peers error: %v\n", err)
		os.Exit(1)
	}
	for _, p := range peers {
		fmt.Printf("- %s (session=%d, public=%s, local=%s)\n", p.ClientID, p.SessionID, p.PublicAddr, p.LocalAddr)
	}
	cancel()
	<-doneCh
}

func runPeer(args []string) {
	if len(args) < 2 || args[0] != "ping" {
		fmt.Fprintln(os.Stderr, "usage: iplink-client peer ping <clientID> [--config path] [--timeout seconds]")
		os.Exit(2)
	}
	target := args[1]

	fs := flag.NewFlagSet("peer ping", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/client.json", "path to client config file")
	timeoutSec := fs.Int("timeout", 10, "overall timeout in seconds")
	_ = fs.Parse(args[2:])

	cfg, err := config.LoadClientConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	cfg.Tunnels = nil
	log := logger.New("warn", "text", os.Stderr)
	cli, err := service.New(cfg, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init client error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(*timeoutSec)*time.Second)
	defer cancel()

	doneCh, err := cli.Start(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect error: %v\n", err)
		os.Exit(1)
	}

	ch, err := cli.ConnectPeer(ctx, target)
	if err != nil {
		cancel()
		<-doneCh
		fmt.Fprintf(os.Stderr, "connect peer %s error: %v\n", target, err)
		os.Exit(1)
	}
	defer ch.Close()

	rtt, err := ch.Ping(ctx)
	if err != nil {
		cancel()
		<-doneCh
		fmt.Fprintf(os.Stderr, "ping %s error: %v\n", target, err)
		os.Exit(1)
	}
	fmt.Printf("peer: %s\nmode: %s\nrtt: %s\n", target, ch.Mode, rtt.Round(time.Microsecond))

	cancel()
	<-doneCh
}

func runInfo(args []string) {
	fs := flag.NewFlagSet("info", flag.ExitOnError)
	cfgPath := fs.String("config", "configs/client.json", "path to client config file")
	_ = fs.Parse(args)

	cfg, err := config.LoadClientConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	cfg.Tunnels = nil
	log := logger.New("warn", "text", os.Stderr)
	cli, err := service.New(cfg, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init client error: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	doneCh, err := cli.Start(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "connect error: %v\n", err)
		os.Exit(1)
	}
	info, err := cli.ServerInfo(ctx)
	cancel()
	<-doneCh
	if err != nil {
		fmt.Fprintf(os.Stderr, "query server info error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("protocol_version: %d\n", info.Capabilities.ProtocolVersion)
	fmt.Printf("relay: enabled=%v port=%d\n", info.Capabilities.RelayEnabled, info.Capabilities.RelayPort)
	fmt.Printf("nat: enabled=%v port=%d\n", info.Capabilities.NATEnabled, info.Capabilities.NATPort)
	fmt.Printf("http_proxy: enabled=%v port=%d\n", info.Capabilities.HTTPProxyEnabled, info.Capabilities.HTTPProxyPort)
	fmt.Printf("metrics: enabled=%v port=%d\n", info.Capabilities.MetricsEnabled, info.Capabilities.MetricsPort)
	fmt.Printf("online_clients: %d\nactive_sessions: %d\nactive_tunnels: %d\n",
		info.Metrics.OnlineClients, info.Metrics.ActiveSessions, info.Metrics.ActiveTunnels)
	fmt.Printf("relay_connections: %d\nbytes_sent: %d\nbytes_received: %d\n",
		info.Metrics.RelayConnections, info.Metrics.BytesSent, info.Metrics.BytesReceived)
	fmt.Printf("p2p: attempts=%d successes=%d success_rate=%.2f\n",
		info.Metrics.P2PAttempts, info.Metrics.P2PSuccesses, info.Metrics.P2PSuccessRate)
	if len(info.Metrics.Tunnels) > 0 {
		fmt.Println("tunnels:")
		for _, t := range info.Metrics.Tunnels {
			fmt.Printf("  %s  proto=%s  conns=%d  tx=%d  rx=%d  local=%s\n",
				t.TunnelID, t.Protocol, t.ActiveConns, t.BytesSent, t.BytesReceived, t.LocalAddr)
		}
	}
}

func runTunnel(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: iplink-client tunnel <tcp|udp|http> --local <ip:port> [--remote <ip:port> | --path </prefix>] [--config path]")
		os.Exit(2)
	}
	proto := args[0]
	if proto != "tcp" && proto != "udp" && proto != "http" {
		fmt.Fprintf(os.Stderr, "unsupported tunnel protocol %q (must be tcp, udp, or http)\n", proto)
		os.Exit(2)
	}

	fs := flag.NewFlagSet("tunnel "+proto, flag.ExitOnError)
	cfgPath := fs.String("config", "configs/client.json", "path to client config file")
	localAddr := fs.String("local", "", "local target ip:port")
	remoteAddr := fs.String("remote", "0.0.0.0:0", "remote listen ip:port on server (for tcp/udp)")
	httpPath := fs.String("path", "/", "HTTP reverse proxy path prefix (for http)")
	stripPrefix := fs.Bool("strip-prefix", true, "strip matched http_path prefix before forwarding")
	name := fs.String("name", proto+"-tunnel", "tunnel name")
	logLevel := fs.String("log-level", "", "override log level")
	_ = fs.Parse(args[1:])

	if *localAddr == "" {
		fmt.Fprintln(os.Stderr, "--local is required")
		os.Exit(2)
	}

	cfg, err := config.LoadClientConfig(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}
	if *logLevel != "" {
		cfg.Logging.Level = *logLevel
	}
	tc := config.TunnelConfig{
		Name:        *name,
		Protocol:    proto,
		LocalAddr:   *localAddr,
		RemoteAddr:  *remoteAddr,
		HTTPPath:    *httpPath,
		StripPrefix: stripPrefix,
	}
	cfg.Tunnels = []config.TunnelConfig{tc}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	log := logger.New(cfg.Logging.Level, cfg.Logging.Format, os.Stdout)
	cli, err := service.New(cfg, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init client error: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := cli.Run(ctx); err != nil && ctx.Err() == nil {
		log.Error("tunnel exited with error", "err", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`IPLink Client - Pure IP Network Tunneling Client

Usage:
  iplink-client <command> [flags]

Commands:
  connect                Connect to IPLink server and start configured tunnels
  tunnel <tcp|udp|http>  Start a single TCP, UDP, or HTTP tunnel
  status                 Validate and display client configuration
  peers                  Show online peer clients
  peer ping <clientID>   Open a peer channel and measure round-trip time
  info                   Query server capabilities and runtime metrics
  version                Print version information
  help                   Show this help message`)
}
