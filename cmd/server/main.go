package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"iplink/internal/config"
	"iplink/internal/logger"
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
