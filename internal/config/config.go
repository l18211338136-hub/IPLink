package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
)

// ServerConfig holds all configuration for the IPLink server.
type ServerConfig struct {
	Server   ServerListenConfig `json:"server"`
	Security SecurityConfig     `json:"security"`
	Relay    RelayConfig        `json:"relay"`
	Metrics  MetricsConfig      `json:"metrics"`
	Logging  LoggingConfig      `json:"logging"`
}

// MetricsConfig configures the built-in Prometheus/JSON metrics endpoint.
type MetricsConfig struct {
	Enabled bool `json:"enabled"`
	Port    int  `json:"port"`
}

// ServerListenConfig configures the server listening addresses and ports.
type ServerListenConfig struct {
	ListenIP      string `json:"listen_ip"`
	ControlPort   int    `json:"control_port"`
	RelayPort     int    `json:"relay_port"`
	NATPort       int    `json:"nat_port"`
	HTTPProxyPort int    `json:"http_proxy_port,omitempty"`
}

// SecurityConfig holds authentication and TLS settings.
type SecurityConfig struct {
	TLSEnabled            bool     `json:"tls_enabled"`
	TLSCertFile           string   `json:"tls_cert_file,omitempty"`
	TLSKeyFile            string   `json:"tls_key_file,omitempty"`
	TLSInsecureSkipVerify bool     `json:"tls_insecure_skip_verify,omitempty"`
	Token                 string   `json:"token"`
	AllowedTargets        []string `json:"allowed_targets,omitempty"`
}

// RelayConfig configures the server relay service.
type RelayConfig struct {
	Enabled        bool  `json:"enabled"`
	MaxSessions    int   `json:"max_sessions"`
	MaxBytesPerSec int64 `json:"max_bytes_per_sec"`
}

// LoggingConfig configures structured logging.
type LoggingConfig struct {
	Level  string `json:"level"`
	Format string `json:"format"`
}

// ClientConfig holds all configuration for the IPLink client.
type ClientConfig struct {
	Client    ClientIdentityConfig `json:"client"`
	Server    ClientServerConfig   `json:"server"`
	Security  SecurityConfig       `json:"security"`
	Network   NetworkConfig        `json:"network"`
	Reconnect ReconnectConfig      `json:"reconnect"`
	Tunnels   []TunnelConfig       `json:"tunnels"`
	Logging   LoggingConfig        `json:"logging"`
}

// ClientIdentityConfig identifies the client.
type ClientIdentityConfig struct {
	ID string `json:"id"`
}

// ClientServerConfig specifies the server IP and ports to connect to.
type ClientServerConfig struct {
	Address   string `json:"address"`
	Port      int    `json:"port"`
	RelayPort int    `json:"relay_port"`
	NATPort   int    `json:"nat_port"`
}

// NetworkConfig enables or disables transport capabilities.
type NetworkConfig struct {
	EnableTCP bool `json:"enable_tcp"`
	EnableUDP bool `json:"enable_udp"`
	EnableP2P bool `json:"enable_p2p"`
}

// ReconnectConfig controls automatic reconnection behavior.
type ReconnectConfig struct {
	Enabled         bool `json:"enabled"`
	MaxAttempts     int  `json:"max_attempts"`
	IntervalSeconds int  `json:"interval_seconds"`
}

// TunnelConfig defines a single port-forwarding or HTTP reverse-proxy tunnel.
type TunnelConfig struct {
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	LocalAddr   string `json:"local_addr"`
	RemoteAddr  string `json:"remote_addr,omitempty"`
	HTTPPath    string `json:"http_path,omitempty"`
	StripPrefix *bool  `json:"strip_prefix,omitempty"`
}

// DefaultServerConfig returns a ServerConfig with sensible defaults.
func DefaultServerConfig() ServerConfig {
	return ServerConfig{
		Server: ServerListenConfig{
			ListenIP:    "0.0.0.0",
			ControlPort: 29000,
			RelayPort:   29001,
			NATPort:     29002,
		},
		Relay: RelayConfig{
			Enabled:     true,
			MaxSessions: 1000,
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Port:    29100,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}
}

// DefaultClientConfig returns a ClientConfig with sensible defaults.
func DefaultClientConfig() ClientConfig {
	return ClientConfig{
		Server: ClientServerConfig{
			Port:      29000,
			RelayPort: 29001,
			NATPort:   29002,
		},
		Network: NetworkConfig{
			EnableTCP: true,
			EnableUDP: true,
			EnableP2P: true,
		},
		Reconnect: ReconnectConfig{
			Enabled:         true,
			MaxAttempts:     0,
			IntervalSeconds: 5,
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}
}

// LoadServerConfig reads, expands env vars in, and validates a JSON server config file.
func LoadServerConfig(path string) (ServerConfig, error) {
	cfg := DefaultServerConfig()
	if err := loadJSONWithEnv(path, &cfg); err != nil {
		return ServerConfig{}, err
	}
	if err := cfg.Validate(); err != nil {
		return ServerConfig{}, err
	}
	return cfg, nil
}

// LoadClientConfig reads, expands env vars in, and validates a JSON client config file.
func LoadClientConfig(path string) (ClientConfig, error) {
	cfg := DefaultClientConfig()
	if err := loadJSONWithEnv(path, &cfg); err != nil {
		return ClientConfig{}, err
	}
	if err := cfg.Validate(); err != nil {
		return ClientConfig{}, err
	}
	return cfg, nil
}

func loadJSONWithEnv(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %q: %w", path, err)
	}
	expanded := os.ExpandEnv(string(data))
	if err := json.Unmarshal([]byte(expanded), target); err != nil {
		return fmt.Errorf("parse config %q: %w", path, err)
	}
	return nil
}

// Validate checks ServerConfig fields for correctness and safe bounds.
func (c *ServerConfig) Validate() error {
	if net.ParseIP(c.Server.ListenIP) == nil {
		return fmt.Errorf("invalid server.listen_ip %q: must be a valid IP address", c.Server.ListenIP)
	}
	if err := validatePort("server.control_port", c.Server.ControlPort); err != nil {
		return err
	}
	if err := validatePort("server.relay_port", c.Server.RelayPort); err != nil {
		return err
	}
	if err := validatePort("server.nat_port", c.Server.NATPort); err != nil {
		return err
	}
	if c.Server.ControlPort == c.Server.RelayPort || c.Server.ControlPort == c.Server.NATPort || c.Server.RelayPort == c.Server.NATPort {
		return errors.New("server control_port, relay_port, and nat_port must be distinct")
	}
	if c.Server.HTTPProxyPort != 0 {
		if err := validatePort("server.http_proxy_port", c.Server.HTTPProxyPort); err != nil {
			return err
		}
		if c.Server.HTTPProxyPort == c.Server.ControlPort || c.Server.HTTPProxyPort == c.Server.RelayPort || c.Server.HTTPProxyPort == c.Server.NATPort {
			return errors.New("server.http_proxy_port must be distinct from control_port, relay_port, and nat_port")
		}
	}
	if c.Metrics.Enabled {
		// 0 表示由内核动态分配端口，便于测试与避免冲突。
		if c.Metrics.Port < 0 || c.Metrics.Port > 65535 {
			return fmt.Errorf("invalid metrics.port %d: must be 0 or between 1 and 65535", c.Metrics.Port)
		}
		if c.Metrics.Port != 0 {
			ports := []int{c.Server.ControlPort, c.Server.RelayPort, c.Server.NATPort}
			if c.Server.HTTPProxyPort != 0 {
				ports = append(ports, c.Server.HTTPProxyPort)
			}
			for _, p := range ports {
				if c.Metrics.Port == p {
					return fmt.Errorf("metrics.port must be distinct from all server ports (got %d)", p)
				}
			}
		}
	}
	if strings.TrimSpace(c.Security.Token) == "" {
		return errors.New("security.token is required")
	}
	if c.Security.TLSEnabled && (c.Security.TLSCertFile == "" || c.Security.TLSKeyFile == "") {
		return errors.New("security.tls_cert_file and security.tls_key_file are required when tls_enabled is true")
	}
	if c.Relay.MaxSessions < 0 {
		return errors.New("relay.max_sessions must be >= 0")
	}
	return nil
}

// Validate checks ClientConfig fields for correctness and IP-first constraints.
func (c *ClientConfig) Validate() error {
	if strings.TrimSpace(c.Client.ID) == "" {
		return errors.New("client.id is required")
	}
	if net.ParseIP(c.Server.Address) == nil {
		return fmt.Errorf("invalid server.address %q: IPLink requires a pure IP address", c.Server.Address)
	}
	if err := validatePort("server.port", c.Server.Port); err != nil {
		return err
	}
	if err := validatePort("server.relay_port", c.Server.RelayPort); err != nil {
		return err
	}
	if err := validatePort("server.nat_port", c.Server.NATPort); err != nil {
		return err
	}
	if strings.TrimSpace(c.Security.Token) == "" {
		return errors.New("security.token is required")
	}
	if c.Reconnect.IntervalSeconds < 0 {
		return errors.New("reconnect.interval_seconds must be >= 0")
	}
	for i, t := range c.Tunnels {
		proto := strings.ToLower(strings.TrimSpace(t.Protocol))
		if proto != "tcp" && proto != "udp" && proto != "http" {
			return fmt.Errorf("tunnels[%d].protocol %q must be tcp, udp, or http", i, t.Protocol)
		}
		if _, _, err := net.SplitHostPort(t.LocalAddr); err != nil {
			return fmt.Errorf("tunnels[%d].local_addr %q: %w", i, t.LocalAddr, err)
		}
		if proto == "http" {
			if !strings.HasPrefix(t.HTTPPath, "/") {
				return fmt.Errorf("tunnels[%d].http_path %q must start with '/'", i, t.HTTPPath)
			}
		} else {
			if _, _, err := net.SplitHostPort(t.RemoteAddr); err != nil {
				return fmt.Errorf("tunnels[%d].remote_addr %q: %w", i, t.RemoteAddr, err)
			}
		}
	}
	return nil
}

func validatePort(name string, port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid %s %d: must be between 1 and 65535", name, port)
	}
	return nil
}
