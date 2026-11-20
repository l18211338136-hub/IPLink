package iplinkclient

import (
	"context"
	"encoding/json"
	"io"
	"os"

	"iplink/internal/client/service"
	"iplink/internal/config"
	"iplink/internal/logger"
)

// Config aliases the IPLink client configuration.
type Config = config.ClientConfig

// TunnelConfig aliases a single tunnel entry configuration.
type TunnelConfig = config.TunnelConfig

// ActiveTunnel aliases a runtime registered tunnel.
type ActiveTunnel = service.ActiveTunnel

// DefaultConfig returns a ClientConfig with sensible defaults.
func DefaultConfig() Config {
	return config.DefaultClientConfig()
}

// ParseConfig unmarshals JSON bytes onto DefaultConfig without expanding env vars.
func ParseConfig(data []byte) (Config, error) {
	cfg := config.DefaultClientConfig()
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// ExpandAndValidate expands environment variables in token and validates the config.
func ExpandAndValidate(cfg Config) (Config, error) {
	if cfg.Security.Token != "" {
		cfg.Security.Token = os.ExpandEnv(cfg.Security.Token)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Client wraps the IPLink client service for external/desktop consumers.
type Client struct {
	svc *service.Client
}

// New creates a new Client with the given configuration and log writer.
func New(cfg Config, logOut io.Writer) (*Client, error) {
	log := logger.New(cfg.Logging.Level, cfg.Logging.Format, logOut)
	svc, err := service.New(cfg, log)
	if err != nil {
		return nil, err
	}
	return &Client{svc: svc}, nil
}

// Run connects to the server and maintains the session until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	return c.svc.Run(ctx)
}

// ActiveTunnels returns the currently registered tunnels.
func (c *Client) ActiveTunnels() []ActiveTunnel {
	return c.svc.ActiveTunnels()
}
