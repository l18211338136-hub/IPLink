package iplinkclient

import (
	"context"
	"encoding/json"
	"io"
	"os"

	"iplink/internal/client/service"
	"iplink/internal/config"
	"iplink/internal/logger"
	"iplink/internal/protocol/message"
)

// Config aliases the IPLink client configuration.
type Config = config.ClientConfig

// TunnelConfig aliases a single tunnel entry configuration.
type TunnelConfig = config.TunnelConfig

// ActiveTunnel aliases a runtime registered tunnel.
type ActiveTunnel = service.ActiveTunnel

// ServerCapabilities aliases the capabilities advertised by the server.
type ServerCapabilities = message.ServerCapabilities

// ServerInfo aliases the live server capabilities and metrics snapshot.
type ServerInfo = message.ServerInfo

// PeerChannel aliases a P2P or Relay channel established with another client.
type PeerChannel = service.PeerChannel

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

// Connected reports whether the control session is alive (fresh heartbeat acknowledgement).
func (c *Client) Connected() bool {
	return c.svc.Connected()
}

// ServerCapabilities returns what the connected server advertised at authentication.
func (c *Client) ServerCapabilities() (ServerCapabilities, bool) {
	return c.svc.ServerCapabilities()
}

// ServerInfo queries the live server for capabilities and runtime metrics.
func (c *Client) ServerInfo(ctx context.Context) (ServerInfo, error) {
	return c.svc.ServerInfo(ctx)
}

// ListPeers returns the clients currently online on the server.
func (c *Client) ListPeers(ctx context.Context) ([]message.PeerInfo, error) {
	return c.svc.ListPeers(ctx)
}

// ConnectPeer opens a direct or relayed channel to another client.
func (c *Client) ConnectPeer(ctx context.Context, targetClientID string) (*PeerChannel, error) {
	return c.svc.ConnectPeer(ctx, targetClientID)
}

// IncomingPeer returns the channel opened by a remote peer, if any.
func (c *Client) IncomingPeer(peerID string) *PeerChannel {
	return c.svc.IncomingPeer(peerID)
}
