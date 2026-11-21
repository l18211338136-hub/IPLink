package service

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"iplink/internal/config"
	"iplink/internal/metrics"
	"iplink/internal/nat/discovery"
	"iplink/internal/nat/punching"
	"iplink/internal/protocol/codec"
	"iplink/internal/protocol/frame"
	"iplink/internal/protocol/message"
	relaymgr "iplink/internal/relay/manager"
	"iplink/internal/security/auth"
	clientcrypto "iplink/internal/security/crypto"
	"iplink/internal/security/identity"
	tcptransport "iplink/internal/transport/tcp"
	"iplink/pkg/protocol"
)

const (
	heartbeatInterval   = 20 * time.Second
	missedPongLimit     = 3 // 连续 3 次心跳无 PONG 判定链路半开（默认 60s）
	streamQueueSize     = 64
	readChunkSize       = 32 * 1024
	udpIdleTimeout      = 60 * time.Second
	peerRecvQueueSize   = 64
	peerPingInterval    = 300 * time.Millisecond
	peerPingTimeout     = 3 * time.Second
	peerPingPrefix      = "IPLINK_PING:"
	peerPongPrefix      = "IPLINK_PONG:"
	peerRelayJoinPrefix = "IPLINK_JOIN:"
)

// ActiveTunnel records a tunnel registered with the server.
type ActiveTunnel struct {
	TunnelID  string `json:"tunnel_id"`
	Name      string `json:"name"`
	Protocol  string `json:"protocol"`
	LocalAddr string `json:"local_addr"`
	BoundAddr string `json:"bound_addr"`
}

// Client manages the control connection, authentication, tunnels, P2P, and reconnects.
type Client struct {
	cfg       config.ClientConfig
	log       *slog.Logger
	metrics   *metrics.Metrics
	validator *identity.TargetValidator

	mu        sync.RWMutex
	conn      net.Conn
	sessionID uint64
	writeMu   sync.Mutex
	tunnels   map[string]ActiveTunnel // tunnelID -> ActiveTunnel
	localMap  map[string]string       // tunnelID -> localAddr

	reqMu   sync.Mutex
	nextReq atomic.Uint64
	pending map[uint64]chan frame.Frame

	streamsMu sync.RWMutex
	streams   map[uint64]*localStream

	udpMu    sync.Mutex
	udpPeers map[string]*udpPeerConn // "tunnelID|peerAddr" -> local UDP conn

	peerMu   sync.Mutex
	incoming map[string]*PeerChannel // peerID -> channel opened by remote peer

	caps       message.ServerCapabilities
	capsKnown  bool
	publicAddr string

	lastPong atomic.Int64 // UnixNano，最近一次收到 HeartbeatPong 的时间

	// dgramCipher 加密 NAT 探测、P2P 打洞与 PeerChannel/Relay 数据报。
	dgramCipher *clientcrypto.DatagramCipher
}

type localStream struct {
	connID    uint64
	conn      net.Conn
	sendCh    chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

type udpPeerConn struct {
	key        string
	tunnelID   string
	peerAddr   string
	conn       *net.UDPConn
	lastActive atomic.Int64
}

// New creates a new IPLink Client.
func New(cfg config.ClientConfig, log *slog.Logger) (*Client, error) {
	v, err := identity.NewTargetValidator(cfg.Security.AllowedTargets)
	if err != nil {
		return nil, err
	}
	dc, err := clientcrypto.NewDatagramCipher(cfg.Security.Token)
	if err != nil {
		return nil, fmt.Errorf("derive datagram cipher: %w", err)
	}
	return &Client{
		cfg:         cfg,
		log:         log,
		metrics:     &metrics.Metrics{},
		validator:   v,
		tunnels:     make(map[string]ActiveTunnel),
		localMap:    make(map[string]string),
		pending:     make(map[uint64]chan frame.Frame),
		streams:     make(map[uint64]*localStream),
		udpPeers:    make(map[string]*udpPeerConn),
		incoming:    make(map[string]*PeerChannel),
		dgramCipher: dc,
	}, nil
}

// Run connects to the server and maintains the session with automatic reconnection until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	attempts := 0
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		attempts++
		err := c.connectAndServe(ctx)
		if ctx.Err() != nil {
			return nil
		}
		c.log.Warn("client disconnected", "err", err)

		if !c.cfg.Reconnect.Enabled {
			return err
		}
		if c.cfg.Reconnect.MaxAttempts > 0 && attempts >= c.cfg.Reconnect.MaxAttempts {
			return fmt.Errorf("max reconnect attempts (%d) reached: %w", c.cfg.Reconnect.MaxAttempts, err)
		}
		interval := time.Duration(c.cfg.Reconnect.IntervalSeconds) * time.Second
		if interval <= 0 {
			interval = 5 * time.Second
		}
		c.log.Info("reconnecting", "delay", interval)
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

// ConnectOnce connects, authenticates, and registers configured tunnels, returning when ready.
// Callers must cancel ctx to stop the background serve loop.
func (c *Client) ConnectOnce(ctx context.Context) error {
	var tlsConfig *tls.Config
	if c.cfg.Security.TLSEnabled {
		tlsConfig = clientcrypto.BuildClientTLSConfig(c.cfg.Security.TLSInsecureSkipVerify)
	}
	addr := fmt.Sprintf("%s:%d", c.cfg.Server.Address, c.cfg.Server.Port)
	conn, err := tcptransport.Dial(ctx, addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("dial server %s: %w", addr, err)
	}

	sessID, err := c.authenticate(conn)
	if err != nil {
		_ = conn.Close()
		return err
	}

	c.mu.Lock()
	c.conn = conn
	c.sessionID = sessID
	c.tunnels = make(map[string]ActiveTunnel)
	c.localMap = make(map[string]string)
	c.mu.Unlock()
	c.lastPong.Store(time.Now().UnixNano()) // 认证完成即视为链路存活，Connected() 立即可用

	c.log.Info("connected to IPLink server", "server", addr, "client_id", c.cfg.Client.ID, "session_id", sessID)

	if natAddr := c.natEndpoint(); c.cfg.Network.EnableP2P && natAddr != "" {
		if nonce, err := auth.GenerateNonce(); err == nil {
			probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			if pub, err := discovery.DiscoverPublicAddr(probeCtx, nil, natAddr, c.cfg.Client.ID, nonce, c.dgramCipher); err == nil {
				c.mu.Lock()
				c.publicAddr = pub
				c.mu.Unlock()
				c.log.Debug("discovered public UDP address", "public_addr", pub)
			}
			cancel()
		}
	}

	return nil
}

// Start connects, authenticates, starts background loops, and registers configured tunnels.
// It returns a channel that receives the terminal error when the session ends.
func (c *Client) Start(ctx context.Context) (<-chan error, error) {
	if err := c.ConnectOnce(ctx); err != nil {
		return nil, err
	}

	serveCtx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	readErrCh := make(chan error, 1)
	doneCh := make(chan error, 1)

	wg.Add(1)
	go func() {
		defer wg.Done()
		readErrCh <- c.readLoop(serveCtx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.heartbeatLoop(serveCtx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		c.reapIdleUDP(serveCtx)
	}()

	for _, t := range c.cfg.Tunnels {
		if !c.tunnelEnabled(t) {
			c.log.Debug("skipping tunnel disabled by network config", "tunnel", t.Name, "protocol", t.Protocol)
			continue
		}
		if _, err := c.RegisterTunnel(serveCtx, t); err != nil {
			cancel()
			c.cleanupSession()
			wg.Wait()
			return nil, err
		}
	}

	go func() {
		var retErr error
		select {
		case <-ctx.Done():
			retErr = ctx.Err()
		case retErr = <-readErrCh:
		}
		cancel()
		c.cleanupSession()
		wg.Wait()
		doneCh <- retErr
		close(doneCh)
	}()

	return doneCh, nil
}

func (c *Client) connectAndServe(ctx context.Context) error {
	doneCh, err := c.Start(ctx)
	if err != nil {
		return err
	}
	return <-doneCh
}

// tunnelEnabled reports whether the network config allows this tunnel's protocol.
func (c *Client) tunnelEnabled(t config.TunnelConfig) bool {
	switch strings.ToLower(strings.TrimSpace(t.Protocol)) {
	case "tcp", "http":
		return c.cfg.Network.EnableTCP
	case "udp":
		return c.cfg.Network.EnableUDP
	default:
		return true // 未知协议交给服务端校验报错
	}
}

// RegisterTunnel requests the server to open a TCP or UDP tunnel and maps it to local_addr.
func (c *Client) RegisterTunnel(ctx context.Context, t config.TunnelConfig) (ActiveTunnel, error) {
	if !c.tunnelEnabled(t) {
		proto := strings.ToLower(strings.TrimSpace(t.Protocol))
		return ActiveTunnel{}, fmt.Errorf("tunnel protocol %q is disabled by network config", proto)
	}
	if err := c.validator.Allow(t.LocalAddr); err != nil {
		return ActiveTunnel{}, err
	}
	stripPrefix := true
	if t.StripPrefix != nil {
		stripPrefix = *t.StripPrefix
	}
	req := message.TunnelCreate{
		Name:        t.Name,
		Protocol:    t.Protocol,
		LocalAddr:   t.LocalAddr,
		RemoteAddr:  t.RemoteAddr,
		HTTPPath:    t.HTTPPath,
		StripPrefix: stripPrefix,
	}
	respFrame, err := c.sendRequest(ctx, protocol.MsgTunnelCreate, req)
	if err != nil {
		return ActiveTunnel{}, err
	}
	var ack message.TunnelCreateAck
	if err := codec.DecodeJSON(respFrame, &ack); err != nil {
		return ActiveTunnel{}, err
	}
	if !ack.Success {
		return ActiveTunnel{}, fmt.Errorf("create tunnel %q failed: %s", t.Name, ack.Error)
	}

	at := ActiveTunnel{
		TunnelID:  ack.TunnelID,
		Name:      t.Name,
		Protocol:  strings.ToLower(t.Protocol),
		LocalAddr: t.LocalAddr,
		BoundAddr: ack.BoundAddr,
	}
	c.mu.Lock()
	c.tunnels[ack.TunnelID] = at
	c.localMap[ack.TunnelID] = t.LocalAddr
	c.mu.Unlock()

	c.log.Info("tunnel registered", "name", t.Name, "protocol", at.Protocol, "bound", at.BoundAddr, "local", at.LocalAddr)
	return at, nil
}

// ActiveTunnels returns a snapshot of registered tunnels.
func (c *Client) ActiveTunnels() []ActiveTunnel {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]ActiveTunnel, 0, len(c.tunnels))
	for _, t := range c.tunnels {
		out = append(out, t)
	}
	return out
}

// ListPeers queries the server for online peer clients.
func (c *Client) ListPeers(ctx context.Context) ([]message.PeerInfo, error) {
	respFrame, err := c.sendRequest(ctx, protocol.MsgPeerListReq, message.PeerListReq{})
	if err != nil {
		return nil, err
	}
	var resp message.PeerListResp
	if err := codec.DecodeJSON(respFrame, &resp); err != nil {
		return nil, err
	}
	return resp.Peers, nil
}

// PeerChannel represents an established P2P or Relay UDP channel to a peer.
type PeerChannel struct {
	Mode       string // "p2p" or "relay"
	PeerID     string
	Conn       net.PacketConn
	PeerAddr   net.Addr
	RelayID    string
	relayToken string

	cipher    *clientcrypto.DatagramCipher
	recvCh    chan []byte
	pongCh    chan []byte
	done      chan struct{}
	closeOnce sync.Once
}

func newPeerChannel(mode, peerID string, conn net.PacketConn, peerAddr net.Addr, relayID, relayToken string, cipher *clientcrypto.DatagramCipher) *PeerChannel {
	ch := &PeerChannel{
		Mode:       mode,
		PeerID:     peerID,
		Conn:       conn,
		PeerAddr:   peerAddr,
		RelayID:    relayID,
		relayToken: relayToken,
		cipher:     cipher,
		recvCh:     make(chan []byte, peerRecvQueueSize),
		pongCh:     make(chan []byte, 8),
		done:       make(chan struct{}),
	}
	go ch.readLoop()
	return ch
}

func (ch *PeerChannel) readLoop() {
	buf := make([]byte, protocol.MaxUDPPacketSize)
	for {
		n, _, err := ch.Conn.ReadFrom(buf)
		if err != nil {
			ch.Close()
			return
		}
		payload := buf[:n]
		if ch.Mode == "relay" {
			sid, body, err := relaymgr.DecodeRelayPacket(payload, ch.relayToken)
			if err != nil || sid != ch.RelayID {
				continue
			}
			payload = body
		}
		plain, err := ch.cipher.Open(payload)
		if err != nil {
			continue // 非本通道密文或篡改包
		}
		if punching.IsPunchPacket(plain) {
			continue // 打洞阶段的残留包
		}
		if bytes.HasPrefix(plain, []byte(peerRelayJoinPrefix)) {
			continue // relay 建连控制包，不投递给业务层
		}
		if bytes.HasPrefix(plain, []byte(peerPingPrefix)) {
			reply := append([]byte(peerPongPrefix), plain[len(peerPingPrefix):]...)
			_ = ch.Send(reply)
			continue
		}
		if bytes.HasPrefix(plain, []byte(peerPongPrefix)) {
			select {
			case ch.pongCh <- plain:
			case <-ch.done:
				return
			default:
			}
			continue
		}
		cp := append([]byte(nil), plain...)
		select {
		case ch.recvCh <- cp:
		case <-ch.done:
			return
		default:
		}
	}
}

// Send writes payload to the peer, adding the relay session header when needed.
func (ch *PeerChannel) Send(payload []byte) error {
	select {
	case <-ch.done:
		return net.ErrClosed
	default:
	}
	sealed := ch.cipher.Seal(payload)
	data := sealed
	if ch.Mode == "relay" {
		data = relaymgr.EncodeRelayPacket(ch.RelayID, ch.relayToken, sealed)
	}
	_, err := ch.Conn.WriteTo(data, ch.PeerAddr)
	return err
}

// Receive reads the next payload from the peer, honoring ctx cancellation.
func (ch *PeerChannel) Receive(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-ch.done:
		return nil, net.ErrClosed
	case p := <-ch.recvCh:
		return p, nil
	}
}

// Ping measures round-trip time over the channel; the remote peer replies automatically.
func (ch *PeerChannel) Ping(ctx context.Context) (time.Duration, error) {
	start := time.Now()
	token := strconv.FormatInt(start.UnixNano(), 10)
	probe := append([]byte(peerPingPrefix), token...)
	want := append([]byte(peerPongPrefix), token...)
	deadline := time.Now().Add(peerPingTimeout)
	ticker := time.NewTicker(peerPingInterval)
	defer ticker.Stop()

	if err := ch.Send(probe); err != nil {
		return 0, err
	}
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-ch.done:
			return 0, net.ErrClosed
		case <-ticker.C:
			if time.Now().After(deadline) {
				return 0, fmt.Errorf("peer ping timeout after %s", peerPingTimeout)
			}
			_ = ch.Send(probe)
		case p := <-ch.pongCh:
			if bytes.Equal(p, want) {
				return time.Since(start), nil
			}
		}
	}
}

// Close releases the channel's socket and background reader.
func (ch *PeerChannel) Close() error {
	var err error
	ch.closeOnce.Do(func() {
		close(ch.done)
		err = ch.Conn.Close()
	})
	return err
}

// RegisterIncoming stores a channel opened by a remote peer. A direct channel
// always wins over a relay channel for the same peer.
func (c *Client) RegisterIncoming(peerID string, ch *PeerChannel) {
	c.peerMu.Lock()
	old := c.incoming[peerID]
	if old == nil || (old.Mode == "relay" && ch.Mode == "p2p") {
		c.incoming[peerID] = ch
		c.peerMu.Unlock()
		if old != nil {
			_ = old.Close()
		}
		return
	}
	c.peerMu.Unlock()
	_ = ch.Close()
}

// IncomingPeer returns the channel opened by peerID, if any.
func (c *Client) IncomingPeer(peerID string) *PeerChannel {
	c.peerMu.Lock()
	defer c.peerMu.Unlock()
	return c.incoming[peerID]
}

// ConnectPeer attempts Direct-First UDP hole punching to targetClientID, falling back to Server Relay.
func (c *Client) ConnectPeer(ctx context.Context, targetClientID string) (*PeerChannel, error) {
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, err
	}
	closePC := func() { _ = pc.Close() }

	var myPub string
	if natAddr := c.natEndpoint(); c.cfg.Network.EnableP2P && natAddr != "" {
		if nonce, err := auth.GenerateNonce(); err == nil {
			if pub, err := discovery.DiscoverPublicAddr(ctx, pc, natAddr, c.cfg.Client.ID, nonce, c.dgramCipher); err == nil {
				myPub = pub
			}
		}
	}

	if c.cfg.Network.EnableP2P {
		c.metrics.P2PAttempts.Add(1)
		respFrame, err := c.sendRequest(ctx, protocol.MsgPeerConnectReq, message.PeerConnectReq{
			TargetClientID: targetClientID,
			MyPublicAddr:   myPub,
			MyLocalAddr:    pc.LocalAddr().String(),
		})
		if err == nil && respFrame.Header.Type == protocol.MsgPeerConnectInfo {
			var info message.PeerConnectInfo
			if codec.DecodeJSON(respFrame, &info) == nil {
				peerAddr, punchErr := punching.Punch(ctx, pc, info.PunchToken, []string{info.PeerPublicAddr, info.PeerLocalAddr}, c.dgramCipher)
				if punchErr == nil {
					c.metrics.P2PSuccesses.Add(1)
					return newPeerChannel("p2p", targetClientID, pc, peerAddr, "", "", c.dgramCipher), nil
				}
				c.log.Info("P2P punching failed, falling back to relay", "peer", targetClientID, "err", punchErr)
			}
		}
	}

	// Fallback to Server Relay. Skip the round-trip when the server advertised it as disabled.
	c.mu.RLock()
	relayEnabled, capsKnown := c.caps.RelayEnabled, c.capsKnown
	c.mu.RUnlock()
	if capsKnown && !relayEnabled {
		closePC()
		return nil, errors.New("server relay is disabled and P2P punching failed")
	}

	relayResp, err := c.sendRequest(ctx, protocol.MsgRelayAllocReq, message.RelayAllocReq{
		TargetClientID: targetClientID,
	})
	if err != nil {
		closePC()
		return nil, fmt.Errorf("relay fallback failed: %w", err)
	}
	if relayResp.Header.Type == protocol.MsgError {
		var em message.ErrorMsg
		if codec.DecodeJSON(relayResp, &em) == nil {
			closePC()
			return nil, fmt.Errorf("relay allocation rejected (%d): %s", em.Code, em.Message)
		}
	}
	var ack message.RelayAllocAck
	if err := codec.DecodeJSON(relayResp, &ack); err != nil {
		closePC()
		return nil, err
	}
	if !ack.Success {
		closePC()
		return nil, fmt.Errorf("relay allocation denied: %s", ack.Error)
	}
	relayUDPAddr, err := net.ResolveUDPAddr("udp", ack.RelayAddr)
	if err != nil {
		closePC()
		return nil, err
	}
	return newPeerChannel("relay", targetClientID, pc, relayUDPAddr, ack.RelaySessionID, ack.RelayToken, c.dgramCipher), nil
}

func (c *Client) authenticate(conn net.Conn) (uint64, error) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	chFrame, err := frame.ReadFrame(conn)
	if err != nil {
		return 0, fmt.Errorf("read auth challenge: %w", err)
	}
	if chFrame.Header.Type != protocol.MsgAuthChallenge {
		return 0, fmt.Errorf("expected AuthChallenge, got %d", chFrame.Header.Type)
	}
	var ch message.AuthChallenge
	if err := codec.DecodeJSON(chFrame, &ch); err != nil {
		return 0, err
	}

	ts := time.Now().Unix()
	sig := auth.SignChallenge(c.cfg.Security.Token, c.cfg.Client.ID, ch.Nonce, ts)
	req := message.AuthRequest{
		ClientID:  c.cfg.Client.ID,
		Nonce:     ch.Nonce,
		Timestamp: ts,
		Signature: sig,
		LocalAddr: conn.LocalAddr().String(),
	}
	reqFrame, err := codec.EncodeJSON(protocol.MsgAuthRequest, 1, 0, req)
	if err != nil {
		return 0, err
	}
	if err := frame.WriteFrame(conn, reqFrame); err != nil {
		return 0, err
	}

	respFrame, err := frame.ReadFrame(conn)
	if err != nil {
		return 0, fmt.Errorf("read auth response: %w", err)
	}
	if respFrame.Header.Type != protocol.MsgAuthResponse {
		return 0, fmt.Errorf("expected AuthResponse, got %d", respFrame.Header.Type)
	}
	var resp message.AuthResponse
	if err := codec.DecodeJSON(respFrame, &resp); err != nil {
		return 0, err
	}
	if !resp.Success {
		return 0, fmt.Errorf("authentication rejected (%d): %s", resp.ErrorCode, resp.Message)
	}
	c.mu.Lock()
	c.caps = resp.Capabilities
	c.capsKnown = resp.Capabilities.ProtocolVersion > 0
	known := c.capsKnown
	c.mu.Unlock()
	if known {
		c.log.Info("server capabilities",
			"relay", c.caps.RelayEnabled, "relay_port", c.caps.RelayPort,
			"nat", c.caps.NATEnabled, "nat_port", c.caps.NATPort,
			"http_proxy", c.caps.HTTPProxyEnabled, "http_port", c.caps.HTTPProxyPort)
	}
	return resp.SessionID, nil
}

// natEndpoint returns the NAT discovery endpoint, preferring the live capability data.
func (c *Client) natEndpoint() string {
	c.mu.RLock()
	port, known, enabled := c.cfg.Server.NATPort, c.capsKnown, c.caps.NATEnabled
	c.mu.RUnlock()
	if known && !enabled {
		return ""
	}
	if known && c.caps.NATPort > 0 {
		port = c.caps.NATPort
	}
	if port <= 0 {
		return ""
	}
	return net.JoinHostPort(c.cfg.Server.Address, strconv.Itoa(port))
}

// ServerCapabilities returns the capabilities advertised by the server at authentication.
// The second return value is false when connected to an older server without capability data.
func (c *Client) ServerCapabilities() (message.ServerCapabilities, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.caps, c.capsKnown
}

// ServerInfo queries the live server for its capabilities and runtime metrics.
func (c *Client) ServerInfo(ctx context.Context) (message.ServerInfo, error) {
	resp, err := c.sendRequest(ctx, protocol.MsgInfoReq, struct{}{})
	if err != nil {
		return message.ServerInfo{}, err
	}
	var info message.ServerInfo
	if err := codec.DecodeJSON(resp, &info); err != nil {
		return message.ServerInfo{}, err
	}
	return info, nil
}

// ServerError is a protocol-level error frame returned by the server in
// response to a synchronous request.
type ServerError struct {
	Code    protocol.ErrorCode
	Message string
}

func (e *ServerError) Error() string {
	return fmt.Sprintf("server error (%d): %s", e.Code, e.Message)
}

// serverErrorFromFrame converts a MsgError frame into a ServerError.
// It returns nil for any non-error frame.
func serverErrorFromFrame(f frame.Frame) error {
	if f.Header.Type != protocol.MsgError {
		return nil
	}
	var em message.ErrorMsg
	if err := codec.DecodeJSON(f, &em); err != nil {
		return fmt.Errorf("server error frame (undecodable): %w", err)
	}
	return &ServerError{Code: em.Code, Message: em.Message}
}

func (c *Client) sendRequest(ctx context.Context, msgType protocol.MessageType, payload any) (frame.Frame, error) {
	reqID := c.nextReq.Add(1)
	ch := make(chan frame.Frame, 1)

	c.reqMu.Lock()
	c.pending[reqID] = ch
	c.reqMu.Unlock()

	defer func() {
		c.reqMu.Lock()
		delete(c.pending, reqID)
		c.reqMu.Unlock()
	}()

	c.mu.RLock()
	sessID := c.sessionID
	c.mu.RUnlock()

	f, err := codec.EncodeJSON(msgType, reqID, sessID, payload)
	if err != nil {
		return frame.Frame{}, err
	}
	if err := c.sendFrame(f); err != nil {
		return frame.Frame{}, err
	}

	select {
	case <-ctx.Done():
		return frame.Frame{}, ctx.Err()
	case resp := <-ch:
		// A server-side error frame must surface as an error instead of being
		// decoded into a zero-value reply by the caller.
		if err := serverErrorFromFrame(resp); err != nil {
			return frame.Frame{}, err
		}
		return resp, nil
	case <-time.After(15 * time.Second):
		return frame.Frame{}, fmt.Errorf("request %d timed out", reqID)
	}
}

func (c *Client) sendFrame(f frame.Frame) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return errors.New("client not connected")
	}
	_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	err := frame.WriteFrame(conn, f)
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

func (c *Client) readLoop(ctx context.Context) error {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		f, err := frame.ReadFrame(conn)
		if err != nil {
			return err
		}
		if f.Header.RequestID != 0 {
			c.reqMu.Lock()
			ch, ok := c.pending[f.Header.RequestID]
			c.reqMu.Unlock()
			if ok {
				select {
				case ch <- f:
				default:
				}
				continue
			}
		}
		c.dispatchAsyncFrame(ctx, f)
	}
}

func (c *Client) dispatchAsyncFrame(ctx context.Context, f frame.Frame) {
	switch f.Header.Type {
	case protocol.MsgHeartbeatPong:
		c.lastPong.Store(time.Now().UnixNano())
	case protocol.MsgTunnelOpenConn:
		var req message.TunnelOpenConn
		if err := codec.DecodeJSON(f, &req); err == nil {
			go c.handleOpenConn(ctx, req)
		}
	case protocol.MsgTunnelData:
		connID, data, err := codec.DecodeTunnelData(f.Payload)
		if err == nil {
			c.forwardToLocalStream(connID, data)
		}
	case protocol.MsgTunnelClose:
		var cls message.TunnelClose
		if err := codec.DecodeJSON(f, &cls); err == nil {
			c.closeLocalStream(cls.ConnID)
		}
	case protocol.MsgUDPDatagram:
		var dgram message.UDPDatagram
		if err := codec.DecodeJSON(f, &dgram); err == nil {
			c.handleUDPFromServer(ctx, dgram)
		}
	case protocol.MsgPeerConnectInfo:
		var info message.PeerConnectInfo
		if err := codec.DecodeJSON(f, &info); err == nil {
			go c.handleIncomingPeerConnect(ctx, info)
		}
	case protocol.MsgRelayAllocNotify:
		var notify message.RelayAllocNotify
		if err := codec.DecodeJSON(f, &notify); err == nil {
			go c.handleIncomingRelay(notify)
		}
	case protocol.MsgError:
		var em message.ErrorMsg
		if err := codec.DecodeJSON(f, &em); err == nil {
			c.log.Warn("server error", "code", em.Code, "message", em.Message)
		}
	}
}

func (c *Client) handleIncomingPeerConnect(ctx context.Context, info message.PeerConnectInfo) {
	if !c.cfg.Network.EnableP2P {
		return
	}
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return
	}
	peerAddr, err := punching.Punch(ctx, pc, info.PunchToken, []string{info.PeerPublicAddr, info.PeerLocalAddr}, c.dgramCipher)
	if err != nil {
		_ = pc.Close()
		c.log.Debug("incoming P2P punch failed", "peer", info.PeerID, "err", err)
		return
	}
	ch := newPeerChannel("p2p", info.PeerID, pc, peerAddr, "", "", c.dgramCipher)
	c.RegisterIncoming(info.PeerID, ch)
	c.log.Info("incoming P2P hole punch succeeded", "peer", info.PeerID, "peer_addr", peerAddr.String())
}

func (c *Client) handleIncomingRelay(notify message.RelayAllocNotify) {
	if c.IncomingPeer(notify.FromClientID) != nil {
		return
	}
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return
	}
	relayAddr, err := net.ResolveUDPAddr("udp", notify.RelayAddr)
	if err != nil {
		_ = pc.Close()
		return
	}
	ch := newPeerChannel("relay", notify.FromClientID, pc, relayAddr, notify.RelaySessionID, notify.RelayToken, c.dgramCipher)
	c.RegisterIncoming(notify.FromClientID, ch)
	_ = ch.Send([]byte(peerRelayJoinPrefix + notify.RelaySessionID))
	c.log.Info("joined relay session", "peer", notify.FromClientID, "relay", notify.RelaySessionID)
}

func (c *Client) handleOpenConn(ctx context.Context, req message.TunnelOpenConn) {
	c.mu.RLock()
	localAddr, ok := c.localMap[req.TunnelID]
	sessID := c.sessionID
	c.mu.RUnlock()
	if !ok {
		localAddr = req.LocalAddr
	}

	if err := c.validator.Allow(localAddr); err != nil {
		c.sendOpenConnAck(sessID, req.ConnID, false, err.Error())
		return
	}

	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	localConn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", localAddr)
	cancel()
	if err != nil {
		c.sendOpenConnAck(sessID, req.ConnID, false, err.Error())
		return
	}

	ls := &localStream{
		connID: req.ConnID,
		conn:   localConn,
		sendCh: make(chan []byte, streamQueueSize),
		done:   make(chan struct{}),
	}
	c.streamsMu.Lock()
	c.streams[req.ConnID] = ls
	c.streamsMu.Unlock()

	c.sendOpenConnAck(sessID, req.ConnID, true, "")

	go c.writeLocalStream(ls)
	go c.readLocalStream(sessID, ls)
}

func (c *Client) sendOpenConnAck(sessID, connID uint64, success bool, errMsg string) {
	f, err := codec.EncodeJSON(protocol.MsgTunnelOpenConnAck, 0, sessID, message.TunnelOpenConnAck{
		ConnID:  connID,
		Success: success,
		Error:   errMsg,
	})
	if err == nil {
		_ = c.sendFrame(f)
	}
}

func (c *Client) writeLocalStream(ls *localStream) {
	defer c.closeLocalStream(ls.connID)
	for {
		select {
		case <-ls.done:
			return
		case chunk := <-ls.sendCh:
			_ = ls.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			n, err := ls.conn.Write(chunk)
			_ = ls.conn.SetWriteDeadline(time.Time{})
			if err != nil {
				return
			}
			c.metrics.BytesSent.Add(uint64(n))
		}
	}
}

func (c *Client) readLocalStream(sessID uint64, ls *localStream) {
	defer func() {
		c.closeLocalStream(ls.connID)
		clsFrame, err := codec.EncodeJSON(protocol.MsgTunnelClose, 0, sessID, message.TunnelClose{ConnID: ls.connID})
		if err == nil {
			_ = c.sendFrame(clsFrame)
		}
	}()

	buf := make([]byte, readChunkSize)
	for {
		n, err := ls.conn.Read(buf)
		if n > 0 {
			c.metrics.BytesReceived.Add(uint64(n))
			df := codec.EncodeTunnelData(0, sessID, ls.connID, buf[:n])
			if sendErr := c.sendFrame(df); sendErr != nil {
				return
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				c.log.Debug("local stream read ended", "conn_id", ls.connID, "err", err)
			}
			return
		}
	}
}

func (c *Client) forwardToLocalStream(connID uint64, data []byte) {
	c.streamsMu.RLock()
	ls, ok := c.streams[connID]
	c.streamsMu.RUnlock()
	if !ok {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)

	select {
	case <-ls.done:
		return
	case ls.sendCh <- cp:
	case <-time.After(5 * time.Second):
		c.closeLocalStream(connID)
	}
}

func (c *Client) closeLocalStream(connID uint64) {
	c.streamsMu.Lock()
	ls, ok := c.streams[connID]
	if ok {
		delete(c.streams, connID)
	}
	c.streamsMu.Unlock()
	if !ok {
		return
	}
	ls.closeOnce.Do(func() {
		close(ls.done)
		_ = ls.conn.Close()
	})
}

func (c *Client) handleUDPFromServer(ctx context.Context, dgram message.UDPDatagram) {
	c.mu.RLock()
	localAddr, ok := c.localMap[dgram.TunnelID]
	sessID := c.sessionID
	c.mu.RUnlock()
	if !ok {
		return
	}
	if err := c.validator.Allow(localAddr); err != nil {
		return
	}
	payload, err := base64.StdEncoding.DecodeString(dgram.PayloadB64)
	if err != nil {
		return
	}

	key := dgram.TunnelID + "|" + dgram.PeerAddr
	c.udpMu.Lock()
	pc, exists := c.udpPeers[key]
	if !exists {
		raddr, err := net.ResolveUDPAddr("udp", localAddr)
		if err != nil {
			c.udpMu.Unlock()
			return
		}
		uconn, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			c.udpMu.Unlock()
			return
		}
		pc = &udpPeerConn{
			key:      key,
			tunnelID: dgram.TunnelID,
			peerAddr: dgram.PeerAddr,
			conn:     uconn,
		}
		pc.lastActive.Store(time.Now().UnixNano())
		c.udpPeers[key] = pc
		go c.readLocalUDP(ctx, sessID, pc)
	} else {
		pc.lastActive.Store(time.Now().UnixNano())
	}
	c.udpMu.Unlock()

	_, _ = pc.conn.Write(payload)
}

func (c *Client) readLocalUDP(ctx context.Context, sessID uint64, pc *udpPeerConn) {
	buf := make([]byte, protocol.MaxUDPPacketSize)
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := pc.conn.Read(buf)
		if err != nil {
			return
		}
		pc.lastActive.Store(time.Now().UnixNano())
		resp := message.UDPDatagram{
			TunnelID:   pc.tunnelID,
			PeerAddr:   pc.peerAddr,
			PayloadB64: base64.StdEncoding.EncodeToString(buf[:n]),
		}
		f, err := codec.EncodeJSON(protocol.MsgUDPDatagram, 0, sessID, resp)
		if err == nil {
			_ = c.sendFrame(f)
		}
	}
}

func (c *Client) reapIdleUDP(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-udpIdleTimeout).UnixNano()
			c.udpMu.Lock()
			for k, pc := range c.udpPeers {
				if pc.lastActive.Load() < cutoff {
					_ = pc.conn.Close()
					delete(c.udpPeers, k)
				}
			}
			c.udpMu.Unlock()
		}
	}
}

func (c *Client) heartbeatLoop(ctx context.Context) {
	// 以会话建立时刻作为初始基准，刚连上不会立刻误判。
	c.lastPong.Store(time.Now().UnixNano())
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if pongStale(c.lastPong.Load(), time.Now()) {
				c.log.Warn("heartbeat timeout, closing stale session", "client_id", c.cfg.Client.ID)
				c.closeStaleConn()
				return // readLoop 读到关闭错误 -> Run 重连
			}
			c.mu.RLock()
			sessID := c.sessionID
			c.mu.RUnlock()
			f, err := codec.EncodeJSON(protocol.MsgHeartbeatPing, 0, sessID, message.HeartbeatPing{
				SentAt: time.Now().UnixMilli(),
			})
			if err == nil {
				_ = c.sendFrame(f)
			}
		}
	}
}

// pongStale 判定最近一次 PONG 是否已超过容忍窗口。
func pongStale(lastPongUnixNano int64, now time.Time) bool {
	if lastPongUnixNano <= 0 {
		return false // 尚未认证，交由上层处理
	}
	return now.Sub(time.Unix(0, lastPongUnixNano)) > heartbeatInterval*missedPongLimit
}

// closeStaleConn 关闭当前控制连接，使 readLoop 返回并触发上层重连。
func (c *Client) closeStaleConn() {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn != nil {
		_ = conn.Close()
	}
}

// Connected reports whether the control session has a fresh heartbeat acknowledgement.
// 半开链路上读循环可能尚未报错，但收不到 PONG 时这里会返回 false。
func (c *Client) Connected() bool {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()
	if conn == nil {
		return false
	}
	lp := c.lastPong.Load()
	return lp > 0 && time.Since(time.Unix(0, lp)) <= heartbeatInterval*missedPongLimit
}

func (c *Client) cleanupSession() {
	c.mu.Lock()
	conn := c.conn
	c.conn = nil
	c.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}

	c.streamsMu.Lock()
	for id, ls := range c.streams {
		delete(c.streams, id)
		ls.closeOnce.Do(func() {
			close(ls.done)
			_ = ls.conn.Close()
		})
	}
	c.streamsMu.Unlock()

	c.udpMu.Lock()
	for k, pc := range c.udpPeers {
		_ = pc.conn.Close()
		delete(c.udpPeers, k)
	}
	c.udpMu.Unlock()

	c.peerMu.Lock()
	for id, ch := range c.incoming {
		delete(c.incoming, id)
		_ = ch.Close()
	}
	c.peerMu.Unlock()
}
