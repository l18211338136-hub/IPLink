package service

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"iplink/internal/config"
	"iplink/internal/metrics"
	"iplink/internal/nat/discovery"
	"iplink/internal/protocol/codec"
	"iplink/internal/protocol/frame"
	"iplink/internal/protocol/message"
	relaymgr "iplink/internal/relay/manager"
	"iplink/internal/security/auth"
	servercrypto "iplink/internal/security/crypto"
	"iplink/internal/security/identity"
	"iplink/internal/server/session"
	tcptransport "iplink/internal/transport/tcp"
	"iplink/pkg/protocol"
)

const (
	authTimeout      = 10 * time.Second
	heartbeatTimeout = 60 * time.Second
	streamQueueSize  = 64
	readChunkSize    = 32 * 1024
	udpPeerTTL       = 2 * time.Minute
)

// Server coordinates control connections, TCP/UDP reverse tunnels, NAT discovery, and Relay.
type Server struct {
	cfg      config.ServerConfig
	log      *slog.Logger
	metrics  *metrics.Metrics
	sessions *session.Manager
	natSrv   *discovery.Server
	relayMgr *relaymgr.Manager

	// 始终按白名单校验 req.LocalAddr；空配置等同于 loopback-only。
	// 需要任意目标时须显式配置 "*:*"。
	targetValidator *identity.TargetValidator
	targetErr       error

	controlLn net.Listener

	connsMu    sync.RWMutex
	proxyConns map[uint64]*proxyConn
	nextConnID atomic.Uint64
	nextTunID  atomic.Uint64

	udpMu      sync.RWMutex
	udpTunnels map[string]net.PacketConn
	udpPeers   map[string]map[string]time.Time // tunnelID -> observed peer addr -> last seen

	httpMu     sync.RWMutex
	httpRoutes map[string]*httpRoute
	httpLn     net.Listener
	httpSrv    *http.Server

	metricsLn  net.Listener
	metricsSrv *http.Server

	// dgramCipher 加密 NAT 发现与 Relay 转发的 UDP 数据报。
	dgramCipher *servercrypto.DatagramCipher
	tlsEnabled  bool

	wg sync.WaitGroup
}

type proxyConn struct {
	id        uint64
	tunnelID  string // server-assigned tunnel ID, for per-tunnel counters
	conn      net.Conn
	sendCh    chan []byte
	readyCh   chan bool
	done      chan struct{}
	closeOnce sync.Once
	active    atomic.Bool // whether this conn has been counted as active
}

// New creates a new IPLink Server instance.
func New(cfg config.ServerConfig, log *slog.Logger) *Server {
	m := &metrics.Metrics{}
	s := &Server{
		cfg:        cfg,
		log:        log,
		metrics:    m,
		tlsEnabled: cfg.Security.TLSEnabled,
		sessions:   session.NewManager(m),
		proxyConns: make(map[uint64]*proxyConn),
		udpTunnels: make(map[string]net.PacketConn),
		udpPeers:   make(map[string]map[string]time.Time),
		httpRoutes: make(map[string]*httpRoute),
	}
	// NewTargetValidator treats an empty list as loopback-only, matching the
	// client-side default. Explicit "*:*" is required for unrestricted targets.
	s.targetValidator, s.targetErr = identity.NewTargetValidator(cfg.Security.AllowedTargets)
	return s
}

// Start binds the control, NAT, and relay listeners and begins serving until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	if s.targetErr != nil {
		return fmt.Errorf("invalid security.allowed_targets: %w", s.targetErr)
	}
	dc, err := servercrypto.NewDatagramCipher(s.cfg.Security.Token)
	if err != nil {
		return fmt.Errorf("derive datagram cipher: %w", err)
	}
	s.dgramCipher = dc
	var tlsConfig *tls.Config
	if s.cfg.Security.TLSEnabled {
		var err error
		tlsConfig, err = servercrypto.LoadServerTLSConfig(s.cfg.Security.TLSCertFile, s.cfg.Security.TLSKeyFile)
		if err != nil {
			return err
		}
	}

	ctrlAddr := fmt.Sprintf("%s:%d", s.cfg.Server.ListenIP, s.cfg.Server.ControlPort)
	ln, err := tcptransport.Listen(ctx, ctrlAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("listen control %s: %w", ctrlAddr, err)
	}
	s.controlLn = ln

	natAddr := fmt.Sprintf("%s:%d", s.cfg.Server.ListenIP, s.cfg.Server.NATPort)
	natSrv, err := discovery.StartServer(ctx, natAddr, s.dgramCipher, s.log)
	if err != nil {
		_ = ln.Close()
		return err
	}
	s.natSrv = natSrv

	relayAddr := fmt.Sprintf("%s:%d", s.cfg.Server.ListenIP, s.cfg.Server.RelayPort)
	rMgr, err := relaymgr.Start(ctx, relayAddr, s.cfg.Relay.Enabled, s.cfg.Relay.MaxSessions, s.cfg.Relay.MaxBytesPerSec, s.metrics, s.log)
	if err != nil {
		_ = natSrv.Close()
		_ = ln.Close()
		return err
	}
	s.relayMgr = rMgr

	if err := s.startHTTPProxy(ctx, tlsConfig); err != nil {
		_ = rMgr.Close()
		_ = natSrv.Close()
		_ = ln.Close()
		return err
	}

	if err := s.startMetrics(tlsConfig); err != nil {
		if s.httpSrv != nil {
			_ = s.httpSrv.Close()
		}
		_ = rMgr.Close()
		_ = natSrv.Close()
		_ = ln.Close()
		return err
	}

	s.log.Info("IPLink server started",
		"control_addr", ln.Addr().String(),
		"nat_addr", natSrv.Addr(),
		"relay_addr", rMgr.Addr(),
		"http_proxy_addr", s.HTTPProxyAddr(),
		"metrics_addr", s.MetricsAddr(),
		"tls", s.cfg.Security.TLSEnabled,
	)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.sessions.ReapExpired(ctx, heartbeatTimeout)
	}()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		_ = s.controlLn.Close()
		_ = s.natSrv.Close()
		_ = s.relayMgr.Close()
		if s.httpSrv != nil {
			shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = s.httpSrv.Shutdown(shutCtx)
			cancel()
		}
		if s.metricsSrv != nil {
			shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_ = s.metricsSrv.Shutdown(shutCtx)
			cancel()
		}
		s.sessions.CloseAll()
		s.closeAllProxyConns()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			s.log.Warn("accept control connection failed", "err", err)
			continue
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleControlConn(ctx, c)
		}(conn)
	}

	s.wg.Wait()
	s.log.Info("IPLink server stopped")
	return nil
}

// ControlAddr returns the bound control listener address (useful when port 0 is used in tests).
func (s *Server) ControlAddr() string {
	if s.controlLn == nil {
		return ""
	}
	return s.controlLn.Addr().String()
}

// NATAddr returns the bound NAT UDP listener address.
func (s *Server) NATAddr() string {
	if s.natSrv == nil {
		return ""
	}
	return s.natSrv.Addr()
}

// RelayAddr returns the bound Relay UDP listener address.
func (s *Server) RelayAddr() string {
	if s.relayMgr == nil {
		return ""
	}
	return s.relayMgr.Addr()
}

// Metrics returns a snapshot of current server metrics.
func (s *Server) Metrics() metrics.Snapshot {
	return s.metrics.Snapshot()
}

// capabilities reports the services actually bound by this server instance.
func (s *Server) capabilities() message.ServerCapabilities {
	natAddr, relayAddr, httpAddr, metricsAddr := "", "", "", ""
	if s.natSrv != nil {
		natAddr = s.natSrv.Addr()
	}
	if s.relayMgr != nil {
		relayAddr = s.relayMgr.Addr()
	}
	if s.httpLn != nil {
		httpAddr = s.httpLn.Addr().String()
	}
	if s.metricsLn != nil {
		metricsAddr = s.metricsLn.Addr().String()
	}
	return message.ServerCapabilities{
		ProtocolVersion:  protocol.ProtocolVersion,
		NATEnabled:       natAddr != "",
		NATPort:          boundPort(natAddr),
		RelayEnabled:     relayAddr != "",
		RelayPort:        boundPort(relayAddr),
		HTTPProxyEnabled: httpAddr != "",
		HTTPProxyPort:    boundPort(httpAddr),
		MetricsEnabled:   metricsAddr != "",
		MetricsPort:      boundPort(metricsAddr),
	}
}

func boundPort(addr string) int {
	if addr == "" {
		return 0
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return p
}

func (s *Server) handleControlConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	sess, err := s.authenticate(conn)
	if err != nil {
		s.log.Warn("client authentication failed", "remote", conn.RemoteAddr().String(), "err", err)
		return
	}
	defer s.sessions.Remove(sess.ID)

	s.log.Info("client authenticated", "client_id", sess.ClientID, "session_id", sess.ID, "remote", conn.RemoteAddr().String())

	for {
		if ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(heartbeatTimeout))
		f, err := frame.ReadFrame(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) && ctx.Err() == nil {
				s.log.Debug("control read ended", "client_id", sess.ClientID, "err", err)
			}
			return
		}
		s.dispatchFrame(ctx, sess, f)
	}
}

func (s *Server) authenticate(conn net.Conn) (*session.Session, error) {
	nonce, err := auth.GenerateNonce()
	if err != nil {
		return nil, err
	}
	challenge := message.AuthChallenge{
		Nonce:     nonce,
		Timestamp: time.Now().Unix(),
	}
	chFrame, err := codec.EncodeJSON(protocol.MsgAuthChallenge, 0, 0, challenge)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(authTimeout))
	if err := frame.WriteFrame(conn, chFrame); err != nil {
		return nil, err
	}

	reqFrame, err := frame.ReadFrame(conn)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})

	if reqFrame.Header.Type != protocol.MsgAuthRequest {
		return nil, fmt.Errorf("expected AuthRequest, got %d", reqFrame.Header.Type)
	}
	var req message.AuthRequest
	if err := codec.DecodeJSON(reqFrame, &req); err != nil {
		return nil, err
	}
	if req.Nonce != nonce {
		s.sendAuthError(conn, reqFrame.Header.RequestID, protocol.ErrAuthFailed, "nonce mismatch")
		return nil, errors.New("nonce mismatch")
	}
	if err := auth.VerifyChallenge(s.cfg.Security.Token, req.ClientID, req.Nonce, req.Timestamp, req.Signature, auth.DefaultMaxClockSkew); err != nil {
		s.sendAuthError(conn, reqFrame.Header.RequestID, protocol.ErrAuthFailed, "authentication failed")
		return nil, err
	}

	sess := s.sessions.Create(req.ClientID, conn, req.LocalAddr)
	resp := message.AuthResponse{
		Success:      true,
		SessionID:    sess.ID,
		Capabilities: s.capabilities(),
	}
	respFrame, err := codec.EncodeJSON(protocol.MsgAuthResponse, reqFrame.Header.RequestID, sess.ID, resp)
	if err != nil {
		s.sessions.Remove(sess.ID)
		return nil, err
	}
	if err := sess.SendFrame(respFrame); err != nil {
		s.sessions.Remove(sess.ID)
		return nil, err
	}
	return sess, nil
}

func (s *Server) sendAuthError(conn net.Conn, reqID uint64, code protocol.ErrorCode, msg string) {
	resp, err := codec.EncodeJSON(protocol.MsgAuthResponse, reqID, 0, message.AuthResponse{
		Success:   false,
		ErrorCode: code,
		Message:   msg,
	})
	if err == nil {
		_ = frame.WriteFrame(conn, resp)
	}
}

func (s *Server) dispatchFrame(ctx context.Context, sess *session.Session, f frame.Frame) {
	switch f.Header.Type {
	case protocol.MsgHeartbeatPing:
		var ping message.HeartbeatPing
		_ = codec.DecodeJSON(f, &ping)
		sess.TouchHeartbeat()
		pong, err := codec.EncodeJSON(protocol.MsgHeartbeatPong, f.Header.RequestID, sess.ID, message.HeartbeatPong{
			SentAt:     ping.SentAt,
			ReceivedAt: time.Now().UnixMilli(),
		})
		if err == nil {
			_ = sess.SendFrame(pong)
		}

	case protocol.MsgTunnelCreate:
		var req message.TunnelCreate
		if err := codec.DecodeJSON(f, &req); err != nil {
			s.sendTunnelCreateErr(sess, f.Header.RequestID, protocol.ErrInvalidFrame, err.Error())
			return
		}
		s.handleTunnelCreate(ctx, sess, f.Header.RequestID, req)

	case protocol.MsgTunnelOpenConnAck:
		var ack message.TunnelOpenConnAck
		if err := codec.DecodeJSON(f, &ack); err != nil {
			return
		}
		s.connsMu.RLock()
		pc, ok := s.proxyConns[ack.ConnID]
		s.connsMu.RUnlock()
		if ok {
			select {
			case pc.readyCh <- ack.Success:
			default:
			}
		}
		if !ack.Success {
			s.closeProxyConn(ack.ConnID)
		}

	case protocol.MsgTunnelData:
		connID, data, err := codec.DecodeTunnelData(f.Payload)
		if err != nil {
			return
		}
		s.forwardToProxyConn(connID, data)

	case protocol.MsgTunnelClose:
		var cls message.TunnelClose
		if err := codec.DecodeJSON(f, &cls); err == nil {
			s.closeProxyConn(cls.ConnID)
		}

	case protocol.MsgUDPDatagram:
		var dgram message.UDPDatagram
		if err := codec.DecodeJSON(f, &dgram); err != nil {
			return
		}
		s.handleUDPFromClient(dgram)

	case protocol.MsgPeerListReq:
		peers := s.sessions.ListPeers()
		resp, err := codec.EncodeJSON(protocol.MsgPeerListResp, f.Header.RequestID, sess.ID, message.PeerListResp{Peers: peers})
		if err == nil {
			_ = sess.SendFrame(resp)
		}

	case protocol.MsgPeerConnectReq:
		var req message.PeerConnectReq
		if err := codec.DecodeJSON(f, &req); err != nil {
			return
		}
		s.handlePeerConnect(sess, f.Header.RequestID, req)

	case protocol.MsgRelayAllocReq:
		var req message.RelayAllocReq
		if err := codec.DecodeJSON(f, &req); err != nil {
			return
		}
		s.handleRelayAlloc(sess, f.Header.RequestID, req)

	case protocol.MsgInfoReq:
		info, err := codec.EncodeJSON(protocol.MsgInfoResp, f.Header.RequestID, sess.ID, message.ServerInfo{
			Capabilities: s.capabilities(),
			Metrics:      s.Metrics(),
		})
		if err == nil {
			_ = sess.SendFrame(info)
		}

	default:
		s.log.Debug("unknown message type", "type", f.Header.Type, "client_id", sess.ClientID)
	}
}

func (s *Server) handleTunnelCreate(ctx context.Context, sess *session.Session, reqID uint64, req message.TunnelCreate) {
	if s.targetValidator != nil {
		if err := s.targetValidator.Allow(req.LocalAddr); err != nil {
			s.log.Warn("tunnel target denied by server policy", "client_id", sess.ClientID, "local", req.LocalAddr, "err", err)
			s.sendTunnelCreateErr(sess, reqID, protocol.ErrTargetDenied, err.Error())
			return
		}
	}
	proto := strings.ToLower(strings.TrimSpace(req.Protocol))
	tunID := fmt.Sprintf("tun-%d", s.nextTunID.Add(1))

	switch proto {
	case "tcp":
		ln, err := net.Listen("tcp", req.RemoteAddr)
		if err != nil {
			s.sendTunnelCreateErr(sess, reqID, protocol.ErrTunnelCreateFailed, err.Error())
			return
		}
		var cleanupOnce sync.Once
		cleanup := func() error {
			cleanupOnce.Do(func() {
				s.metrics.ActiveTunnels.Add(-1)
				s.metrics.UnregisterTunnel(tunID)
				_ = ln.Close()
			})
			return nil
		}
		s.metrics.ActiveTunnels.Add(1)
		s.metrics.RegisterTunnel(tunID, "tcp", req.LocalAddr)
		sess.RegisterTunnel(tunID, closerFunc(cleanup))

		ack, err := codec.EncodeJSON(protocol.MsgTunnelCreateAck, reqID, sess.ID, message.TunnelCreateAck{
			Success:   true,
			TunnelID:  tunID,
			BoundAddr: ln.Addr().String(),
		})
		if err != nil || sess.SendFrame(ack) != nil {
			_ = cleanup()
			return
		}
		s.log.Info("TCP tunnel created", "tunnel_id", tunID, "client_id", sess.ClientID, "bound", ln.Addr().String(), "local", req.LocalAddr)

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.acceptTCPTunnel(ctx, sess, tunID, req.LocalAddr, ln)
		}()

	case "udp":
		pc, err := net.ListenPacket("udp", req.RemoteAddr)
		if err != nil {
			s.sendTunnelCreateErr(sess, reqID, protocol.ErrTunnelCreateFailed, err.Error())
			return
		}
		s.udpMu.Lock()
		s.udpTunnels[tunID] = pc
		s.udpMu.Unlock()
		var cleanupOnce sync.Once
		cleanup := func() error {
			cleanupOnce.Do(func() {
				s.udpMu.Lock()
				delete(s.udpTunnels, tunID)
				delete(s.udpPeers, tunID)
				s.udpMu.Unlock()
				s.metrics.ActiveTunnels.Add(-1)
				s.metrics.UnregisterTunnel(tunID)
				_ = pc.Close()
			})
			return nil
		}
		s.metrics.ActiveTunnels.Add(1)
		s.metrics.RegisterTunnel(tunID, "udp", req.LocalAddr)
		sess.RegisterTunnel(tunID, closerFunc(cleanup))

		ack, err := codec.EncodeJSON(protocol.MsgTunnelCreateAck, reqID, sess.ID, message.TunnelCreateAck{
			Success:   true,
			TunnelID:  tunID,
			BoundAddr: pc.LocalAddr().String(),
		})
		if err != nil || sess.SendFrame(ack) != nil {
			_ = cleanup()
			return
		}
		s.log.Info("UDP tunnel created", "tunnel_id", tunID, "client_id", sess.ClientID, "bound", pc.LocalAddr().String(), "local", req.LocalAddr)

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveUDPTunnel(ctx, sess, tunID, pc)
		}()

	case "http":
		prefix, err := s.registerHTTPRoute(ctx, sess, tunID, req)
		if err != nil {
			s.sendTunnelCreateErr(sess, reqID, protocol.ErrTunnelCreateFailed, err.Error())
			return
		}
		var cleanupOnce sync.Once
		cleanup := func() error {
			cleanupOnce.Do(func() {
				s.unregisterHTTPRoute(prefix, tunID)
				s.metrics.ActiveTunnels.Add(-1)
				s.metrics.UnregisterTunnel(tunID)
			})
			return nil
		}
		s.metrics.ActiveTunnels.Add(1)
		s.metrics.RegisterTunnel(tunID, "http", req.LocalAddr)
		sess.RegisterTunnel(tunID, closerFunc(cleanup))

		scheme := "http"
		if s.tlsEnabled {
			scheme = "https"
		}
		bound := fmt.Sprintf("%s://%s%s", scheme, s.HTTPProxyAddr(), prefix)
		ack, err := codec.EncodeJSON(protocol.MsgTunnelCreateAck, reqID, sess.ID, message.TunnelCreateAck{
			Success:   true,
			TunnelID:  tunID,
			BoundAddr: bound,
		})
		if err != nil || sess.SendFrame(ack) != nil {
			_ = cleanup()
			return
		}
		s.log.Info("HTTP reverse proxy route created", "tunnel_id", tunID, "client_id", sess.ClientID, "path", prefix, "local", req.LocalAddr)

	default:
		s.sendTunnelCreateErr(sess, reqID, protocol.ErrTunnelCreateFailed, "unsupported protocol: "+req.Protocol)
	}
}

func (s *Server) sendTunnelCreateErr(sess *session.Session, reqID uint64, code protocol.ErrorCode, msg string) {
	ack, err := codec.EncodeJSON(protocol.MsgTunnelCreateAck, reqID, sess.ID, message.TunnelCreateAck{
		Success:   false,
		ErrorCode: code,
		Error:     msg,
	})
	if err == nil {
		_ = sess.SendFrame(ack)
	}
}

func (s *Server) acceptTCPTunnel(ctx context.Context, sess *session.Session, tunID, localAddr string, ln net.Listener) {
	for {
		extConn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Debug("tunnel accept error", "tunnel_id", tunID, "err", err)
			return
		}
		connID := s.nextConnID.Add(1)
		pc := &proxyConn{
			id:       connID,
			tunnelID: tunID,
			conn:     extConn,
			sendCh:   make(chan []byte, streamQueueSize),
			readyCh:  make(chan bool, 1),
			done:     make(chan struct{}),
		}
		s.connsMu.Lock()
		s.proxyConns[connID] = pc
		s.connsMu.Unlock()

		openFrame, err := codec.EncodeJSON(protocol.MsgTunnelOpenConn, 0, sess.ID, message.TunnelOpenConn{
			TunnelID:   tunID,
			ConnID:     connID,
			LocalAddr:  localAddr,
			RemotePeer: extConn.RemoteAddr().String(),
		})
		if err != nil || sess.SendFrame(openFrame) != nil {
			s.closeProxyConn(connID)
			continue
		}

		s.wg.Add(1)
		go func(p *proxyConn) {
			defer s.wg.Done()
			select {
			case ok := <-p.readyCh:
				if !ok {
					s.closeProxyConn(p.id)
					return
				}
			case <-time.After(5 * time.Second):
				s.closeProxyConn(p.id)
				return
			case <-ctx.Done():
				s.closeProxyConn(p.id)
				return
			}

			s.activateProxyConn(p)
			s.wg.Add(2)
			go func() {
				defer s.wg.Done()
				s.writeProxyConnLoop(p)
			}()
			go func() {
				defer s.wg.Done()
				s.readProxyConnLoop(sess, p)
			}()
		}(pc)
	}
}

func (s *Server) writeProxyConnLoop(pc *proxyConn) {
	defer s.closeProxyConn(pc.id)
	for {
		select {
		case <-pc.done:
			return
		case chunk := <-pc.sendCh:
			_ = pc.conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			n, err := pc.conn.Write(chunk)
			_ = pc.conn.SetWriteDeadline(time.Time{})
			if err != nil {
				return
			}
			s.metrics.BytesSent.Add(uint64(n))
			if tc := s.metrics.Tunnel(pc.tunnelID); tc != nil {
				tc.BytesSent.Add(uint64(n))
			}
		}
	}
}

func (s *Server) readProxyConnLoop(sess *session.Session, pc *proxyConn) {
	defer func() {
		s.closeProxyConn(pc.id)
		clsFrame, err := codec.EncodeJSON(protocol.MsgTunnelClose, 0, sess.ID, message.TunnelClose{ConnID: pc.id})
		if err == nil {
			_ = sess.SendFrame(clsFrame)
		}
	}()

	buf := make([]byte, readChunkSize)
	for {
		n, err := pc.conn.Read(buf)
		if n > 0 {
			s.metrics.BytesReceived.Add(uint64(n))
			if tc := s.metrics.Tunnel(pc.tunnelID); tc != nil {
				tc.BytesReceived.Add(uint64(n))
			}
			dataFrame := codec.EncodeTunnelData(0, sess.ID, pc.id, buf[:n])
			if sendErr := sess.SendFrame(dataFrame); sendErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (s *Server) forwardToProxyConn(connID uint64, data []byte) {
	s.connsMu.RLock()
	pc, ok := s.proxyConns[connID]
	s.connsMu.RUnlock()
	if !ok {
		return
	}
	cp := make([]byte, len(data))
	copy(cp, data)

	select {
	case <-pc.done:
		return
	case pc.sendCh <- cp:
	case <-time.After(5 * time.Second):
		// Backpressure timeout: drop slow consumer to protect server memory.
		s.closeProxyConn(connID)
	}
}

// activateProxyConn marks a proxy conn as established and increments the
// per-tunnel active connection counter exactly once.
func (s *Server) activateProxyConn(pc *proxyConn) {
	if pc.active.CompareAndSwap(false, true) {
		if tc := s.metrics.Tunnel(pc.tunnelID); tc != nil {
			tc.ActiveConns.Add(1)
		}
	}
}

func (s *Server) closeProxyConn(connID uint64) {
	s.connsMu.Lock()
	pc, ok := s.proxyConns[connID]
	if ok {
		delete(s.proxyConns, connID)
	}
	s.connsMu.Unlock()
	if !ok {
		return
	}
	s.shutdownProxyConn(pc)
}

// shutdownProxyConn closes a multiplexed connection and releases its
// per-tunnel active counter exactly once.
func (s *Server) shutdownProxyConn(pc *proxyConn) {
	pc.closeOnce.Do(func() {
		if pc.active.CompareAndSwap(true, false) {
			if tc := s.metrics.Tunnel(pc.tunnelID); tc != nil {
				tc.ActiveConns.Add(-1)
			}
		}
		close(pc.done)
		_ = pc.conn.Close()
	})
}

func (s *Server) closeAllProxyConns() {
	s.connsMu.Lock()
	conns := make([]*proxyConn, 0, len(s.proxyConns))
	for id, pc := range s.proxyConns {
		conns = append(conns, pc)
		delete(s.proxyConns, id)
	}
	s.connsMu.Unlock()
	for _, pc := range conns {
		s.shutdownProxyConn(pc)
	}
}

// rememberUDPPeer records a real source address observed on the public UDP
// tunnel. Only these addresses may be used as reply targets by clients.
func (s *Server) rememberUDPPeer(tunID string, addr net.Addr) {
	key := addr.String()
	now := time.Now()
	s.udpMu.Lock()
	peers := s.udpPeers[tunID]
	if peers == nil {
		peers = make(map[string]time.Time)
		s.udpPeers[tunID] = peers
	}
	for seenAddr, seenAt := range peers {
		if now.Sub(seenAt) > udpPeerTTL {
			delete(peers, seenAddr)
		}
	}
	peers[key] = now
	s.udpMu.Unlock()
}

// allowUDPPeer reports whether addr was recently observed as a real peer of tunID.
func (s *Server) allowUDPPeer(tunID, addr string) bool {
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	peers := s.udpPeers[tunID]
	seenAt, ok := peers[addr]
	if !ok {
		return false
	}
	if time.Since(seenAt) > udpPeerTTL {
		delete(peers, addr)
		return false
	}
	return true
}

func (s *Server) serveUDPTunnel(ctx context.Context, sess *session.Session, tunID string, pc net.PacketConn) {
	buf := make([]byte, protocol.MaxUDPPacketSize)
	for {
		n, peerAddr, err := pc.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			return
		}
		s.rememberUDPPeer(tunID, peerAddr)
		s.metrics.BytesReceived.Add(uint64(n))
		if tc := s.metrics.Tunnel(tunID); tc != nil {
			tc.BytesReceived.Add(uint64(n))
		}
		dgram := message.UDPDatagram{
			TunnelID:   tunID,
			PeerAddr:   peerAddr.String(),
			PayloadB64: base64.StdEncoding.EncodeToString(buf[:n]),
		}
		f, err := codec.EncodeJSON(protocol.MsgUDPDatagram, 0, sess.ID, dgram)
		if err == nil {
			_ = sess.SendFrame(f)
		}
	}
}

func (s *Server) handleUDPFromClient(dgram message.UDPDatagram) {
	s.udpMu.RLock()
	pc, ok := s.udpTunnels[dgram.TunnelID]
	s.udpMu.RUnlock()
	if !ok {
		return
	}
	payload, err := base64.StdEncoding.DecodeString(dgram.PayloadB64)
	if err != nil {
		return
	}
	addr, err := net.ResolveUDPAddr("udp", dgram.PeerAddr)
	if err != nil {
		return
	}
	// The client must not choose arbitrary reply targets: only addresses that
	// were actually observed on this tunnel may be written back to.
	if !s.allowUDPPeer(dgram.TunnelID, addr.String()) {
		s.log.Debug("udp reply target not observed on tunnel", "tunnel_id", dgram.TunnelID, "peer_addr", dgram.PeerAddr)
		return
	}
	n, err := pc.WriteTo(payload, addr)
	if err == nil {
		s.metrics.BytesSent.Add(uint64(n))
		if tc := s.metrics.Tunnel(dgram.TunnelID); tc != nil {
			tc.BytesSent.Add(uint64(n))
		}
	}
}

func (s *Server) handlePeerConnect(sess *session.Session, reqID uint64, req message.PeerConnectReq) {
	if req.MyPublicAddr != "" {
		sess.SetPublicAddr(req.MyPublicAddr)
	}
	target, ok := s.sessions.GetByClientID(req.TargetClientID)
	if !ok {
		errFrame, _ := codec.EncodeJSON(protocol.MsgError, reqID, sess.ID, message.ErrorMsg{
			Code:    protocol.ErrPeerNotFound,
			Message: "target peer not online: " + req.TargetClientID,
		})
		_ = sess.SendFrame(errFrame)
		return
	}
	punchToken, err := auth.GenerateNonce()
	if err != nil {
		return
	}
	infoForRequester, _ := codec.EncodeJSON(protocol.MsgPeerConnectInfo, reqID, sess.ID, message.PeerConnectInfo{
		PeerID:         target.ClientID,
		PeerPublicAddr: target.PublicAddr,
		PeerLocalAddr:  target.LocalAddr,
		PunchToken:     punchToken,
	})
	infoForTarget, _ := codec.EncodeJSON(protocol.MsgPeerConnectInfo, 0, target.ID, message.PeerConnectInfo{
		PeerID:         sess.ClientID,
		PeerPublicAddr: req.MyPublicAddr,
		PeerLocalAddr:  sess.LocalAddr,
		PunchToken:     punchToken,
	})
	_ = sess.SendFrame(infoForRequester)
	_ = target.SendFrame(infoForTarget)
}

func (s *Server) handleRelayAlloc(sess *session.Session, reqID uint64, req message.RelayAllocReq) {
	target, ok := s.sessions.GetByClientID(req.TargetClientID)
	if !ok {
		ack, _ := codec.EncodeJSON(protocol.MsgRelayAllocAck, reqID, sess.ID, message.RelayAllocAck{
			Success:   false,
			ErrorCode: protocol.ErrPeerNotFound,
			Error:     "target peer not online: " + req.TargetClientID,
		})
		_ = sess.SendFrame(ack)
		return
	}
	rid, relayToken, err := s.relayMgr.Allocate(sess.ClientID, target.ClientID)
	if err != nil {
		ack, _ := codec.EncodeJSON(protocol.MsgRelayAllocAck, reqID, sess.ID, message.RelayAllocAck{
			Success:   false,
			ErrorCode: protocol.ErrRelayUnavailable,
			Error:     err.Error(),
		})
		_ = sess.SendFrame(ack)
		return
	}
	ack, _ := codec.EncodeJSON(protocol.MsgRelayAllocAck, reqID, sess.ID, message.RelayAllocAck{
		Success:        true,
		RelaySessionID: rid,
		RelayAddr:      s.relayMgr.Addr(),
		RelayToken:     relayToken,
	})
	_ = sess.SendFrame(ack)

	notify, _ := codec.EncodeJSON(protocol.MsgRelayAllocNotify, 0, target.ID, message.RelayAllocNotify{
		FromClientID:   sess.ClientID,
		RelaySessionID: rid,
		RelayAddr:      s.relayMgr.Addr(),
		RelayToken:     relayToken,
	})
	_ = target.SendFrame(notify)
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }
