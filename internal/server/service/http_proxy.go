package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"iplink/internal/metrics"
	"iplink/internal/protocol/codec"
	"iplink/internal/protocol/message"
	"iplink/internal/server/session"
	"iplink/pkg/protocol"
)

type httpRoute struct {
	tunnelID    string
	prefix      string
	localAddr   string
	stripPrefix bool
	sess        *session.Session
	proxy       *httputil.ReverseProxy
}

func normalizeHTTPPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return strings.TrimRight(p, "/")
}

func (s *Server) startHTTPProxy(ctx context.Context, tlsConfig *tls.Config) error {
	if s.cfg.Server.HTTPProxyPort <= 0 {
		return nil
	}
	addr := fmt.Sprintf("%s:%d", s.cfg.Server.ListenIP, s.cfg.Server.HTTPProxyPort)
	baseLn, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen http_proxy %s: %w", addr, err)
	}
	// tls_enabled 时 HTTP 反向代理也走 HTTPS（复用服务端证书）。
	ln := net.Listener(baseLn)
	if tlsConfig != nil {
		ln = tls.NewListener(baseLn, tlsConfig)
	}
	s.httpLn = ln
	s.httpSrv = &http.Server{
		Handler:           http.HandlerFunc(s.serveHTTPProxy),
		ReadHeaderTimeout: 15 * time.Second,
		ReadTimeout:       60 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.httpSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Warn("http proxy server error", "err", err)
		}
	}()
	return nil
}

// startMetrics starts the built-in metrics HTTP server if enabled.
func (s *Server) startMetrics(tlsConfig *tls.Config) error {
	if !s.cfg.Metrics.Enabled {
		return nil
	}
	listenIP := s.cfg.Metrics.ListenIP
	if listenIP == "" {
		listenIP = "127.0.0.1"
	}
	addr := fmt.Sprintf("%s:%d", listenIP, s.cfg.Metrics.Port)
	baseLn, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen metrics %s: %w", addr, err)
	}
	ln := net.Listener(baseLn)
	if tlsConfig != nil {
		ln = tls.NewListener(baseLn, tlsConfig)
	}
	s.metricsLn = ln
	s.metricsSrv = &http.Server{
		Handler:           metrics.HandlerWithOptions(s.metrics, s.cfg.Metrics.Token, s.cfg.Metrics.AllowQueryToken),
		ReadHeaderTimeout: 15 * time.Second,
	}

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := s.metricsSrv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Warn("metrics server error", "err", err)
		}
	}()
	return nil
}

// MetricsAddr returns the bound metrics listener address, or "" if disabled.
func (s *Server) MetricsAddr() string {
	if s.metricsLn == nil {
		return ""
	}
	return s.metricsLn.Addr().String()
}

// HTTPProxyAddr returns the bound HTTP reverse proxy listener address, or "" if disabled.
func (s *Server) HTTPProxyAddr() string {
	if s.httpLn == nil {
		return ""
	}
	return s.httpLn.Addr().String()
}

func (s *Server) registerHTTPRoute(ctx context.Context, sess *session.Session, tunID string, req message.TunnelCreate) (string, error) {
	if s.httpLn == nil {
		return "", errors.New("http_proxy_port is not enabled on server")
	}
	prefix := normalizeHTTPPath(req.HTTPPath)

	s.httpMu.Lock()
	defer s.httpMu.Unlock()
	if existing, exists := s.httpRoutes[prefix]; exists {
		return "", fmt.Errorf("http_path %q is already registered by tunnel %s", prefix, existing.tunnelID)
	}

	route := &httpRoute{
		tunnelID:    tunID,
		prefix:      prefix,
		localAddr:   req.LocalAddr,
		stripPrefix: req.StripPrefix,
		sess:        sess,
	}
	transport := &http.Transport{
		DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			return s.dialTunnelStream(ctx, dialCtx, route)
		},
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   20,
		MaxConnsPerHost:       100,
		IdleConnTimeout:       60 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}
	route.proxy = &httputil.ReverseProxy{
		// Negative value flushes immediately after each write, keeping SSE and
		// chunked responses responsive even when Content-Length is known.
		FlushInterval: -1,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = route.localAddr
			// Backends doing Host-based virtual hosting must see the real local
			// target instead of the public proxy host.
			pr.Out.Host = route.localAddr
			if route.stripPrefix && route.prefix != "/" {
				trimmed := strings.TrimPrefix(pr.In.URL.Path, route.prefix)
				if trimmed == "" {
					trimmed = "/"
				}
				pr.Out.URL.Path = trimmed
				if pr.In.URL.RawPath != "" {
					pr.Out.URL.RawPath = strings.TrimPrefix(pr.In.URL.RawPath, route.prefix)
					if pr.Out.URL.RawPath == "" {
						pr.Out.URL.RawPath = "/"
					}
				}
				pr.Out.Header.Set("X-Forwarded-Prefix", route.prefix)
			}
			pr.SetXForwarded()
		},
		Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "iplink bad gateway: "+err.Error(), http.StatusBadGateway)
		},
	}

	s.httpRoutes[prefix] = route
	return prefix, nil
}

func (s *Server) unregisterHTTPRoute(prefix, tunID string) {
	s.httpMu.Lock()
	if r, ok := s.httpRoutes[prefix]; ok && r.tunnelID == tunID {
		delete(s.httpRoutes, prefix)
	}
	s.httpMu.Unlock()
}

func (s *Server) matchHTTPRoute(reqPath string) *httpRoute {
	s.httpMu.RLock()
	defer s.httpMu.RUnlock()

	var best *httpRoute
	for prefix, r := range s.httpRoutes {
		if prefix == "/" || reqPath == prefix || strings.HasPrefix(reqPath, prefix+"/") {
			if best == nil || len(prefix) > len(best.prefix) {
				best = r
			}
		}
	}
	return best
}

func (s *Server) serveHTTPProxy(w http.ResponseWriter, r *http.Request) {
	route := s.matchHTTPRoute(r.URL.Path)
	if route == nil {
		http.Error(w, "iplink: no reverse proxy route matched", http.StatusNotFound)
		return
	}
	route.proxy.ServeHTTP(w, r)
}

func (s *Server) dialTunnelStream(serverCtx, dialCtx context.Context, route *httpRoute) (net.Conn, error) {
	serverSide, clientSide := net.Pipe()
	connID := s.nextConnID.Add(1)
	pc := &proxyConn{
		id:       connID,
		tunnelID: route.tunnelID,
		conn:     clientSide,
		sendCh:   make(chan []byte, streamQueueSize),
		readyCh:  make(chan bool, 1),
		done:     make(chan struct{}),
	}
	s.connsMu.Lock()
	s.proxyConns[connID] = pc
	s.connsMu.Unlock()

	openFrame, err := codec.EncodeJSON(protocol.MsgTunnelOpenConn, 0, route.sess.ID, message.TunnelOpenConn{
		TunnelID:   route.tunnelID,
		ConnID:     connID,
		LocalAddr:  route.localAddr,
		RemotePeer: "http-proxy",
	})
	if err != nil || route.sess.SendFrame(openFrame) != nil {
		s.closeProxyConn(connID)
		_ = serverSide.Close()
		return nil, errors.New("failed to open tunnel stream to client")
	}

	select {
	case ok := <-pc.readyCh:
		if !ok {
			s.closeProxyConn(connID)
			_ = serverSide.Close()
			return nil, errors.New("client rejected local target connection")
		}
	case <-time.After(5 * time.Second):
		s.closeProxyConn(connID)
		_ = serverSide.Close()
		return nil, errors.New("timed out waiting for client local dial")
	case <-dialCtx.Done():
		s.closeProxyConn(connID)
		_ = serverSide.Close()
		return nil, dialCtx.Err()
	case <-serverCtx.Done():
		s.closeProxyConn(connID)
		_ = serverSide.Close()
		return nil, serverCtx.Err()
	}

	s.activateProxyConn(pc)
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		s.writeProxyConnLoop(pc)
	}()
	go func() {
		defer s.wg.Done()
		s.readProxyConnLoop(route.sess, pc)
	}()

	return serverSide, nil
}
