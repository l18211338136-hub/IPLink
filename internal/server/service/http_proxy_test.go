package service

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"testing"
	"time"

	"iplink/internal/protocol/message"
)

func TestRegisterHTTPRouteProxySettings(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	s := &Server{httpLn: ln, httpRoutes: make(map[string]*httpRoute)}
	prefix, err := s.registerHTTPRoute(context.Background(), nil, "tun-x", message.TunnelCreate{
		LocalAddr: "127.0.0.1:8080",
		HTTPPath:  "/stream",
	})
	if err != nil {
		t.Fatal(err)
	}
	route := s.httpRoutes[prefix]
	if route == nil {
		t.Fatal("route not registered")
	}
	if route.proxy.FlushInterval != -1 {
		t.Fatalf("FlushInterval = %v, want -1 (immediate flush)", route.proxy.FlushInterval)
	}

	transport, ok := route.proxy.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport type = %T, want *http.Transport", route.proxy.Transport)
	}
	if transport.MaxConnsPerHost != 100 || transport.ResponseHeaderTimeout != 30*time.Second {
		t.Fatalf("transport limits = (%d, %v), want (100, 30s)",
			transport.MaxConnsPerHost, transport.ResponseHeaderTimeout)
	}

	// Host-based backends must see the local target, not the public proxy host.
	in := httptest.NewRequest(http.MethodGet, "http://public.example/stream", nil)
	out := httptest.NewRequest(http.MethodGet, "http://placeholder/stream", nil)
	route.proxy.Rewrite(&httputil.ProxyRequest{In: in, Out: out})
	if out.Host != "127.0.0.1:8080" {
		t.Fatalf("rewritten Host = %q, want %q", out.Host, "127.0.0.1:8080")
	}
	if out.URL.Host != "127.0.0.1:8080" {
		t.Fatalf("rewritten URL.Host = %q, want %q", out.URL.Host, "127.0.0.1:8080")
	}
}
