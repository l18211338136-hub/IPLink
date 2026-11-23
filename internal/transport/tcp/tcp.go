package tcp

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// Listen starts a TCP listener (or TLS 1.3 listener when tlsCfg is non-nil) on addr.
func Listen(ctx context.Context, addr string, tlsCfg *tls.Config) (net.Listener, error) {
	lc := net.ListenConfig{
		KeepAlive: 15 * time.Second,
	}
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if tlsCfg != nil {
		return tls.NewListener(ln, tlsCfg), nil
	}
	return ln, nil
}

// Dial connects to addr over TCP (or TLS 1.3 when tlsCfg is non-nil) with context cancellation.
func Dial(ctx context.Context, addr string, tlsCfg *tls.Config) (net.Conn, error) {
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 15 * time.Second,
	}
	if tlsCfg != nil {
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    tlsCfg,
		}
		return tlsDialer.DialContext(ctx, "tcp", addr)
	}
	return dialer.DialContext(ctx, "tcp", addr)
}
