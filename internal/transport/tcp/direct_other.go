//go:build !windows

package tcp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
)

// ErrDirectUnsupported is returned on platforms where physical interface binding is not implemented.
var ErrDirectUnsupported = errors.New("direct physical interface dial is only supported on Windows")

// DialDirect is only implemented on Windows to bypass virtual TUN/VPN adapters.
func DialDirect(_ context.Context, _ string, _ *tls.Config) (net.Conn, error) {
	return nil, ErrDirectUnsupported
}

// ListenPacketDirect is only implemented on Windows to bypass virtual TUN/VPN adapters.
func ListenPacketDirect(_ context.Context) (net.PacketConn, error) {
	return nil, ErrDirectUnsupported
}
