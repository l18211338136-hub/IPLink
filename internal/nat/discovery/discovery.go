package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"time"

	"iplink/internal/protocol/message"
	dgramcrypto "iplink/internal/security/crypto"
	"iplink/pkg/protocol"
)

// Server listens on UDP and reflects the sender's observed public IP:port.
type Server struct {
	conn   net.PacketConn
	log    *slog.Logger
	cipher *dgramcrypto.DatagramCipher
}

// StartServer binds a UDP socket on addr and serves NATProbe requests until ctx is cancelled.
// cipher encrypts probe/ack datagrams; it must be non-nil so NAT traffic is never left in cleartext.
func StartServer(ctx context.Context, addr string, cipher *dgramcrypto.DatagramCipher, log *slog.Logger) (*Server, error) {
	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen NAT UDP %s: %w", addr, err)
	}
	s := &Server{conn: pc, log: log, cipher: cipher}
	go s.serve(ctx)
	return s, nil
}

func (s *Server) serve(ctx context.Context) {
	defer s.conn.Close()
	go func() {
		<-ctx.Done()
		_ = s.conn.Close()
	}()

	buf := make([]byte, protocol.MaxUDPPacketSize)
	for {
		n, peerAddr, err := s.conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			s.log.Debug("NAT discovery read error", "err", err)
			continue
		}
		plain, err := s.cipher.Open(buf[:n])
		if err != nil {
			continue
		}
		var probe message.NATProbe
		if err := json.Unmarshal(plain, &probe); err != nil {
			continue
		}
		ack := message.NATProbeAck{
			PublicAddr: peerAddr.String(),
			Nonce:      probe.Nonce,
		}
		respJSON, err := json.Marshal(ack)
		if err != nil {
			continue
		}
		resp := s.cipher.Seal(respJSON)
		if _, err := s.conn.WriteTo(resp, peerAddr); err != nil && ctx.Err() == nil {
			s.log.Debug("NAT discovery write error", "peer", peerAddr.String(), "err", err)
		}
	}
}

// Addr returns the bound UDP address of the NAT discovery server.
func (s *Server) Addr() string {
	return s.conn.LocalAddr().String()
}

// Close closes the underlying UDP socket.
func (s *Server) Close() error {
	return s.conn.Close()
}

// DiscoverPublicAddr sends a NATProbe from localConn (or an ephemeral UDP socket if nil)
// to serverNATAddr and returns the observed public IP:port.
func DiscoverPublicAddr(ctx context.Context, localConn net.PacketConn, serverNATAddr, clientID, nonce string, cipher *dgramcrypto.DatagramCipher) (string, error) {
	ownConn := false
	if localConn == nil {
		var err error
		localConn, err = net.ListenPacket("udp", ":0")
		if err != nil {
			return "", fmt.Errorf("open UDP socket: %w", err)
		}
		ownConn = true
	}
	if ownConn {
		defer localConn.Close()
	}

	raddr, err := net.ResolveUDPAddr("udp", serverNATAddr)
	if err != nil {
		return "", fmt.Errorf("resolve NAT server %q: %w", serverNATAddr, err)
	}

	reqBytes, err := json.Marshal(message.NATProbe{
		ClientID: clientID,
		Nonce:    nonce,
	})
	if err != nil {
		return "", err
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(3 * time.Second)
	}
	_ = localConn.SetDeadline(deadline)
	defer func() { _ = localConn.SetDeadline(time.Time{}) }()

	if _, err := localConn.WriteTo(cipher.Seal(reqBytes), raddr); err != nil {
		return "", fmt.Errorf("send NAT probe: %w", err)
	}

	buf := make([]byte, 2048)
	for {
		n, _, err := localConn.ReadFrom(buf)
		if err != nil {
			return "", fmt.Errorf("read NAT probe ack: %w", err)
		}
		plain, err := cipher.Open(buf[:n])
		if err != nil {
			continue
		}
		var ack message.NATProbeAck
		if err := json.Unmarshal(plain, &ack); err != nil {
			continue
		}
		if ack.Nonce == nonce && ack.PublicAddr != "" {
			return ack.PublicAddr, nil
		}
	}
}
