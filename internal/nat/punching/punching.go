package punching

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

const (
	punchPrefix    = "IPLINK_PUNCH:"
	punchAckPrefix = "IPLINK_PUNCH_ACK:"
)

var ErrPunchTimeout = errors.New("nat: UDP hole punching timed out")

// Punch attempts direct UDP hole punching on pc toward candidateAddrs using punchToken.
// On success, it returns the verified peer *net.UDPAddr. On failure, callers must fall back to Relay.
func Punch(ctx context.Context, pc net.PacketConn, punchToken string, candidateAddrs []string) (*net.UDPAddr, error) {
	if pc == nil {
		return nil, errors.New("nat: PacketConn is nil")
	}
	targets := make([]*net.UDPAddr, 0, len(candidateAddrs))
	for _, raw := range candidateAddrs {
		if raw == "" {
			continue
		}
		ua, err := net.ResolveUDPAddr("udp", raw)
		if err == nil {
			targets = append(targets, ua)
		}
	}
	if len(targets) == 0 {
		return nil, errors.New("nat: no valid candidate addresses for punching")
	}

	punchMsg := []byte(punchPrefix + punchToken)
	ackMsg := []byte(punchAckPrefix + punchToken)

	punchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Periodically transmit punch probes to all candidate endpoints.
	go func() {
		ticker := time.NewTicker(150 * time.Millisecond)
		defer ticker.Stop()
		for _, t := range targets {
			_, _ = pc.WriteTo(punchMsg, t)
		}
		for {
			select {
			case <-punchCtx.Done():
				return
			case <-ticker.C:
				for _, t := range targets {
					_, _ = pc.WriteTo(punchMsg, t)
				}
			}
		}
	}()

	buf := make([]byte, 1024)
	for {
		if err := pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			return nil, err
		}
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if punchCtx.Err() != nil {
					_ = pc.SetReadDeadline(time.Time{})
					return nil, ErrPunchTimeout
				}
				continue
			}
			_ = pc.SetReadDeadline(time.Time{})
			return nil, fmt.Errorf("nat punch read: %w", err)
		}
		payload := buf[:n]
		if bytes.Equal(payload, punchMsg) {
			// Peer punch received: send ack and return verified peer address.
			_, _ = pc.WriteTo(ackMsg, addr)
			_ = pc.SetReadDeadline(time.Time{})
			if ua, ok := addr.(*net.UDPAddr); ok {
				return ua, nil
			}
			return net.ResolveUDPAddr("udp", addr.String())
		}
		if bytes.Equal(payload, ackMsg) {
			_ = pc.SetReadDeadline(time.Time{})
			if ua, ok := addr.(*net.UDPAddr); ok {
				return ua, nil
			}
			return net.ResolveUDPAddr("udp", addr.String())
		}
	}
}
