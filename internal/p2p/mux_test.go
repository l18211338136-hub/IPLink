package p2p

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"sync"
	"testing"
	"time"
)

type memTransport struct {
	sendCh   chan []byte
	recvCh   chan []byte
	dropOnce sync.Map
	dropMod  int
	counter  int
	mu       sync.Mutex
}

func newMemPair(dropEveryN int) (*memTransport, *memTransport) {
	ab := make(chan []byte, 256)
	ba := make(chan []byte, 256)
	return &memTransport{sendCh: ab, recvCh: ba, dropMod: dropEveryN},
		&memTransport{sendCh: ba, recvCh: ab, dropMod: dropEveryN}
}

func (t *memTransport) Send(p []byte) error {
	t.mu.Lock()
	t.counter++
	n := t.counter
	t.mu.Unlock()
	if t.dropMod > 0 && n%t.dropMod == 0 {
		return nil // simulate packet loss
	}
	cp := make([]byte, len(p))
	copy(cp, p)
	select {
	case t.sendCh <- cp:
	default:
	}
	return nil
}

func (t *memTransport) Receive(ctx context.Context) ([]byte, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case p := <-t.recvCh:
		return p, nil
	}
}

func TestMuxReliableStreamWithLoss(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Drop 1 out of every 5 packets to verify ARQ retransmission & ordering.
	ta, tb := newMemPair(5)
	muxA := NewMux(ctx, ta, true)
	defer muxA.Close()
	muxB := NewMux(ctx, tb, false)
	defer muxB.Close()

	payload := make([]byte, 64*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}

	errCh := make(chan error, 1)
	go func() {
		conn, target, err := muxB.Accept(ctx)
		if err != nil {
			errCh <- err
			return
		}
		defer conn.Close()
		if target != "127.0.0.1:3389" {
			errCh <- io.ErrUnexpectedEOF
			return
		}
		got, err := io.ReadAll(conn)
		if err != nil {
			errCh <- err
			return
		}
		if !bytes.Equal(got, payload) {
			errCh <- io.ErrShortBuffer
			return
		}
		errCh <- nil
	}()

	connA, err := muxA.OpenStream(ctx, "127.0.0.1:3389")
	if err != nil {
		t.Fatalf("OpenStream failed: %v", err)
	}
	if _, err := connA.Write(payload); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	_ = connA.Close()

	if err := <-errCh; err != nil {
		t.Fatalf("server side verify failed: %v", err)
	}
}

