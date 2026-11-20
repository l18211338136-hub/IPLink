package punching

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	dgramcrypto "iplink/internal/security/crypto"
)

type punchResult struct {
	addr *net.UDPAddr
	err  error
}

func testCipher(t *testing.T) *dgramcrypto.DatagramCipher {
	t.Helper()
	c, err := dgramcrypto.NewDatagramCipher("punch-test-token")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newPunchSocket(t *testing.T) net.PacketConn {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc
}

func runPunch(ctx context.Context, pc net.PacketConn, token string, candidates []string, cipher *dgramcrypto.DatagramCipher) <-chan punchResult {
	done := make(chan punchResult, 1)
	go func() {
		addr, err := Punch(ctx, pc, token, candidates, cipher)
		done <- punchResult{addr: addr, err: err}
	}()
	return done
}

func waitPunch(t *testing.T, done <-chan punchResult) punchResult {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(3 * time.Second):
		t.Fatal("Punch did not return in time")
		return punchResult{}
	}
}

func TestPunchBothSidesSameToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cipher := testCipher(t)
	pcA := newPunchSocket(t)
	pcB := newPunchSocket(t)
	doneA := runPunch(ctx, pcA, "token-shared", []string{pcB.LocalAddr().String()}, cipher)
	doneB := runPunch(ctx, pcB, "token-shared", []string{pcA.LocalAddr().String()}, cipher)

	resB := waitPunch(t, doneB)
	if resB.err != nil {
		t.Fatalf("peer B punch: %v", resB.err)
	}
	if resB.addr.String() != pcA.LocalAddr().String() {
		t.Fatalf("peer B resolved %q, want %q", resB.addr, pcA.LocalAddr())
	}

	resA := waitPunch(t, doneA)
	if resA.err != nil {
		t.Fatalf("peer A punch: %v", resA.err)
	}
	if resA.addr.String() != pcB.LocalAddr().String() {
		t.Fatalf("peer A resolved %q, want %q", resA.addr, pcB.LocalAddr())
	}
}

func TestPunchCompletesOnAckOnly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	cipher := testCipher(t)
	pcA := newPunchSocket(t)
	pcB := newPunchSocket(t)
	doneA := runPunch(ctx, pcA, "token-ack", []string{pcB.LocalAddr().String()}, cipher)

	go func() {
		buf := make([]byte, 1024)
		n, from, err := pcB.ReadFrom(buf)
		if err != nil {
			return
		}
		plain, err := cipher.Open(buf[:n])
		if err != nil || string(plain) != punchPrefix+"token-ack" {
			return
		}
		_, _ = pcB.WriteTo(cipher.Seal([]byte(punchAckPrefix+"token-ack")), from)
	}()
	go func() {
		_, _ = pcA.WriteTo(cipher.Seal([]byte(punchPrefix+"token-ack")), pcB.LocalAddr())
	}()

	res := waitPunch(t, doneA)
	if res.err != nil {
		t.Fatalf("punch via ACK: %v", res.err)
	}
	if res.addr.String() != pcB.LocalAddr().String() {
		t.Fatalf("resolved %q, want %q", res.addr, pcB.LocalAddr())
	}
}

func TestPunchIgnoresMismatchedToken(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()

	cipher := testCipher(t)
	pcA := newPunchSocket(t)
	pcB := newPunchSocket(t)
	doneA := runPunch(ctx, pcA, "token-good", []string{pcB.LocalAddr().String()}, cipher)

	go func() {
		for i := 0; i < 20; i++ {
			_, _ = pcB.WriteTo(cipher.Seal([]byte(punchPrefix+"token-bad")), pcA.LocalAddr())
			time.Sleep(20 * time.Millisecond)
		}
	}()

	res := waitPunch(t, doneA)
	if !errors.Is(res.err, ErrPunchTimeout) {
		t.Fatalf("expected ErrPunchTimeout for mismatched token, got %v", res.err)
	}
	if res.addr != nil {
		t.Fatalf("expected no verified address, got %v", res.addr)
	}
}

func TestPunchIgnoresCleartextPackets(t *testing.T) {
	// 密文通道下，明文打洞包（旧版本/攻击者）必须被忽略，不能骗过验证。
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	cipher := testCipher(t)
	pcA := newPunchSocket(t)
	pcB := newPunchSocket(t)
	doneA := runPunch(ctx, pcA, "token-good", []string{pcB.LocalAddr().String()}, cipher)

	go func() {
		for i := 0; i < 20; i++ {
			_, _ = pcB.WriteTo([]byte(punchPrefix+"token-good"), pcA.LocalAddr())
			time.Sleep(20 * time.Millisecond)
		}
	}()

	res := waitPunch(t, doneA)
	if !errors.Is(res.err, ErrPunchTimeout) {
		t.Fatalf("cleartext punch must be ignored, got %v", res.err)
	}
}

func TestPunchRejectsEmptyCandidates(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer pc.Close()

	_, err = Punch(context.Background(), pc, "token", []string{"", "not-an-address"}, testCipher(t))
	if err == nil {
		t.Fatal("expected error for empty candidate list")
	}
}
