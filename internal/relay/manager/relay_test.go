package manager

import (
	"testing"
	"time"

	"iplink/pkg/protocol"
)

func TestTokenBucketDisabledAllowsEverything(t *testing.T) {
	var b *tokenBucket // nil = 不限速
	for i := 0; i < 1000; i++ {
		if !b.allow(protocol.MaxUDPPacketSize) {
			t.Fatal("nil bucket must always allow")
		}
	}
}

func TestTokenBucketBurstCapacity(t *testing.T) {
	// 速率低于最大包时，容量仍应能容纳一个最大包，避免首包永远被丢。
	b := newTokenBucket(1024)
	if b.capacity < protocol.MaxUDPPacketSize {
		t.Fatalf("capacity %v < MaxUDPPacketSize %d", b.capacity, protocol.MaxUDPPacketSize)
	}
	if !b.allow(protocol.MaxUDPPacketSize) {
		t.Fatal("first max-size packet must pass via burst capacity")
	}
	// 首包耗尽令牌后，紧随的大包应被拒绝。
	if b.allow(protocol.MaxUDPPacketSize) {
		t.Fatal("second max-size packet should be denied before refill")
	}
}

func TestTokenBucketRefillsOverTime(t *testing.T) {
	const rate = 100_000 // 100 KB/s
	b := newTokenBucket(rate)
	payload := 10_000

	// 先消耗到接近空。
	for b.allow(payload) {
	}
	time.Sleep(150 * time.Millisecond)
	if !b.allow(payload) {
		t.Fatal("bucket should refill after wait")
	}
}

func TestTokenBucketEnforcesRate(t *testing.T) {
	const rate = 20_000 // 20 KB/s
	b := newTokenBucket(rate)
	payload := 4_000

	passed := 0
	start := time.Now()
	for time.Since(start) < 200*time.Millisecond {
		if b.allow(payload) {
			passed++
		} else {
			time.Sleep(5 * time.Millisecond)
		}
	}
	// 桶容量 >= 64KB，首轮突发可能通过多个包；200ms 内补充约 4KB。
	// 这里只断言没有无限制通过（避免 200ms 内通过 >100 个包这种失控情况）。
	if passed > 100 {
		t.Fatalf("rate limiting ineffective: %d packets passed in 200ms", passed)
	}
	if passed == 0 {
		t.Fatal("no packets passed at all")
	}
}
