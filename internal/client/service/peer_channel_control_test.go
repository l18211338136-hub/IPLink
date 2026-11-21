package service

import (
	"context"
	"net"
	"testing"
	"time"

	clientcrypto "iplink/internal/security/crypto"
)

func TestRelayJoinPacketIsNotDeliveredAsPayload(t *testing.T) {
	cipher, err := clientcrypto.NewDatagramCipher("join-filter-token")
	if err != nil {
		t.Fatal(err)
	}

	aPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer aPC.Close()

	bPC, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bPC.Close()

	a := newPeerChannel("p2p", "b", aPC, bPC.LocalAddr(), "", "", cipher)
	b := newPeerChannel("p2p", "a", bPC, aPC.LocalAddr(), "", "", cipher)
	defer a.Close()
	defer b.Close()

	if err := a.Send([]byte(peerRelayJoinPrefix + "rly-test")); err != nil {
		t.Fatal(err)
	}
	shortCtx, cancelShort := context.WithTimeout(context.Background(), 120*time.Millisecond)
	defer cancelShort()
	if got, err := b.Receive(shortCtx); err == nil {
		t.Fatalf("relay JOIN control packet leaked as payload: %q", got)
	}

	if err := a.Send([]byte("real-payload")); err != nil {
		t.Fatal(err)
	}
	recvCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	got, err := b.Receive(recvCtx)
	if err != nil {
		t.Fatalf("receive real payload: %v", err)
	}
	if string(got) != "real-payload" {
		t.Fatalf("payload = %q, want %q", got, "real-payload")
	}
}
