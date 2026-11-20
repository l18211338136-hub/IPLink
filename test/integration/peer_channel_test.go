package integration

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"

	clientservice "iplink/internal/client/service"
	"iplink/internal/config"
	"iplink/internal/logger"
)

func startPeerClient(t *testing.T, ctx context.Context, token string, ctrlPort, relayPort, natPort int, id string, p2p bool) (*clientservice.Client, <-chan error) {
	t.Helper()
	cfg := config.DefaultClientConfig()
	cfg.Client.ID = id
	cfg.Server.Address = "127.0.0.1"
	cfg.Server.Port = ctrlPort
	cfg.Server.RelayPort = relayPort
	cfg.Server.NATPort = natPort
	cfg.Security.Token = token
	cfg.Network.EnableP2P = p2p
	cfg.Tunnels = nil

	cli, err := clientservice.New(cfg, logger.New("warn", "text", io.Discard))
	if err != nil {
		t.Fatal(err)
	}
	done, err := cli.Start(ctx)
	if err != nil {
		t.Fatalf("client %s start: %v", id, err)
	}
	return cli, done
}

func waitIncomingPeer(t *testing.T, cli *clientservice.Client, peerID string) *clientservice.PeerChannel {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ch := cli.IncomingPeer(peerID); ch != nil {
			return ch
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("incoming channel from %s was not registered", peerID)
	return nil
}

func verifyPeerChannel(t *testing.T, ctx context.Context, a, b *clientservice.PeerChannel, wantMode string) {
	t.Helper()
	if a.Mode != wantMode || b.Mode != wantMode {
		t.Fatalf("channel modes = (%q, %q), want %q", a.Mode, b.Mode, wantMode)
	}
	if _, err := a.Ping(ctx); err != nil {
		t.Fatalf("ping over %s channel: %v", wantMode, err)
	}

	recvCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	if err := a.Send([]byte("from-a")); err != nil {
		t.Fatalf("A send: %v", err)
	}
	got, err := b.Receive(recvCtx)
	if err != nil || !bytes.Equal(got, []byte("from-a")) {
		t.Fatalf("B receive = %q, err = %v", got, err)
	}

	if err := b.Send([]byte("from-b")); err != nil {
		t.Fatalf("B send: %v", err)
	}
	got, err = a.Receive(recvCtx)
	if err != nil || !bytes.Equal(got, []byte("from-b")) {
		t.Fatalf("A receive = %q, err = %v", got, err)
	}
}

func TestP2PChannelBidirectional(t *testing.T) {
	const token = "p2p-channel-secret"
	_, ctrlPort, relayPort, natPort, stopSrv := startTestServer(t, token)
	defer stopSrv()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cliA, doneA := startPeerClient(t, ctx, token, ctrlPort, relayPort, natPort, "client-a", true)
	cliB, doneB := startPeerClient(t, ctx, token, ctrlPort, relayPort, natPort, "client-b", true)
	defer func() {
		cancel()
		<-doneA
		<-doneB
	}()

	chA, err := cliA.ConnectPeer(ctx, "client-b")
	if err != nil {
		t.Fatalf("ConnectPeer: %v", err)
	}
	defer chA.Close()
	if chA.Mode != "p2p" {
		t.Fatalf("expected p2p mode on localhost, got %q", chA.Mode)
	}

	chB := waitIncomingPeer(t, cliB, "client-a")
	defer chB.Close()

	verifyPeerChannel(t, ctx, chA, chB, "p2p")
}

func TestRelayChannelBothEndsNotified(t *testing.T) {
	const token = "relay-notify-secret"
	_, ctrlPort, relayPort, natPort, stopSrv := startTestServer(t, token)
	defer stopSrv()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cliA, doneA := startPeerClient(t, ctx, token, ctrlPort, relayPort, natPort, "client-a", false)
	cliB, doneB := startPeerClient(t, ctx, token, ctrlPort, relayPort, natPort, "client-b", false)
	defer func() {
		cancel()
		<-doneA
		<-doneB
	}()

	chA, err := cliA.ConnectPeer(ctx, "client-b")
	if err != nil {
		t.Fatalf("ConnectPeer: %v", err)
	}
	defer chA.Close()
	if chA.Mode != "relay" {
		t.Fatalf("expected relay mode, got %q", chA.Mode)
	}

	chB := waitIncomingPeer(t, cliB, "client-a")
	defer chB.Close()

	verifyPeerChannel(t, ctx, chA, chB, "relay")

	if _, err := chB.Ping(ctx); err != nil {
		t.Fatalf("reverse ping over relay: %v", err)
	}
}

func TestRelayAllocUnknownPeerRejected(t *testing.T) {
	const token = "relay-missing-secret"
	_, ctrlPort, relayPort, natPort, stopSrv := startTestServer(t, token)
	defer stopSrv()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cliA, doneA := startPeerClient(t, ctx, token, ctrlPort, relayPort, natPort, "client-a", false)
	defer func() {
		cancel()
		<-doneA
	}()

	_, err := cliA.ConnectPeer(ctx, "does-not-exist")
	if err == nil {
		t.Fatal("expected error when target peer is offline")
	}
}
