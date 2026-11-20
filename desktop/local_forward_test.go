package main

import (
	"io"
	"net"
	"testing"
	"time"
)

func TestLocalForwardManager(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echoLn.Close()

	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}(c)
		}
	}()

	// Pick a free listen port.
	probeLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe port: %v", err)
	}
	listenAddr := probeLn.Addr().String()
	_ = probeLn.Close()

	mgr := NewLocalForwardManager(nil)
	defer mgr.StopAll()

	mgr.Apply([]LocalForwardRule{
		{
			Name:       "test-5000-to-6000",
			ListenAddr: listenAddr,
			TargetAddr: echoLn.Addr().String(),
			Enabled:    true,
		},
	})

	statuses := mgr.Statuses()
	if len(statuses) != 1 || !statuses[0].Running {
		t.Fatalf("expected running forwarder, got %+v", statuses)
	}

	conn, err := net.DialTimeout("tcp", listenAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial forwarder: %v", err)
	}
	defer conn.Close()

	msg := "hello-iplink"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("got %q, want %q", string(buf), msg)
	}
}
