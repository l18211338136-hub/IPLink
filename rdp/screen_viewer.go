package main

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ScreenViewerBridge exposes a local WebSocket endpoint (ws://127.0.0.1:<port>/ws)
// that bridges binary screen frames and JSON input events over dual P2P/Relay streams
// (one dedicated stream for video, one dedicated low-latency stream for mouse/keyboard input).
type ScreenViewerBridge struct {
	URL        string
	targetAddr string
	srv        *http.Server
	ln         net.Listener

	mu          sync.Mutex
	activeVideo net.Conn
	activeInput net.Conn
	closed      bool
	logFn       func(string)
	upgrader    websocket.Upgrader
}

func StartScreenViewerBridge(forwardListenAddr string, logFn func(string)) (*ScreenViewerBridge, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen viewer bridge: %w", err)
	}
	b := &ScreenViewerBridge{
		URL:        fmt.Sprintf("ws://%s/ws", ln.Addr().String()),
		targetAddr: forwardListenAddr,
		ln:         ln,
		logFn:      logFn,
		upgrader: websocket.Upgrader{
			ReadBufferSize:  4096,
			WriteBufferSize: 64 * 1024,
			CheckOrigin:     func(r *http.Request) bool { return true },
		},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", b.handleWS)
	b.srv = &http.Server{Handler: mux}
	go func() {
		_ = b.srv.Serve(ln)
	}()
	return b, nil
}

func (b *ScreenViewerBridge) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	if b.activeVideo != nil {
		_ = b.activeVideo.Close()
		b.activeVideo = nil
	}
	if b.activeInput != nil {
		_ = b.activeInput.Close()
		b.activeInput = nil
	}
	b.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = b.srv.Shutdown(ctx)
	return b.ln.Close()
}

func (b *ScreenViewerBridge) handleWS(w http.ResponseWriter, r *http.Request) {
	wsConn, err := b.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer wsConn.Close()

	videoConn, err := net.DialTimeout("tcp", b.targetAddr, 8*time.Second)
	if err != nil {
		if b.logFn != nil {
			b.logFn(fmt.Sprintf("同屏画面流连接失败: %v", err))
		}
		_ = wsConn.WriteMessage(websocket.TextMessage, []byte(`{"error":"无法连接远端桌面服务，请确认对方已勾选「允许被同屏远控」"}`))
		return
	}
	defer videoConn.Close()
	if tc, ok := videoConn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}
	_ = writeScreenFrame(videoConn, msgRoleVideo, nil)

	// Open a second dedicated stream for mouse/keyboard input so input never queues behind video frames.
	inputConn, inputErr := net.DialTimeout("tcp", b.targetAddr, 5*time.Second)
	if inputErr == nil {
		defer inputConn.Close()
		if tc, ok := inputConn.(*net.TCPConn); ok {
			_ = tc.SetNoDelay(true)
		}
		_ = writeScreenFrame(inputConn, msgRoleInput, nil)
	}

	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	if b.activeVideo != nil {
		_ = b.activeVideo.Close()
	}
	if b.activeInput != nil {
		_ = b.activeInput.Close()
	}
	b.activeVideo = videoConn
	b.activeInput = inputConn
	b.mu.Unlock()

	done := make(chan struct{})
	// Pump WS text input events -> dedicated input stream (config goes to video stream).
	go func() {
		defer close(done)
		defer videoConn.Close()
		if inputConn != nil {
			defer inputConn.Close()
		}
		for {
			msgType, data, err := wsConn.ReadMessage()
			if err != nil {
				return
			}
			if msgType != websocket.TextMessage || len(data) == 0 {
				continue
			}
			if inputConn != nil && !bytes.Contains(data, []byte(`"config"`)) && !bytes.Contains(data, []byte(`"refresh"`)) {
				if err := writeScreenFrame(inputConn, msgInputEvent, data); err == nil {
					continue
				}
				// Dedicated input stream failed; fall back to video stream so control continues.
				if b.logFn != nil {
					b.logFn("独立输入流断开，已自动切换回主通道发送键鼠事件")
				}
				_ = inputConn.Close()
				inputConn = nil
			}
			if err := writeScreenFrame(videoConn, msgInputEvent, data); err != nil {
				return
			}
		}
	}()

	// Pump remote screen frames -> WS client.
	for {
		msgType, payload, err := readScreenFrame(videoConn)
		if err != nil {
			return
		}
		switch msgType {
		case msgScreenInfo:
			if err := wsConn.WriteMessage(websocket.TextMessage, payload); err != nil {
				return
			}
		case msgScreenJPEG, msgScreenTiles:
			if len(payload) > 4 {
				out := make([]byte, 1+len(payload))
				out[0] = msgType
				copy(out[1:], payload)
				if err := wsConn.WriteMessage(websocket.BinaryMessage, out); err != nil {
					return
				}
			}
		}
	}
}

