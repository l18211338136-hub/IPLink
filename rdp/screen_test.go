package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestScreenFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	want := []byte("hello-frame")
	if err := writeScreenFrame(&buf, msgScreenInfo, want); err != nil {
		t.Fatalf("writeScreenFrame: %v", err)
	}
	mt, got, err := readScreenFrame(&buf)
	if err != nil {
		t.Fatalf("readScreenFrame: %v", err)
	}
	if mt != msgScreenInfo || !bytes.Equal(got, want) {
		t.Fatalf("got (%d, %q), want (%d, %q)", mt, got, msgScreenInfo, want)
	}
}

func TestScreenHostAndViewerBridge(t *testing.T) {
	host, err := StartScreenHostOn("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("StartScreenHostOn: %v", err)
	}
	defer host.Close()

	bridge, err := StartScreenViewerBridge(host.Addr(), nil)
	if err != nil {
		t.Fatalf("StartScreenViewerBridge: %v", err)
	}
	defer bridge.Close()

	ws, _, err := websocket.DefaultDialer.Dial(bridge.URL, nil)
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	defer ws.Close()

	_ = ws.SetReadDeadline(time.Now().Add(5 * time.Second))
	mt, infoData, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read screen info: %v", err)
	}
	if mt != websocket.TextMessage || len(infoData) == 0 {
		t.Fatalf("unexpected info message: type=%d len=%d", mt, len(infoData))
	}

	mt, frameData, err := ws.ReadMessage()
	if err != nil {
		t.Fatalf("read jpeg frame: %v", err)
	}
	if mt != websocket.BinaryMessage || len(frameData) < 7 || frameData[0] != msgScreenJPEG {
		t.Fatalf("unexpected frame message: type=%d len=%d", mt, len(frameData))
	}
	w := binary.BigEndian.Uint16(frameData[1:3])
	h := binary.BigEndian.Uint16(frameData[3:5])
	// Verify JPEG SOI marker (0xFF 0xD8).
	if w == 0 || h == 0 || frameData[5] != 0xFF || frameData[6] != 0xD8 {
		t.Fatalf("invalid JPEG frame: %dx%d header=%x", w, h, frameData[5:7])
	}
	t.Logf("received valid screen JPEG frame: %dx%d (%d bytes)", w, h, len(frameData)-5)

	// Verify dedicated input stream accepts events without closing the video stream.
	if err := ws.WriteMessage(websocket.TextMessage, []byte(`{"t":"config","scale":0.75,"quality":55,"fps":18}`)); err != nil {
		t.Fatalf("write config event: %v", err)
	}
	if err := ws.WriteMessage(websocket.TextMessage, []byte(`{"t":"keyup","vk":0}`)); err != nil {
		t.Fatalf("write input event: %v", err)
	}
}

func TestFileTransferEndToEnd(t *testing.T) {
	host, err := StartScreenHostOn("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("StartScreenHostOn: %v", err)
	}
	defer host.Close()

	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "iplink-test-payload.bin")
	payload := bytes.Repeat([]byte("IPLINK_P2P_FILE_TEST_0123456789\n"), 4096) // ~128 KB
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	var lastSent int64
	savedPath, err := sendFileOverAddr(host.Addr(), srcPath, func(sent, total, _ int64, _ bool) {
		lastSent = sent
	})
	if err != nil {
		t.Fatalf("sendFileOverAddr: %v", err)
	}
	defer os.Remove(savedPath)

	got, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("read saved file %s: %v", savedPath, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("saved file mismatch: got %d bytes, want %d bytes", len(got), len(payload))
	}
	if lastSent != int64(len(payload)) {
		t.Fatalf("progress lastSent=%d, want %d", lastSent, len(payload))
	}
	t.Logf("file transferred and verified: %s (%d bytes)", savedPath, len(got))
}

func TestFileTransferResume(t *testing.T) {
	host, err := StartScreenHostOn("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("StartScreenHostOn: %v", err)
	}
	defer host.Close()

	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "iplink-resume-test.bin")
	payload := bytes.Repeat([]byte("RESUME_CHECKPOINT_DATA_987654321\n"), 6000) // ~198 KB
	if err := os.WriteFile(srcPath, payload, 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	// Pre-seed a 50% .iplinkpart file in the receive dir to simulate an interrupted transfer.
	f, err := os.Open(srcPath)
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	tid := computeFileTransferID(f, filepath.Base(srcPath), int64(len(payload)))
	_ = f.Close()

	saveDir, err := defaultReceiveDir()
	if err != nil {
		t.Fatalf("defaultReceiveDir: %v", err)
	}
	half := len(payload) / 2
	partPath := partFilePath(saveDir, sanitizeFileName(filepath.Base(srcPath)), tid)
	if err := os.WriteFile(partPath, payload[:half], 0o644); err != nil {
		t.Fatalf("write partial checkpoint: %v", err)
	}
	defer os.Remove(partPath)

	sawResume := false
	savedPath, err := sendFileOverAddr(host.Addr(), srcPath, func(sent, total, _ int64, resumed bool) {
		if resumed {
			sawResume = true
		}
	})
	if err != nil {
		t.Fatalf("sendFileOverAddr resume: %v", err)
	}
	defer os.Remove(savedPath)

	if !sawResume {
		t.Fatalf("expected resumed=true when .iplinkpart checkpoint existed")
	}
	got, err := os.ReadFile(savedPath)
	if err != nil {
		t.Fatalf("read resumed file: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("resumed file content mismatch: got %d bytes, want %d bytes", len(got), len(payload))
	}
	if _, err := os.Stat(partPath); !os.IsNotExist(err) {
		t.Fatalf("expected .iplinkpart to be renamed/removed after completion")
	}
	t.Logf("resumed transfer from %d/%d bytes and verified intact: %s", half, len(payload), savedPath)
}

func TestScreenHostCloseWithActiveConn(t *testing.T) {
	host, err := StartScreenHostOn("127.0.0.1:0", nil)
	if err != nil {
		t.Fatalf("StartScreenHostOn: %v", err)
	}
	bridge, err := StartScreenViewerBridge(host.Addr(), nil)
	if err != nil {
		_ = host.Close()
		t.Fatalf("StartScreenViewerBridge: %v", err)
	}
	defer bridge.Close()

	ws, _, err := websocket.DefaultDialer.Dial(bridge.URL, nil)
	if err != nil {
		_ = host.Close()
		t.Fatalf("ws dial: %v", err)
	}
	defer ws.Close()

	// Wait until host has accepted both video and input streams.
	_ = ws.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, _, _ = ws.ReadMessage()

	start := time.Now()
	if err := host.Close(); err != nil {
		t.Fatalf("host.Close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("host.Close took too long (%v) with active connections", elapsed)
	}
}

func TestHybridTileClassifier(t *testing.T) {
	w, h := 64, 64
	stride := w * 4

	// Solid background + crisp text-like pixels => should classify as UI/Text (PNG).
	ui := make([]byte, w*h*4)
	for i := 0; i < len(ui); i += 4 {
		ui[i], ui[i+1], ui[i+2], ui[i+3] = 30, 30, 30, 255
	}
	for x := 8; x < 56; x++ {
		off := (20*w + x) * 4
		ui[off], ui[off+1], ui[off+2] = 240, 240, 240
	}
	if !isTextOrUITile(ui, stride, 0, 0, w, h) {
		t.Fatalf("expected UI/text tile to be classified as lossless PNG")
	}

	// Rich gradient/photo tile => should classify as photo (JPEG).
	photo := make([]byte, w*h*4)
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			off := (y*w + x) * 4
			photo[off] = byte((x * 4) & 0xFF)
			photo[off+1] = byte((y * 4) & 0xFF)
			photo[off+2] = byte(((x + y) * 3) & 0xFF)
			photo[off+3] = 255
		}
	}
	if isTextOrUITile(photo, stride, 0, 0, w, h) {
		t.Fatalf("expected rich photo tile to be classified as JPEG")
	}
}

