//go:build windows

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"image"
	"image/jpeg"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

var (
	modUser32   = syscall.NewLazyDLL("user32.dll")
	modGdi32    = syscall.NewLazyDLL("gdi32.dll")
	modKernel32 = syscall.NewLazyDLL("kernel32.dll")

	procGetSystemMetrics    = modUser32.NewProc("GetSystemMetrics")
	procGetDC               = modUser32.NewProc("GetDC")
	procReleaseDC           = modUser32.NewProc("ReleaseDC")
	procSetCursorPos        = modUser32.NewProc("SetCursorPos")
	procSendInput           = modUser32.NewProc("SendInput")
	procSetProcessDPIAware  = modUser32.NewProc("SetProcessDPIAware")
	procOpenClipboard       = modUser32.NewProc("OpenClipboard")
	procCloseClipboard      = modUser32.NewProc("CloseClipboard")
	procEmptyClipboard      = modUser32.NewProc("EmptyClipboard")
	procSetClipboardData    = modUser32.NewProc("SetClipboardData")
	procGlobalAlloc         = modKernel32.NewProc("GlobalAlloc")
	procGlobalLock          = modKernel32.NewProc("GlobalLock")
	procGlobalUnlock        = modKernel32.NewProc("GlobalUnlock")
	procGlobalFree          = modKernel32.NewProc("GlobalFree")
	procRtlMoveMemory       = modKernel32.NewProc("RtlMoveMemory")
	procCreateCompatibleDC  = modGdi32.NewProc("CreateCompatibleDC")
	procDeleteDC            = modGdi32.NewProc("DeleteDC")
	procCreateDIBSection    = modGdi32.NewProc("CreateDIBSection")
	procSelectObject        = modGdi32.NewProc("SelectObject")
	procDeleteObject        = modGdi32.NewProc("DeleteObject")
	procBitBlt              = modGdi32.NewProc("BitBlt")
	procStretchBlt          = modGdi32.NewProc("StretchBlt")
	procSetStretchBltMode   = modGdi32.NewProc("SetStretchBltMode")

	uipiBlocked atomic.Bool
)

const (
	smCXScreen = 0
	smCYScreen = 1

	srccopy       = 0x00CC0020
	colorOnColor  = 3
	dibRGB        = 0
	biRGB      = 0

	inputMouse    = 0
	inputKeyboard = 1

	mouseEventMove        = 0x0001
	mouseEventLeftDown    = 0x0002
	mouseEventLeftUp      = 0x0004
	mouseEventRightDown   = 0x0008
	mouseEventRightUp     = 0x0010
	mouseEventMiddleDown  = 0x0020
	mouseEventMiddleUp    = 0x0040
	mouseEventWheel       = 0x0800
	mouseEventAbsolute    = 0x8000

	keyEventExtendedKey = 0x0001
	keyEventKeyUp       = 0x0002

	cfUnicodeText = 13
	gmemMoveable  = 0x0002
)

type bitmapInfoHeader struct {
	BiSize          uint32
	BiWidth         int32
	BiHeight        int32
	BiPlanes        uint16
	BiBitCount      uint16
	BiCompression   uint32
	BiSizeImage     uint32
	BiXPelsPerMeter int32
	BiYPelsPerMeter int32
	BiClrUsed       uint32
	BiClrImportant  uint32
}

type bitmapInfo struct {
	BmiHeader bitmapInfoHeader
	BmiColors [1]uint32
}

type mouseInput struct {
	Dx          int32
	Dy          int32
	MouseData   uint32
	DwFlags     uint32
	Time        uint32
	DwExtraInfo uintptr
}

type keybdInput struct {
	WVk         uint16
	WScan       uint16
	DwFlags     uint32
	Time        uint32
	DwExtraInfo uintptr
}

// inputUnion matches the 64-bit Windows INPUT structure (40 bytes on amd64).
type mouseInputStruct struct {
	Type uint32
	_    uint32
	Mi   mouseInput
}

type keybdInputStruct struct {
	Type uint32
	_    uint32
	Ki   keybdInput
	_    [8]byte // pad to match sizeof(INPUT) == 40 on amd64
}

// ScreenHost serves screen frames and accepts mouse/keyboard input on 127.0.0.1:29389
// so remote peers can connect via IPLink P2P/Relay without Windows RDP (3389).
type ScreenHost struct {
	ln     net.Listener
	logFn  func(string)
	closed atomic.Bool
	wg     sync.WaitGroup

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func StartScreenHost(logFn func(string)) (*ScreenHost, error) {
	return StartScreenHostOn(builtinScreenAddr, logFn)
}

func StartScreenHostOn(addr string, logFn func(string)) (*ScreenHost, error) {
	_, _, _ = procSetProcessDPIAware.Call()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	h := &ScreenHost{
		ln:    ln,
		logFn: logFn,
		conns: make(map[net.Conn]struct{}),
	}
	h.wg.Add(1)
	go h.acceptLoop()
	return h, nil
}

func (h *ScreenHost) Addr() string {
	if h == nil || h.ln == nil {
		return ""
	}
	return h.ln.Addr().String()
}

func (h *ScreenHost) Close() error {
	if h == nil || !h.closed.CompareAndSwap(false, true) {
		return nil
	}
	err := h.ln.Close()

	// Close all active client connections immediately so serveConn/serveInputOnly
	// unblock from Read/Write and app shutdown never hangs.
	h.mu.Lock()
	for c := range h.conns {
		_ = c.Close()
	}
	h.mu.Unlock()

	done := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(1500 * time.Millisecond):
	}
	return err
}

func (h *ScreenHost) acceptLoop() {
	defer h.wg.Done()
	for {
		conn, err := h.ln.Accept()
		if err != nil {
			return
		}
		h.mu.Lock()
		if h.closed.Load() {
			h.mu.Unlock()
			_ = conn.Close()
			return
		}
		h.conns[conn] = struct{}{}
		h.mu.Unlock()

		h.wg.Add(1)
		go func(c net.Conn) {
			defer h.wg.Done()
			defer func() {
				h.mu.Lock()
				delete(h.conns, c)
				h.mu.Unlock()
			}()
			h.serveConn(c)
		}(conn)
	}
}

func (h *ScreenHost) serveConn(conn net.Conn) {
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	// Wait for the client's stream role handshake (video stream vs dedicated input stream).
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	roleType, rolePayload, roleErr := readScreenFrame(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if roleErr != nil {
		return
	}
	if roleType == msgRoleInput {
		h.serveInputOnly(conn)
		return
	}
	if roleType == msgRoleFile {
		h.serveFileReceive(conn)
		return
	}
	tracker := newInputTracker()
	defer tracker.ReleaseAll()

	if roleType == msgInputEvent {
		var ev inputEventMsg
		if json.Unmarshal(rolePayload, &ev) == nil {
			tracker.Inject(ev)
		}
	}

	if h.logFn != nil {
		h.logFn("收到远程同屏控制连接，开始共享本机桌面")
		defer h.logFn("远程同屏控制连接已断开")
	}

	var cfgMu sync.Mutex
	quality := 55
	fps := 18
	scale := 0.75
	forceFull := false

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			msgType, payload, err := readScreenFrame(conn)
			if err != nil {
				return
			}
			if msgType != msgInputEvent {
				continue
			}
			var ev inputEventMsg
			if json.Unmarshal(payload, &ev) != nil {
				continue
			}
			if ev.Type == "refresh" {
				cfgMu.Lock()
				forceFull = true
				cfgMu.Unlock()
				continue
			}
			if ev.Type == "config" {
				cfgMu.Lock()
				if ev.Quality >= 25 && ev.Quality <= 92 {
					quality = ev.Quality
				}
				if ev.FPS >= 4 && ev.FPS <= 30 {
					fps = ev.FPS
				}
				if ev.Scale >= 0.4 && ev.Scale <= 1.0 {
					scale = ev.Scale
				}
				forceFull = true
				cfgMu.Unlock()
				continue
			}
			tracker.Inject(ev)
		}
	}()

	cap := newScreenCapturer()
	defer cap.Close()

	// Send initial screen dimensions.
	sw, sh := getScreenSize()
	infoBytes, _ := json.Marshal(screenInfoMsg{Width: sw, Height: sh, FPS: fps})
	if err := writeScreenFrame(conn, msgScreenInfo, infoBytes); err != nil {
		return
	}

	const tileSize = 64
	type tileRect struct{ x, y, w, h int }
	type encodedTile struct {
		r    tileRect
		data []byte
	}

	workers := runtime.NumCPU()
	if workers > 4 {
		workers = 4
	}
	if workers < 1 {
		workers = 1
	}

	var (
		jpegBuf        bytes.Buffer
		batchBuf       bytes.Buffer
		frameOut       []byte
		prevPix        []byte
		prevW          int
		prevH          int
		dirty          []tileRect
		qualityPenalty int
		needsRefine    bool
		idleSince      time.Time
	)

	mergeVertical := func(rects []tileRect) []tileRect {
		if len(rects) <= 1 {
			return rects
		}
		out := rects[:0]
		for _, r := range rects {
			merged := false
			for i := len(out) - 1; i >= 0; i-- {
				// Merge vertically adjacent strips with identical X and Width into one 2D block.
				if out[i].x == r.x && out[i].w == r.w && out[i].y+out[i].h == r.y {
					out[i].h += r.h
					merged = true
					break
				}
				if out[i].y+out[i].h < r.y {
					break
				}
			}
			if !merged {
				out = append(out, r)
			}
		}
		return out
	}

	for {
		select {
		case <-done:
			return
		default:
		}
		if h.closed.Load() {
			return
		}

		cfgMu.Lock()
		baseQ, f, sc := quality, fps, scale
		wantFull := forceFull
		forceFull = false
		cfgMu.Unlock()

		effQ := baseQ - qualityPenalty
		if effQ < 28 {
			effQ = 28
		}

		start := time.Now()
		bgra, w, hgt, err := cap.CaptureBGRA(sc)
		if err == nil && len(bgra) > 0 {
			stride := w * 4
			needFull := wantFull || prevW != w || prevH != hgt || len(prevPix) != len(bgra)
			dirty = dirty[:0]
			totalTiles := 0
			dirtyTileCount := 0

			if !needFull {
				// Fast whole-frame idle check in raw BGRA before doing any RGBA conversion.
				if bytes.Equal(bgra, prevPix) {
					if qualityPenalty > 0 {
						qualityPenalty = 0
					}
					if needsRefine {
						if idleSince.IsZero() {
							idleSince = time.Now()
						} else if time.Since(idleSince) >= 250*time.Millisecond {
							// Progressive Sharpness Refinement: once motion stops, send one crisp frame.
							needsRefine = false
							idleSince = time.Time{}
							refineQ := baseQ + 18
							if refineQ > 85 {
								refineQ = 85
							}
							effQ = refineQ
							needFull = true
						}
					}
					if !needFull {
						goto sleepNext
					}
				} else {
					idleSince = time.Time{}
					for ty := 0; ty < hgt; ty += tileSize {
						th := tileSize
						if ty+th > hgt {
							th = hgt - ty
						}
						// Merge horizontally adjacent dirty tiles on the same row into one strip.
						runStart := -1
						runWidth := 0
						for tx := 0; tx < w; tx += tileSize {
							tw := tileSize
							if tx+tw > w {
								tw = w - tx
							}
							totalTiles++
							if tileChanged(bgra, prevPix, stride, tx, ty, tw, th) {
								dirtyTileCount++
								if runStart < 0 {
									runStart = tx
									runWidth = tw
								} else {
									runWidth += tw
								}
							} else if runStart >= 0 {
								dirty = append(dirty, tileRect{x: runStart, y: ty, w: runWidth, h: th})
								runStart = -1
								runWidth = 0
							}
						}
						if runStart >= 0 {
							dirty = append(dirty, tileRect{x: runStart, y: ty, w: runWidth, h: th})
						}
					}
					dirty = mergeVertical(dirty)
					if dirtyTileCount*100 >= totalTiles*60 {
						needFull = true
					}
				}
			}

			var writeDur time.Duration
			if needFull {
				img := cap.BGRAToRGBAFull(bgra, w, hgt)
				jpegBuf.Reset()
				if err := jpeg.Encode(&jpegBuf, img, &jpeg.Options{Quality: effQ}); err == nil {
					need := 4 + jpegBuf.Len()
					if capSize(frameOut) < need {
						frameOut = make([]byte, need)
					} else {
						frameOut = frameOut[:need]
					}
					binary.BigEndian.PutUint16(frameOut[0:2], uint16(w))
					binary.BigEndian.PutUint16(frameOut[2:4], uint16(hgt))
					copy(frameOut[4:], jpegBuf.Bytes())

					ws := time.Now()
					_ = conn.SetWriteDeadline(ws.Add(15 * time.Second))
					if err := writeScreenFrame(conn, msgScreenJPEG, frameOut); err != nil {
						return
					}
					writeDur = time.Since(ws)
					if effQ < baseQ {
						needsRefine = true
					}
					if len(prevPix) != len(bgra) {
						prevPix = make([]byte, len(bgra))
					}
					copy(prevPix, bgra)
					prevW, prevH = w, hgt
				}
			} else if len(dirty) > 0 {
				results := make([]encodedTile, len(dirty))
				if len(dirty) >= 4 && workers > 1 {
					// Parallel multi-core JPEG encoding for dirty 2D regions.
					var wg sync.WaitGroup
					var idx atomic.Int32
					nWorkers := workers
					if nWorkers > len(dirty) {
						nWorkers = len(dirty)
					}
					wg.Add(nWorkers)
					for wi := 0; wi < nWorkers; wi++ {
						go func() {
							defer wg.Done()
							var localBuf bytes.Buffer
							for {
								i := int(idx.Add(1) - 1)
								if i >= len(dirty) {
									return
								}
								r := dirty[i]
								sub := cap.BGRAToRGBATile(bgra, stride, r.x, r.y, r.w, r.h)
								localBuf.Reset()
								if err := jpeg.Encode(&localBuf, sub, &jpeg.Options{Quality: effQ}); err == nil {
									cp := make([]byte, localBuf.Len())
									copy(cp, localBuf.Bytes())
									results[i] = encodedTile{r: r, data: cp}
								}
							}
						}()
					}
					wg.Wait()
				} else {
					for i, r := range dirty {
						sub := cap.BGRAToRGBATile(bgra, stride, r.x, r.y, r.w, r.h)
						jpegBuf.Reset()
						if err := jpeg.Encode(&jpegBuf, sub, &jpeg.Options{Quality: effQ}); err == nil {
							cp := make([]byte, jpegBuf.Len())
							copy(cp, jpegBuf.Bytes())
							results[i] = encodedTile{r: r, data: cp}
						}
					}
				}

				batchBuf.Reset()
				var hdr [6]byte
				binary.BigEndian.PutUint16(hdr[0:2], uint16(w))
				binary.BigEndian.PutUint16(hdr[2:4], uint16(hgt))
				binary.BigEndian.PutUint16(hdr[4:6], 0)
				batchBuf.Write(hdr[:])

				var tHdr [12]byte
				encodedTiles := 0
				for _, res := range results {
					if len(res.data) == 0 {
						continue
					}
					binary.BigEndian.PutUint16(tHdr[0:2], uint16(res.r.x))
					binary.BigEndian.PutUint16(tHdr[2:4], uint16(res.r.y))
					binary.BigEndian.PutUint16(tHdr[4:6], uint16(res.r.w))
					binary.BigEndian.PutUint16(tHdr[6:8], uint16(res.r.h))
					binary.BigEndian.PutUint32(tHdr[8:12], uint32(len(res.data)))
					batchBuf.Write(tHdr[:])
					batchBuf.Write(res.data)
					encodedTiles++
				}

				if encodedTiles > 0 {
					rawBatch := batchBuf.Bytes()
					binary.BigEndian.PutUint16(rawBatch[4:6], uint16(encodedTiles))
					ws := time.Now()
					_ = conn.SetWriteDeadline(ws.Add(15 * time.Second))
					if err := writeScreenFrame(conn, msgScreenTiles, rawBatch); err != nil {
						return
					}
					writeDur = time.Since(ws)
					if effQ < baseQ {
						needsRefine = true
					}
					copy(prevPix, bgra)
				}
			}

			// Adaptive quality backpressure: lower quality slightly during congestion,
			// recover smoothly once writes are fast.
			if writeDur > 100*time.Millisecond {
				if qualityPenalty < 20 {
					qualityPenalty += 5
				}
			} else if writeDur > 0 && writeDur < 35*time.Millisecond && qualityPenalty > 0 {
				qualityPenalty -= 3
				if qualityPenalty < 0 {
					qualityPenalty = 0
				}
			}
		}

	sleepNext:
		interval := time.Second / time.Duration(f)
		if elapsed := time.Since(start); elapsed < interval {
			select {
			case <-done:
				return
			case <-time.After(interval - elapsed):
			}
		}
	}
}

func (h *ScreenHost) serveInputOnly(conn net.Conn) {
	tracker := newInputTracker()
	defer tracker.ReleaseAll()
	uipiWarned := false
	for {
		msgType, payload, err := readScreenFrame(conn)
		if err != nil {
			return
		}
		if msgType != msgInputEvent {
			continue
		}
		var ev inputEventMsg
		if json.Unmarshal(payload, &ev) != nil {
			continue
		}
		tracker.Inject(ev)
		if !uipiWarned && uipiBlocked.Swap(false) {
			uipiWarned = true
			if h.logFn != nil {
				h.logFn("提示: SendInput 被系统拦截（可能前台为管理员权限窗口），请以管理员身份运行受控端")
			}
		}
	}
}

func tileChanged(cur, prev []byte, stride, x, y, w, h int) bool {
	rowBytes := w * 4
	for row := y; row < y+h; row++ {
		off := row*stride + x*4
		if !bytes.Equal(cur[off:off+rowBytes], prev[off:off+rowBytes]) {
			return true
		}
	}
	return false
}

func capSize(b []byte) int { return cap(b) }

func getScreenSize() (int, int) {
	w, _, _ := procGetSystemMetrics.Call(smCXScreen)
	h, _, _ := procGetSystemMetrics.Call(smCYScreen)
	if w == 0 {
		w = 1920
	}
	if h == 0 {
		h = 1080
	}
	return int(w), int(h)
}

type screenCapturer struct {
	memDC  uintptr
	bitmap uintptr
	oldObj uintptr
	bits   unsafe.Pointer
	width  int
	height int
	rgba   *image.RGBA
}

func newScreenCapturer() *screenCapturer { return &screenCapturer{} }

func (c *screenCapturer) Close() {
	if c.memDC != 0 {
		if c.oldObj != 0 {
			_, _, _ = procSelectObject.Call(c.memDC, c.oldObj)
			c.oldObj = 0
		}
		if c.bitmap != 0 {
			_, _, _ = procDeleteObject.Call(c.bitmap)
			c.bitmap = 0
		}
		_, _, _ = procDeleteDC.Call(c.memDC)
		c.memDC = 0
	}
	c.bits = nil
	c.width, c.height = 0, 0
}

func (c *screenCapturer) ensureBuffer(screenDC uintptr, dstW, dstH int) error {
	if c.memDC != 0 && c.width == dstW && c.height == dstH {
		return nil
	}
	c.Close()

	memDC, _, _ := procCreateCompatibleDC.Call(screenDC)
	if memDC == 0 {
		return fmt.Errorf("CreateCompatibleDC failed")
	}
	var bi bitmapInfo
	bi.BmiHeader = bitmapInfoHeader{
		BiSize:        uint32(unsafe.Sizeof(bi.BmiHeader)),
		BiWidth:       int32(dstW),
		BiHeight:      -int32(dstH), // top-down DIB
		BiPlanes:      1,
		BiBitCount:    32,
		BiCompression: biRGB,
	}
	var bits unsafe.Pointer
	bmp, _, _ := procCreateDIBSection.Call(
		memDC,
		uintptr(unsafe.Pointer(&bi)),
		dibRGB,
		uintptr(unsafe.Pointer(&bits)),
		0,
		0,
	)
	if bmp == 0 || bits == nil {
		_, _, _ = procDeleteDC.Call(memDC)
		return fmt.Errorf("CreateDIBSection failed")
	}
	oldObj, _, _ := procSelectObject.Call(memDC, bmp)
	_, _, _ = procSetStretchBltMode.Call(memDC, colorOnColor)

	c.memDC = memDC
	c.bitmap = bmp
	c.oldObj = oldObj
	c.bits = bits
	c.width = dstW
	c.height = dstH
	c.rgba = image.NewRGBA(image.Rect(0, 0, dstW, dstH))
	return nil
}

func (c *screenCapturer) CaptureBGRA(scale float64) ([]byte, int, int, error) {
	srcW, srcH := getScreenSize()
	if scale <= 0 || scale > 1.0 {
		scale = 1.0
	}
	dstW := int(float64(srcW) * scale)
	dstH := int(float64(srcH) * scale)
	if dstW < 320 {
		dstW = srcW
		dstH = srcH
	}
	// Ensure even dimensions.
	dstW &^= 1
	dstH &^= 1

	screenDC, _, _ := procGetDC.Call(0)
	if screenDC == 0 {
		return nil, 0, 0, fmt.Errorf("GetDC failed")
	}
	defer procReleaseDC.Call(0, screenDC)

	if err := c.ensureBuffer(screenDC, dstW, dstH); err != nil {
		return nil, 0, 0, err
	}

	if dstW == srcW && dstH == srcH {
		_, _, _ = procBitBlt.Call(
			c.memDC, 0, 0, uintptr(dstW), uintptr(dstH),
			screenDC, 0, 0, srccopy,
		)
	} else {
		_, _, _ = procStretchBlt.Call(
			c.memDC, 0, 0, uintptr(dstW), uintptr(dstH),
			screenDC, 0, 0, uintptr(srcW), uintptr(srcH),
			srccopy,
		)
	}

	totalBytes := dstW * dstH * 4
	return unsafe.Slice((*byte)(c.bits), totalBytes), dstW, dstH, nil
}

func (c *screenCapturer) BGRAToRGBAFull(src []byte, w, h int) *image.RGBA {
	dst := c.rgba.Pix
	totalBytes := w * h * 4
	for i := 0; i < totalBytes; i += 4 {
		dst[i] = src[i+2]
		dst[i+1] = src[i+1]
		dst[i+2] = src[i]
		dst[i+3] = 255
	}
	return c.rgba
}

func (c *screenCapturer) BGRAToRGBATile(src []byte, stride, x, y, w, h int) image.Image {
	dst := c.rgba.Pix
	for row := y; row < y+h; row++ {
		base := row*stride + x*4
		end := base + w*4
		for i := base; i < end; i += 4 {
			dst[i] = src[i+2]
			dst[i+1] = src[i+1]
			dst[i+2] = src[i]
			dst[i+3] = 255
		}
	}
	return c.rgba.SubImage(image.Rect(x, y, x+w, y+h))
}

// inputTracker tracks mouse buttons and keys pressed during a remote session
// and guarantees all of them are released when the session disconnects, preventing
// stuck mouse buttons or modifier keys from locking up the remote Windows desktop.
type inputTracker struct {
	mu      sync.Mutex
	buttons map[int]bool
	keys    map[int]bool
}

func newInputTracker() *inputTracker {
	return &inputTracker{
		buttons: make(map[int]bool),
		keys:    make(map[int]bool),
	}
}

func (t *inputTracker) Inject(ev inputEventMsg) {
	switch ev.Type {
	case "down":
		if ev.Button >= 0 && ev.Button <= 2 {
			t.mu.Lock()
			t.buttons[ev.Button] = true
			t.mu.Unlock()
		}
	case "up":
		if ev.Button >= 0 && ev.Button <= 2 {
			t.mu.Lock()
			delete(t.buttons, ev.Button)
			t.mu.Unlock()
		}
	case "keydown":
		if ev.VK > 0 && ev.VK <= 255 {
			t.mu.Lock()
			t.keys[ev.VK] = true
			t.mu.Unlock()
		}
	case "keyup":
		if ev.VK > 0 && ev.VK <= 255 {
			t.mu.Lock()
			delete(t.keys, ev.VK)
			t.mu.Unlock()
		}
	}
	injectInput(ev)
}

func (t *inputTracker) ReleaseAll() {
	t.mu.Lock()
	btns := make([]int, 0, len(t.buttons))
	for b := range t.buttons {
		btns = append(btns, b)
	}
	keys := make([]int, 0, len(t.keys))
	for k := range t.keys {
		keys = append(keys, k)
	}
	t.buttons = make(map[int]bool)
	t.keys = make(map[int]bool)
	t.mu.Unlock()

	for _, b := range btns {
		injectMouseButton(b, false)
	}
	for _, k := range keys {
		injectKey(k, true)
	}
}

func injectMouseButton(button int, down bool) {
	var flags uint32
	switch button {
	case 0:
		if down {
			flags = mouseEventLeftDown
		} else {
			flags = mouseEventLeftUp
		}
	case 1:
		if down {
			flags = mouseEventMiddleDown
		} else {
			flags = mouseEventMiddleUp
		}
	case 2:
		if down {
			flags = mouseEventRightDown
		} else {
			flags = mouseEventRightUp
		}
	default:
		return
	}
	in := mouseInputStruct{
		Type: inputMouse,
		Mi:   mouseInput{DwFlags: flags},
	}
	ret, _, _ := procSendInput.Call(1, uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in))
	if ret == 0 {
		uipiBlocked.Store(true)
	}
}

func injectKey(vk int, up bool) {
	if vk <= 0 || vk > 255 {
		return
	}
	var flags uint32
	if up {
		flags |= keyEventKeyUp
	}
	if isExtendedVK(vk) {
		flags |= keyEventExtendedKey
	}
	in := keybdInputStruct{
		Type: inputKeyboard,
		Ki: keybdInput{
			WVk:     uint16(vk),
			DwFlags: flags,
		},
	}
	ret, _, _ := procSendInput.Call(1, uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in))
	if ret == 0 {
		uipiBlocked.Store(true)
	}
}

func injectInput(ev inputEventMsg) {
	switch ev.Type {
	case "move", "down", "up", "wheel":
		sw, sh := getScreenSize()
		px := int32(clamp01(ev.X) * float64(sw-1))
		py := int32(clamp01(ev.Y) * float64(sh-1))
		_, _, _ = procSetCursorPos.Call(uintptr(px), uintptr(py))

		switch ev.Type {
		case "down":
			injectMouseButton(ev.Button, true)
		case "up":
			injectMouseButton(ev.Button, false)
		case "wheel":
			in := mouseInputStruct{
				Type: inputMouse,
				Mi: mouseInput{
					MouseData: uint32(int32(ev.DeltaY)),
					DwFlags:   mouseEventWheel,
				},
			}
			ret, _, _ := procSendInput.Call(1, uintptr(unsafe.Pointer(&in)), unsafe.Sizeof(in))
			if ret == 0 {
				uipiBlocked.Store(true)
			}
		}

	case "keydown":
		injectKey(ev.VK, false)
	case "keyup":
		injectKey(ev.VK, true)

	case "paste":
		if ev.Text == "" {
			return
		}
		if setWindowsClipboardText(ev.Text) {
			// Trigger Ctrl+V to paste immediately into the focused remote window.
			sendKeyCombo(0x11, 'V')
		}
	}
}

func sendKeyCombo(modVK, keyVK int) {
	seq := []keybdInputStruct{
		{Type: inputKeyboard, Ki: keybdInput{WVk: uint16(modVK)}},
		{Type: inputKeyboard, Ki: keybdInput{WVk: uint16(keyVK)}},
		{Type: inputKeyboard, Ki: keybdInput{WVk: uint16(keyVK), DwFlags: keyEventKeyUp}},
		{Type: inputKeyboard, Ki: keybdInput{WVk: uint16(modVK), DwFlags: keyEventKeyUp}},
	}
	for i := range seq {
		_, _, _ = procSendInput.Call(1, uintptr(unsafe.Pointer(&seq[i])), unsafe.Sizeof(seq[i]))
	}
}

func setWindowsClipboardText(text string) bool {
	u16 := utf16.Encode([]rune(text))
	u16 = append(u16, 0)
	byteLen := uintptr(len(u16) * 2)

	hMem, _, _ := procGlobalAlloc.Call(gmemMoveable, byteLen)
	if hMem == 0 {
		return false
	}
	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 {
		_, _, _ = procGlobalFree.Call(hMem)
		return false
	}
	_, _, _ = procRtlMoveMemory.Call(ptr, uintptr(unsafe.Pointer(&u16[0])), byteLen)
	_, _, _ = procGlobalUnlock.Call(hMem)

	opened := false
	for i := 0; i < 5; i++ {
		r, _, _ := procOpenClipboard.Call(0)
		if r != 0 {
			opened = true
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	if !opened {
		_, _, _ = procGlobalFree.Call(hMem)
		return false
	}
	defer procCloseClipboard.Call()
	_, _, _ = procEmptyClipboard.Call()
	r, _, _ := procSetClipboardData.Call(cfUnicodeText, hMem)
	if r == 0 {
		_, _, _ = procGlobalFree.Call(hMem)
		return false
	}
	return true
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func isExtendedVK(vk int) bool {
	switch vk {
	case 0x21, 0x22, 0x23, 0x24, // PgUp, PgDn, End, Home
		0x25, 0x26, 0x27, 0x28, // Arrow keys
		0x2D, 0x2E, // Insert, Delete
		0x5B, 0x5C, // LWin, RWin
		0xA3, 0xA5: // RControl, RMenu
		return true
	}
	return false
}

