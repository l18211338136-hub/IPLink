package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const fileChunkSize = 256 * 1024

// computeFileTransferID produces a fast, deterministic fingerprint from file name,
// size, and the first/last 64KB of content so resumable transfers never collide.
func computeFileTransferID(f *os.File, name string, size int64) string {
	h := sha256.New()
	_, _ = fmt.Fprintf(h, "%s|%d|", name, size)
	buf := make([]byte, 64*1024)
	if n, err := f.ReadAt(buf, 0); n > 0 && (err == nil || err == io.EOF) {
		_, _ = h.Write(buf[:n])
	}
	if size > int64(len(buf)) {
		if n, err := f.ReadAt(buf, size-int64(len(buf))); n > 0 && (err == nil || err == io.EOF) {
			_, _ = h.Write(buf[:n])
		}
	}
	return hex.EncodeToString(h.Sum(nil)[:8])
}

func partFilePath(saveDir, safeName, transferID string) string {
	if transferID == "" {
		transferID = "default"
	}
	return filepath.Join(saveDir, fmt.Sprintf(".%s.%s.iplinkpart", safeName, transferID))
}

// serveFileReceive receives a streamed file over a dedicated msgRoleFile stream
// with breakpoint resume support (.iplinkpart) and writes it into ~/Downloads/IPLink/.
func (h *ScreenHost) serveFileReceive(conn net.Conn) {
	sendResume := func(offset int64, errMsg string) error {
		b, _ := json.Marshal(fileResumeMsg{Offset: offset, Error: errMsg})
		return writeScreenFrame(conn, msgFileResume, b)
	}
	sendAck := func(ok bool, savedPath, errMsg string) {
		b, _ := json.Marshal(fileAckMsg{OK: ok, SavedPath: savedPath, Error: errMsg})
		_ = writeScreenFrame(conn, msgFileAck, b)
	}

	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	mt, payload, err := readScreenFrame(conn)
	if err != nil || mt != msgFileMeta {
		_ = sendResume(0, "未收到有效的文件头信息")
		return
	}

	var meta fileMetaMsg
	if err := json.Unmarshal(payload, &meta); err != nil || strings.TrimSpace(meta.Name) == "" || meta.Size < 0 {
		_ = sendResume(0, "文件元信息无效")
		return
	}

	saveDir, err := defaultReceiveDir()
	if err != nil {
		_ = sendResume(0, fmt.Sprintf("创建接收目录失败: %v", err))
		return
	}
	safeName := sanitizeFileName(meta.Name)
	tmpPath := partFilePath(saveDir, safeName, sanitizeFileName(meta.TransferID))

	// Check if a partial transfer exists so we can resume from its current byte offset.
	var offset int64
	if st, statErr := os.Stat(tmpPath); statErr == nil && !st.IsDir() {
		if st.Size() >= 0 && st.Size() <= meta.Size {
			offset = st.Size()
		} else {
			_ = os.Remove(tmpPath)
		}
	}

	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		_ = sendResume(0, fmt.Sprintf("打开临时文件失败: %v", err))
		return
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		_ = f.Close()
		_ = sendResume(0, fmt.Sprintf("定位断点位置失败: %v", err))
		return
	}

	if err := sendResume(offset, ""); err != nil {
		_ = f.Close()
		return
	}

	if h.logFn != nil {
		if offset > 0 {
			h.logFn(fmt.Sprintf("断点续传接收: %s (从 %s / %s 继续)", safeName, formatByteSize(offset), formatByteSize(meta.Size)))
		} else {
			h.logFn(fmt.Sprintf("开始接收文件: %s (%s)", safeName, formatByteSize(meta.Size)))
		}
	}

	bw := bufio.NewWriterSize(f, 256*1024)
	written := offset
	completed := false
	defer func() {
		if !completed {
			// Preserve .iplinkpart on disk so the next attempt resumes from this exact offset.
			_ = bw.Flush()
			_ = f.Sync()
			_ = f.Close()
		}
	}()

	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		mt, chunk, err := readScreenFrame(conn)
		if err != nil {
			sendAck(false, "", fmt.Sprintf("接收中断 (已保存断点 %s): %v", formatByteSize(written), err))
			if h.logFn != nil {
				h.logFn(fmt.Sprintf("文件接收中断 (%s，已保留断点 %s): %v", safeName, formatByteSize(written), err))
			}
			return
		}
		switch mt {
		case msgFileChunk:
			if len(chunk) > 0 {
				n, wErr := bw.Write(chunk)
				written += int64(n)
				if wErr != nil {
					sendAck(false, "", fmt.Sprintf("写入磁盘失败: %v", wErr))
					return
				}
			}
		case msgFileDone:
			if err := bw.Flush(); err != nil {
				sendAck(false, "", fmt.Sprintf("刷新写入缓冲失败: %v", err))
				return
			}
			if written != meta.Size {
				sendAck(false, "", fmt.Sprintf("文件大小校验不一致: 收到 %d，期望 %d", written, meta.Size))
				return
			}
			if err := f.Sync(); err != nil {
				sendAck(false, "", fmt.Sprintf("刷盘失败: %v", err))
				return
			}
			_ = f.Close()
			completed = true

			dstPath := uniqueFilePath(saveDir, safeName)
			var renameErr error
			for i := 0; i < 10; i++ {
				renameErr = os.Rename(tmpPath, dstPath)
				if renameErr == nil {
					break
				}
				// Windows Defender may briefly scan a newly closed .exe/.zip file.
				time.Sleep(200 * time.Millisecond)
			}
			if renameErr != nil {
				sendAck(false, "", fmt.Sprintf("保存最终文件失败: %v", renameErr))
				if h.logFn != nil {
					h.logFn(fmt.Sprintf("重命名最终文件失败 (%s -> %s): %v", tmpPath, dstPath, renameErr))
				}
				return
			}
			sendAck(true, dstPath, "")
			if h.logFn != nil {
				h.logFn(fmt.Sprintf("文件接收完成: %s (%s) -> %s", safeName, formatByteSize(written), dstPath))
			}
			return
		}
	}
}

// sendFileOverAddr streams localPath over a dedicated msgRoleFile TCP connection
// to forwardListenAddr, automatically resuming from the receiver's reported byte offset.
func sendFileOverAddr(forwardListenAddr, localPath string, onProgress func(sent, total, speedKBps int64, resumed bool)) (string, error) {
	info, err := os.Stat(localPath)
	if err != nil {
		return "", fmt.Errorf("读取文件信息失败: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("暂不支持直接发送文件夹，请先压缩为 zip 后发送")
	}
	f, err := os.Open(localPath)
	if err != nil {
		return "", fmt.Errorf("打开文件失败: %w", err)
	}
	defer f.Close()

	baseName := filepath.Base(localPath)
	total := info.Size()
	transferID := computeFileTransferID(f, baseName, total)

	conn, err := net.DialTimeout("tcp", forwardListenAddr, 10*time.Second)
	if err != nil {
		return "", fmt.Errorf("连接文件传输通道失败: %w", err)
	}
	defer conn.Close()
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
	}

	if err := writeScreenFrame(conn, msgRoleFile, nil); err != nil {
		return "", fmt.Errorf("发送角色握手失败: %w", err)
	}

	metaBytes, _ := json.Marshal(fileMetaMsg{
		Name:       baseName,
		Size:       total,
		TransferID: transferID,
	})
	if err := writeScreenFrame(conn, msgFileMeta, metaBytes); err != nil {
		return "", fmt.Errorf("发送文件头失败: %w", err)
	}

	// Wait for receiver's resume offset.
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	mt, payload, err := readScreenFrame(conn)
	if err != nil {
		return "", fmt.Errorf("等待对端断点确认失败: %w", err)
	}
	if mt != msgFileResume {
		return "", fmt.Errorf("对端返回异常断点响应: %d", mt)
	}
	var resume fileResumeMsg
	if err := json.Unmarshal(payload, &resume); err != nil {
		return "", fmt.Errorf("解析断点响应失败: %w", err)
	}
	if resume.Error != "" {
		return "", fmt.Errorf("对端拒绝接收: %s", resume.Error)
	}
	if resume.Offset < 0 || resume.Offset > total {
		return "", fmt.Errorf("对端返回无效断点偏移: %d", resume.Offset)
	}

	resumed := resume.Offset > 0
	if resumed {
		if _, err := f.Seek(resume.Offset, io.SeekStart); err != nil {
			return "", fmt.Errorf("定位本地文件断点失败: %w", err)
		}
	}

	sent := resume.Offset
	var sessionSent int64
	startTime := time.Now()
	lastReport := time.Now()
	if onProgress != nil && (resumed || total == 0) {
		onProgress(sent, total, 0, resumed)
	}

	// Coalesce 5-byte frame header + payload into a single Write call to avoid small-packet splits.
	frameBuf := make([]byte, 5+fileChunkSize)
	frameBuf[0] = msgFileChunk
	for sent < total {
		n, rErr := f.Read(frameBuf[5:])
		if n > 0 {
			binary.BigEndian.PutUint32(frameBuf[1:5], uint32(n))
			_ = conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
			if _, err := conn.Write(frameBuf[:5+n]); err != nil {
				return "", fmt.Errorf("发送文件数据失败: %w", err)
			}
			sent += int64(n)
			sessionSent += int64(n)
			if onProgress != nil && (time.Since(lastReport) >= 150*time.Millisecond || sent >= total) {
				elapsed := time.Since(startTime).Seconds()
				var speedKBps int64
				if elapsed > 0 {
					speedKBps = int64(float64(sessionSent) / 1024.0 / elapsed)
				}
				onProgress(sent, total, speedKBps, resumed)
				lastReport = time.Now()
			}
		}
		if rErr == io.EOF {
			break
		}
		if rErr != nil {
			return "", fmt.Errorf("读取本地文件失败: %w", rErr)
		}
	}

	_ = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if err := writeScreenFrame(conn, msgFileDone, nil); err != nil {
		return "", fmt.Errorf("发送完成标记失败: %w", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	mt, payload, err = readScreenFrame(conn)
	if err != nil {
		return "", fmt.Errorf("等待对端确认失败: %w", err)
	}
	if mt != msgFileAck {
		return "", fmt.Errorf("对端返回异常响应类型: %d", mt)
	}
	var ack fileAckMsg
	if err := json.Unmarshal(payload, &ack); err != nil {
		return "", fmt.Errorf("解析对端确认失败: %w", err)
	}
	if !ack.OK {
		return "", fmt.Errorf("对端接收失败: %s", ack.Error)
	}
	return ack.SavedPath, nil
}

func defaultReceiveDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		home = "."
	}
	dir := filepath.Join(home, "Downloads", "IPLink")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func sanitizeFileName(name string) string {
	base := filepath.Base(strings.ReplaceAll(name, "\\", "/"))
	base = strings.Map(func(r rune) rune {
		switch r {
		case ':', '*', '?', '"', '<', '>', '|':
			return '_'
		default:
			if r < 0x20 {
				return -1
			}
			return r
		}
	}, strings.TrimSpace(base))
	if base == "" || base == "." || base == ".." {
		return fmt.Sprintf("file-%d.bin", time.Now().Unix())
	}
	return base
}

func uniqueFilePath(dir, name string) string {
	candidate := filepath.Join(dir, name)
	if _, err := os.Stat(candidate); os.IsNotExist(err) {
		return candidate
	}
	ext := filepath.Ext(name)
	stem := strings.TrimSuffix(name, ext)
	for i := 1; i < 1000; i++ {
		c := filepath.Join(dir, fmt.Sprintf("%s (%d)%s", stem, i, ext))
		if _, err := os.Stat(c); os.IsNotExist(err) {
			return c
		}
	}
	return filepath.Join(dir, fmt.Sprintf("%s-%d%s", stem, time.Now().Unix(), ext))
}

func formatByteSize(b int64) string {
	switch {
	case b >= 1024*1024*1024:
		return fmt.Sprintf("%.2f GB", float64(b)/(1024*1024*1024))
	case b >= 1024*1024:
		return fmt.Sprintf("%.2f MB", float64(b)/(1024*1024))
	case b >= 1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%d B", b)
	}
}
