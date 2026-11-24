package main

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	builtinScreenPort = 29389
	builtinScreenAddr = "127.0.0.1:29389"

	// Wire frame types exchanged over the P2P/Relay TCP stream.
	msgScreenInfo  byte = 0x01 // JSON: screenInfoMsg
	msgScreenJPEG  byte = 0x02 // [width:uint16][height:uint16][jpeg bytes]
	msgScreenTiles byte = 0x03 // [screenW:2B][screenH:2B][count:2B] + count * ([x:2B][y:2B][w:2B][h:2B][len:4B][jpeg])
	msgInputEvent  byte = 0x10 // JSON: inputEventMsg
	msgRoleVideo   byte = 0x20 // client -> host: dedicated video stream
	msgRoleInput   byte = 0x21 // client -> host: dedicated low-latency input stream
	msgRoleFile    byte = 0x22 // client -> host: dedicated file transfer stream
	msgFileMeta    byte = 0x30 // JSON: fileMetaMsg
	msgFileChunk   byte = 0x31 // raw binary chunk
	msgFileDone    byte = 0x32 // EOF marker
	msgFileAck     byte = 0x33 // JSON: fileAckMsg
	msgFileResume  byte = 0x34 // JSON: fileResumeMsg (host -> client resume offset)
)

type fileMetaMsg struct {
	Name       string `json:"name"`
	Size       int64  `json:"size"`
	TransferID string `json:"transfer_id,omitempty"`
}

type fileResumeMsg struct {
	Offset int64  `json:"offset"`
	Error  string `json:"error,omitempty"`
}

type fileAckMsg struct {
	OK        bool   `json:"ok"`
	SavedPath string `json:"saved_path,omitempty"`
	Error     string `json:"error,omitempty"`
}

type screenInfoMsg struct {
	Width  int `json:"width"`
	Height int `json:"height"`
	FPS    int `json:"fps"`
}

type inputEventMsg struct {
	Type    string  `json:"t"`                 // "move" | "down" | "up" | "wheel" | "keydown" | "keyup" | "paste" | "config"
	X       float64 `json:"x,omitempty"`       // normalized 0..1
	Y       float64 `json:"y,omitempty"`       // normalized 0..1
	Button  int     `json:"b,omitempty"`       // 0=left, 1=middle, 2=right
	DeltaY  int     `json:"dy,omitempty"`      // wheel delta (+up / -down)
	VK      int     `json:"vk,omitempty"`      // Windows Virtual-Key code
	Text    string  `json:"text,omitempty"`    // UTF-8 text for "paste"
	Quality int     `json:"quality,omitempty"` // JPEG quality 30..90
	FPS     int     `json:"fps,omitempty"`     // target fps 5..30
	Scale   float64 `json:"scale,omitempty"`   // 0.5..1.0
}

func writeScreenFrame(w io.Writer, msgType byte, payload []byte) error {
	var hdr [5]byte
	hdr[0] = msgType
	binary.BigEndian.PutUint32(hdr[1:5], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func readScreenFrame(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	length := binary.BigEndian.Uint32(hdr[1:5])
	if length > 8*1024*1024 {
		return 0, nil, fmt.Errorf("screen frame too large: %d", length)
	}
	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return hdr[0], payload, nil
}

