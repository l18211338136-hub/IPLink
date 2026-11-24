package p2p

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	headerSize    = 15
	maxChunkSize  = 1150
	maxInFlight   = 64
	maxRecvWindow = 128
	initialRTO    = 150 * time.Millisecond
	maxRTO        = 1500 * time.Millisecond
	tickInterval  = 25 * time.Millisecond
)

const (
	msgOpen      byte = 1
	msgOpenOK    byte = 2
	msgOpenErr   byte = 3
	msgData      byte = 4
	msgAck       byte = 5
	msgFin       byte = 6
	msgRst       byte = 7
	msgKeepalive byte = 8
)

// PacketTransport abstracts a datagram channel (e.g. PeerChannel).
type PacketTransport interface {
	Send(payload []byte) error
	Receive(ctx context.Context) ([]byte, error)
}

type packetHeader struct {
	Type     byte
	StreamID uint32
	Seq      uint32
	Ack      uint32
	Window   uint16
}

func encodePacket(h packetHeader, payload []byte) []byte {
	buf := make([]byte, headerSize+len(payload))
	buf[0] = h.Type
	binary.BigEndian.PutUint32(buf[1:5], h.StreamID)
	binary.BigEndian.PutUint32(buf[5:9], h.Seq)
	binary.BigEndian.PutUint32(buf[9:13], h.Ack)
	binary.BigEndian.PutUint16(buf[13:15], h.Window)
	copy(buf[headerSize:], payload)
	return buf
}

func decodePacket(raw []byte) (packetHeader, []byte, error) {
	if len(raw) < headerSize {
		return packetHeader{}, nil, errors.New("short p2p packet")
	}
	h := packetHeader{
		Type:     raw[0],
		StreamID: binary.BigEndian.Uint32(raw[1:5]),
		Seq:      binary.BigEndian.Uint32(raw[5:9]),
		Ack:      binary.BigEndian.Uint32(raw[9:13]),
		Window:   binary.BigEndian.Uint16(raw[13:15]),
	}
	return h, raw[headerSize:], nil
}

// AcceptedStream represents an incoming stream opened by the remote peer.
type AcceptedStream struct {
	Conn   net.Conn
	Target string
}

// Mux multiplexes reliable ordered byte streams over a PacketTransport.
type Mux struct {
	transport PacketTransport
	ctx       context.Context
	cancel    context.CancelFunc

	nextID atomic.Uint32

	mu      sync.Mutex
	streams map[uint32]*Stream
	closed  bool

	acceptCh chan AcceptedStream
}

// NewMux starts a reliable stream multiplexer on transport.
// isClient determines whether locally-initiated stream IDs are odd (true) or even (false).
func NewMux(ctx context.Context, transport PacketTransport, isClient bool) *Mux {
	mCtx, cancel := context.WithCancel(ctx)
	m := &Mux{
		transport: transport,
		ctx:       mCtx,
		cancel:    cancel,
		streams:   make(map[uint32]*Stream),
		acceptCh:  make(chan AcceptedStream, 32),
	}
	if isClient {
		m.nextID.Store(1)
	} else {
		m.nextID.Store(2)
	}
	go m.recvLoop()
	go m.timerLoop()
	return m
}

// Close shuts down the multiplexer and all active streams.
func (m *Mux) Close() error {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil
	}
	m.closed = true
	streams := make([]*Stream, 0, len(m.streams))
	for _, s := range m.streams {
		streams = append(streams, s)
	}
	m.streams = make(map[uint32]*Stream)
	m.mu.Unlock()

	m.cancel()
	for _, s := range streams {
		s.abort(net.ErrClosed)
	}
	return nil
}

// Accept waits for an incoming stream opened by the remote peer.
func (m *Mux) Accept(ctx context.Context) (net.Conn, string, error) {
	select {
	case <-ctx.Done():
		return nil, "", ctx.Err()
	case <-m.ctx.Done():
		return nil, "", net.ErrClosed
	case item := <-m.acceptCh:
		return item.Conn, item.Target, nil
	}
}

// OpenStream requests the remote peer to open a TCP connection to target and returns a reliable net.Conn.
func (m *Mux) OpenStream(ctx context.Context, target string) (net.Conn, error) {
	id := m.nextID.Add(2) - 2
	s := newStream(m, id)

	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, net.ErrClosed
	}
	m.streams[id] = s
	m.mu.Unlock()

	openPkt := encodePacket(packetHeader{
		Type:     msgOpen,
		StreamID: id,
		Window:   maxRecvWindow,
	}, []byte(target))

	// Retry OPEN up to 5 times until OPEN_OK / OPEN_ERR or ctx cancellation.
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()

	if err := m.transport.Send(openPkt); err != nil {
		m.removeStream(id)
		return nil, err
	}
	for tries := 0; tries < 20; tries++ {
		select {
		case <-ctx.Done():
			m.removeStream(id)
			_ = m.transport.Send(encodePacket(packetHeader{Type: msgRst, StreamID: id}, nil))
			return nil, ctx.Err()
		case <-m.ctx.Done():
			m.removeStream(id)
			return nil, net.ErrClosed
		case err := <-s.openResultCh:
			if err != nil {
				m.removeStream(id)
				return nil, err
			}
			return s, nil
		case <-ticker.C:
			_ = m.transport.Send(openPkt)
		}
	}
	m.removeStream(id)
	return nil, errors.New("p2p open stream timeout")
}

func (m *Mux) removeStream(id uint32) {
	m.mu.Lock()
	delete(m.streams, id)
	m.mu.Unlock()
}

func (m *Mux) recvLoop() {
	defer m.Close()
	for {
		raw, err := m.transport.Receive(m.ctx)
		if err != nil {
			return
		}
		h, payload, err := decodePacket(raw)
		if err != nil {
			continue
		}
		if h.Type == msgKeepalive {
			continue
		}

		if h.Type == msgOpen {
			m.handleOpen(h.StreamID, string(payload))
			continue
		}

		m.mu.Lock()
		s := m.streams[h.StreamID]
		m.mu.Unlock()
		if s == nil {
			continue
		}
		s.onPacket(h, payload)
	}
}

func (m *Mux) handleOpen(id uint32, target string) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	if _, exists := m.streams[id]; exists {
		m.mu.Unlock()
		// Re-ACK an already accepted stream's OPEN retry.
		_ = m.transport.Send(encodePacket(packetHeader{
			Type:     msgOpenOK,
			StreamID: id,
			Window:   maxRecvWindow,
		}, nil))
		return
	}
	s := newStream(m, id)
	m.streams[id] = s
	m.mu.Unlock()

	select {
	case m.acceptCh <- AcceptedStream{Conn: s, Target: target}:
		_ = m.transport.Send(encodePacket(packetHeader{
			Type:     msgOpenOK,
			StreamID: id,
			Window:   maxRecvWindow,
		}, nil))
	default:
		m.removeStream(id)
		_ = m.transport.Send(encodePacket(packetHeader{
			Type:     msgOpenErr,
			StreamID: id,
		}, []byte("accept queue full")))
	}
}

func (m *Mux) timerLoop() {
	ticker := time.NewTicker(tickInterval)
	defer ticker.Stop()
	keepaliveTick := 0
	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.mu.Lock()
			streams := make([]*Stream, 0, len(m.streams))
			for _, s := range m.streams {
				streams = append(streams, s)
			}
			m.mu.Unlock()

			now := time.Now()
			for _, s := range streams {
				s.onTick(now)
			}

			keepaliveTick++
			if keepaliveTick >= 400 { // ~10s
				keepaliveTick = 0
				_ = m.transport.Send(encodePacket(packetHeader{Type: msgKeepalive}, nil))
			}
		}
	}
}

type sentPacket struct {
	seq      uint32
	pktType  byte
	payload  []byte
	sentAt   time.Time
	rto      time.Duration
	attempts int
}

// Stream is a reliable, ordered net.Conn multiplexed over a Mux.
type Stream struct {
	mux *Mux
	id  uint32

	openOnce     sync.Once
	openResultCh chan error

	mu           sync.Mutex
	nextSendSeq  uint32
	sendUnacked  map[uint32]*sentPacket
	peerWindow   uint16
	finSent      bool
	closedLocal  bool
	closedRemote bool
	err          error

	nextRecvSeq uint32
	oooBuf      map[uint32][]byte
	finSeq      uint32
	readBuf     []byte
	ackDirty    bool

	readDeadline  time.Time
	writeDeadline time.Time
	notifyCh      chan struct{}
}

func newStream(m *Mux, id uint32) *Stream {
	return &Stream{
		mux:          m,
		id:           id,
		openResultCh: make(chan error, 1),
		nextSendSeq:  1,
		sendUnacked:  make(map[uint32]*sentPacket),
		peerWindow:   maxInFlight,
		nextRecvSeq:  1,
		oooBuf:       make(map[uint32][]byte),
		notifyCh:     make(chan struct{}, 1),
	}
}

func (s *Stream) signal() {
	select {
	case s.notifyCh <- struct{}{}:
	default:
	}
}

func (s *Stream) resolveOpen(err error) {
	s.openOnce.Do(func() {
		s.openResultCh <- err
	})
}

func (s *Stream) onPacket(h packetHeader, payload []byte) {
	switch h.Type {
	case msgOpenOK:
		s.resolveOpen(nil)
	case msgOpenErr:
		s.resolveOpen(fmt.Errorf("remote rejected stream: %s", string(payload)))
	case msgRst:
		s.resolveOpen(errors.New("stream reset by peer"))
		s.abort(io.ErrUnexpectedEOF)
	case msgAck:
		s.mu.Lock()
		s.handleAckLocked(h.Ack, h.Window)
		s.mu.Unlock()
		s.signal()
	case msgData:
		s.mu.Lock()
		if h.Ack > 0 {
			s.handleAckLocked(h.Ack, h.Window)
		}
		s.handleDataLocked(h.Seq, payload)
		s.mu.Unlock()
		s.signal()
	case msgFin:
		s.mu.Lock()
		if h.Ack > 0 {
			s.handleAckLocked(h.Ack, h.Window)
		}
		if s.finSeq == 0 || h.Seq < s.finSeq {
			s.finSeq = h.Seq
		}
		if s.nextRecvSeq >= s.finSeq {
			s.closedRemote = true
		}
		s.ackDirty = true
		s.mu.Unlock()
		s.signal()
	}
}

func (s *Stream) handleAckLocked(ack uint32, window uint16) {
	if window > 0 {
		s.peerWindow = window
	}
	for seq := range s.sendUnacked {
		if seq < ack {
			delete(s.sendUnacked, seq)
		}
	}
}

func (s *Stream) handleDataLocked(seq uint32, payload []byte) {
	if seq < s.nextRecvSeq {
		s.ackDirty = true
		return
	}
	if seq >= s.nextRecvSeq+maxRecvWindow {
		return
	}
	if seq == s.nextRecvSeq {
		s.readBuf = append(s.readBuf, payload...)
		s.nextRecvSeq++
		for {
			nextData, ok := s.oooBuf[s.nextRecvSeq]
			if !ok {
				break
			}
			delete(s.oooBuf, s.nextRecvSeq)
			s.readBuf = append(s.readBuf, nextData...)
			s.nextRecvSeq++
		}
		if s.finSeq > 0 && s.nextRecvSeq >= s.finSeq {
			s.closedRemote = true
		}
		s.ackDirty = true
		return
	}
	if _, exists := s.oooBuf[seq]; !exists {
		cp := make([]byte, len(payload))
		copy(cp, payload)
		s.oooBuf[seq] = cp
	}
	// Send immediate duplicate ACK to help trigger retransmit.
	_ = s.mux.transport.Send(encodePacket(packetHeader{
		Type:     msgAck,
		StreamID: s.id,
		Ack:      s.nextRecvSeq,
		Window:   maxRecvWindow,
	}, nil))
}

func (s *Stream) onTick(now time.Time) {
	s.mu.Lock()
	var toSend [][]byte
	for _, sp := range s.sendUnacked {
		if now.Sub(sp.sentAt) >= sp.rto {
			if sp.attempts >= 16 {
				s.mu.Unlock()
				s.abort(errors.New("p2p stream retransmit timeout"))
				return
			}
			sp.attempts++
			sp.sentAt = now
			sp.rto *= 2
			if sp.rto > maxRTO {
				sp.rto = maxRTO
			}
			toSend = append(toSend, encodePacket(packetHeader{
				Type:     sp.pktType,
				StreamID: s.id,
				Seq:      sp.seq,
				Ack:      s.nextRecvSeq,
				Window:   maxRecvWindow,
			}, sp.payload))
		}
	}
	if s.ackDirty && len(toSend) == 0 {
		s.ackDirty = false
		toSend = append(toSend, encodePacket(packetHeader{
			Type:     msgAck,
			StreamID: s.id,
			Ack:      s.nextRecvSeq,
			Window:   maxRecvWindow,
		}, nil))
	} else {
		s.ackDirty = false
	}
	s.mu.Unlock()

	for _, pkt := range toSend {
		_ = s.mux.transport.Send(pkt)
	}
}

func (s *Stream) abort(err error) {
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.closedLocal = true
	s.closedRemote = true
	s.mu.Unlock()
	s.signal()
}

// Read reads ordered bytes from the stream.
func (s *Stream) Read(p []byte) (int, error) {
	for {
		s.mu.Lock()
		if len(s.readBuf) > 0 {
			n := copy(p, s.readBuf)
			s.readBuf = s.readBuf[n:]
			s.mu.Unlock()
			return n, nil
		}
		if s.err != nil {
			err := s.err
			s.mu.Unlock()
			return 0, err
		}
		if s.closedRemote {
			s.mu.Unlock()
			return 0, io.EOF
		}
		deadline := s.readDeadline
		s.mu.Unlock()

		if err := s.waitNotify(deadline); err != nil {
			return 0, err
		}
	}
}

// Write queues data into reliable in-order packets.
func (s *Stream) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > maxChunkSize {
			chunk = p[:maxChunkSize]
		}

		for {
			s.mu.Lock()
			if s.err != nil {
				err := s.err
				s.mu.Unlock()
				return written, err
			}
			if s.closedLocal || s.finSent {
				s.mu.Unlock()
				return written, net.ErrClosed
			}
			limit := int(s.peerWindow)
			if limit == 0 || limit > maxInFlight {
				limit = maxInFlight
			}
			if len(s.sendUnacked) < limit {
				seq := s.nextSendSeq
				s.nextSendSeq++
				cp := make([]byte, len(chunk))
				copy(cp, chunk)
				s.sendUnacked[seq] = &sentPacket{
					seq:     seq,
					pktType: msgData,
					payload: cp,
					sentAt:  time.Now(),
					rto:     initialRTO,
				}
				ack := s.nextRecvSeq
				s.ackDirty = false
				s.mu.Unlock()

				if err := s.mux.transport.Send(encodePacket(packetHeader{
					Type:     msgData,
					StreamID: s.id,
					Seq:      seq,
					Ack:      ack,
					Window:   maxRecvWindow,
				}, cp)); err != nil {
					return written, err
				}
				written += len(chunk)
				p = p[len(chunk):]
				break
			}
			deadline := s.writeDeadline
			s.mu.Unlock()

			if err := s.waitNotify(deadline); err != nil {
				return written, err
			}
		}
	}
	return written, nil
}

func (s *Stream) waitNotify(deadline time.Time) error {
	if !deadline.IsZero() {
		rem := time.Until(deadline)
		if rem <= 0 {
			return context.DeadlineExceeded
		}
		t := time.NewTimer(rem)
		defer t.Stop()
		select {
		case <-s.notifyCh:
			return nil
		case <-t.C:
			return context.DeadlineExceeded
		case <-s.mux.ctx.Done():
			return net.ErrClosed
		}
	}
	select {
	case <-s.notifyCh:
		return nil
	case <-s.mux.ctx.Done():
		return net.ErrClosed
	}
}

// Close sends a FIN packet and closes the stream.
func (s *Stream) Close() error {
	s.mu.Lock()
	if s.closedLocal {
		s.mu.Unlock()
		return nil
	}
	s.closedLocal = true
	if !s.finSent {
		s.finSent = true
		seq := s.nextSendSeq
		s.nextSendSeq++
		s.sendUnacked[seq] = &sentPacket{
			seq:     seq,
			pktType: msgFin,
			sentAt:  time.Now(),
			rto:     initialRTO,
		}
		ack := s.nextRecvSeq
		s.mu.Unlock()
		_ = s.mux.transport.Send(encodePacket(packetHeader{
			Type:     msgFin,
			StreamID: s.id,
			Seq:      seq,
			Ack:      ack,
			Window:   maxRecvWindow,
		}, nil))
	} else {
		s.mu.Unlock()
	}
	s.signal()
	return nil
}

type muxAddr string

func (a muxAddr) Network() string { return "p2p" }
func (a muxAddr) String() string  { return string(a) }

func (s *Stream) LocalAddr() net.Addr  { return muxAddr(fmt.Sprintf("p2p-stream-%d", s.id)) }
func (s *Stream) RemoteAddr() net.Addr { return muxAddr(fmt.Sprintf("p2p-peer-%d", s.id)) }

func (s *Stream) SetDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.writeDeadline = t
	s.mu.Unlock()
	s.signal()
	return nil
}

func (s *Stream) SetReadDeadline(t time.Time) error {
	s.mu.Lock()
	s.readDeadline = t
	s.mu.Unlock()
	s.signal()
	return nil
}

func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.mu.Lock()
	s.writeDeadline = t
	s.mu.Unlock()
	s.signal()
	return nil
}

