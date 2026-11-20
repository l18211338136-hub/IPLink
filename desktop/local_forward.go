package main

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// LocalForwardRule defines a local TCP port-to-port mapping rule.
type LocalForwardRule struct {
	Name       string `json:"name"`
	ListenAddr string `json:"listen_addr"`
	TargetAddr string `json:"target_addr"`
	Enabled    bool   `json:"enabled"`
}

// LocalForwardStatus reports the runtime status of a LocalForwardRule.
type LocalForwardStatus struct {
	Name        string `json:"name"`
	ListenAddr  string `json:"listen_addr"`
	TargetAddr  string `json:"target_addr"`
	Running     bool   `json:"running"`
	Error       string `json:"error,omitempty"`
	ActiveConns int64  `json:"active_conns"`
}

type activeForwarder struct {
	rule        LocalForwardRule
	listener    net.Listener
	activeConns atomic.Int64
	stopOnce    sync.Once
	done        chan struct{}
}

// LocalForwardManager manages local TCP port forwarding listeners.
type LocalForwardManager struct {
	logFn func(string)

	mu       sync.Mutex
	rules    []LocalForwardRule
	runners  map[int]*activeForwarder
	errors   map[int]string
}

// NewLocalForwardManager creates a new LocalForwardManager.
func NewLocalForwardManager(logFn func(string)) *LocalForwardManager {
	return &LocalForwardManager{
		logFn:   logFn,
		runners: make(map[int]*activeForwarder),
		errors:  make(map[int]string),
	}
}

// Apply replaces the active forwarding rules and restarts listeners.
func (m *LocalForwardManager) Apply(rules []LocalForwardRule) {
	m.StopAll()

	m.mu.Lock()
	m.rules = make([]LocalForwardRule, len(rules))
	copy(m.rules, rules)
	m.runners = make(map[int]*activeForwarder)
	m.errors = make(map[int]string)

	for i, r := range m.rules {
		if !r.Enabled {
			continue
		}
		if _, _, err := net.SplitHostPort(r.ListenAddr); err != nil {
			m.errors[i] = fmt.Sprintf("invalid listen_addr: %v", err)
			continue
		}
		if _, _, err := net.SplitHostPort(r.TargetAddr); err != nil {
			m.errors[i] = fmt.Sprintf("invalid target_addr: %v", err)
			continue
		}
		ln, err := net.Listen("tcp", r.ListenAddr)
		if err != nil {
			m.errors[i] = err.Error()
			if m.logFn != nil {
				m.logFn(fmt.Sprintf("level=ERROR msg=\"local forward listen failed\" name=%s listen=%s err=%q", r.Name, r.ListenAddr, err.Error()))
			}
			continue
		}
		af := &activeForwarder{
			rule:     r,
			listener: ln,
			done:     make(chan struct{}),
		}
		m.runners[i] = af
		if m.logFn != nil {
			m.logFn(fmt.Sprintf("level=INFO msg=\"local forward started\" name=%s listen=%s target=%s", r.Name, r.ListenAddr, r.TargetAddr))
		}
		go m.serve(af)
	}
	m.mu.Unlock()
}

// StopAll closes all active local forwarding listeners.
func (m *LocalForwardManager) StopAll() {
	m.mu.Lock()
	runners := make([]*activeForwarder, 0, len(m.runners))
	for _, af := range m.runners {
		runners = append(runners, af)
	}
	m.runners = make(map[int]*activeForwarder)
	m.mu.Unlock()

	for _, af := range runners {
		af.stopOnce.Do(func() {
			_ = af.listener.Close()
		})
		<-af.done
	}
}

// Statuses returns the current runtime status for each configured rule.
func (m *LocalForwardManager) Statuses() []LocalForwardStatus {
	m.mu.Lock()
	defer m.mu.Unlock()

	out := make([]LocalForwardStatus, len(m.rules))
	for i, r := range m.rules {
		st := LocalForwardStatus{
			Name:       r.Name,
			ListenAddr: r.ListenAddr,
			TargetAddr: r.TargetAddr,
		}
		if af, ok := m.runners[i]; ok {
			st.Running = true
			st.ActiveConns = af.activeConns.Load()
		} else if errMsg, ok := m.errors[i]; ok {
			st.Error = errMsg
		}
		out[i] = st
	}
	return out
}

func (m *LocalForwardManager) serve(af *activeForwarder) {
	defer close(af.done)
	for {
		src, err := af.listener.Accept()
		if err != nil {
			return
		}
		go m.pipe(af, src)
	}
}

func (m *LocalForwardManager) pipe(af *activeForwarder, src net.Conn) {
	af.activeConns.Add(1)
	defer func() {
		af.activeConns.Add(-1)
		_ = src.Close()
	}()

	dst, err := net.DialTimeout("tcp", af.rule.TargetAddr, 5*time.Second)
	if err != nil {
		if m.logFn != nil {
			m.logFn(fmt.Sprintf("level=WARN msg=\"local forward dial failed\" name=%s target=%s err=%q", af.rule.Name, af.rule.TargetAddr, err.Error()))
		}
		return
	}
	defer dst.Close()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(dst, src)
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(src, dst)
		if tc, ok := src.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	}()
	wg.Wait()
}
