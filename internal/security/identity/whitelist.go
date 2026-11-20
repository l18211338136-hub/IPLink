package identity

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// TargetValidator enforces an allowlist on local target IP:port pairs to prevent open-proxy abuse.
type TargetValidator struct {
	rules []rule
}

type rule struct {
	anyHost bool
	ip      net.IP
	ipNet   *net.IPNet
	anyPort bool
	port    int
}

// NewTargetValidator builds a validator from patterns like "127.0.0.1:*", "192.168.1.0/24:8080", or "*:*".
// If patterns is empty, only loopback addresses (127.0.0.1 / ::1) are permitted by default.
func NewTargetValidator(patterns []string) (*TargetValidator, error) {
	if len(patterns) == 0 {
		patterns = []string{"127.0.0.1:*", "[::1]:*"}
	}
	rules := make([]rule, 0, len(patterns))
	for _, p := range patterns {
		r, err := parseRule(strings.TrimSpace(p))
		if err != nil {
			return nil, fmt.Errorf("invalid target rule %q: %w", p, err)
		}
		rules = append(rules, r)
	}
	return &TargetValidator{rules: rules}, nil
}

func parseRule(pattern string) (rule, error) {
	host, portStr, err := net.SplitHostPort(pattern)
	if err != nil {
		return rule{}, err
	}
	var r rule
	if host == "*" {
		r.anyHost = true
	} else if strings.Contains(host, "/") {
		_, ipNet, err := net.ParseCIDR(host)
		if err != nil {
			return rule{}, err
		}
		r.ipNet = ipNet
	} else {
		ip := net.ParseIP(host)
		if ip == nil {
			return rule{}, fmt.Errorf("host %q must be an IP, CIDR, or *", host)
		}
		r.ip = ip
	}

	if portStr == "*" {
		r.anyPort = true
	} else {
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return rule{}, fmt.Errorf("invalid port %q", portStr)
		}
		r.port = port
	}
	return r, nil
}

// Allow returns nil if addr ("ip:port") matches at least one configured rule.
func (v *TargetValidator) Allow(addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid target address %q: %w", addr, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("target host %q must be an IP address", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid target port %q", portStr)
	}

	for _, r := range v.rules {
		if !r.matchesHost(ip) {
			continue
		}
		if r.anyPort || r.port == port {
			return nil
		}
	}
	return fmt.Errorf("target %q is not permitted by allowed_targets policy", addr)
}

func (r rule) matchesHost(ip net.IP) bool {
	if r.anyHost {
		return true
	}
	if r.ipNet != nil {
		return r.ipNet.Contains(ip)
	}
	return r.ip != nil && r.ip.Equal(ip)
}
