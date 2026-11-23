//go:build windows

package tcp

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestIsFakeIPv4(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"198.18.0.1", true},
		{"198.19.255.254", true},
		{"198.20.0.1", false},
		{"192.168.1.1", false},
		{"8.8.8.8", false},
	}
	for _, tc := range cases {
		if got := isFakeIPv4(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("isFakeIPv4(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

func TestIsVirtualInterfaceName(t *testing.T) {
	if !isVirtualInterfaceName("Meta") {
		t.Error("expected Meta to be detected as virtual")
	}
	if !isVirtualInterfaceName("Clash Tunnel") {
		t.Error("expected Clash Tunnel to be detected as virtual")
	}
	if isVirtualInterfaceName("WLAN") {
		t.Error("expected WLAN not to be detected as virtual")
	}
	if isVirtualInterfaceName("以太网") {
		t.Error("expected 以太网 not to be detected as virtual")
	}
}

func TestBuildAndParseDNSA(t *testing.T) {
	txID, query, err := buildDNSAQuery("example.com")
	if err != nil {
		t.Fatalf("buildDNSAQuery failed: %v", err)
	}
	if binary.BigEndian.Uint16(query[0:2]) != txID {
		t.Fatalf("txID mismatch in query")
	}

	// Build a minimal valid DNS A response echoing the question + 1 answer (1.2.3.4).
	resp := make([]byte, len(query))
	copy(resp, query)
	binary.BigEndian.PutUint16(resp[2:4], 0x8180) // standard response
	binary.BigEndian.PutUint16(resp[6:8], 1)      // ANCOUNT = 1
	// Answer: pointer to question name (0xC00C), TYPE A (1), CLASS IN (1), TTL 60, RDLENGTH 4, 1.2.3.4
	resp = append(resp, 0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 1, 2, 3, 4)

	ips, err := parseDNSAResponse(resp, txID)
	if err != nil {
		t.Fatalf("parseDNSAResponse failed: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(net.IPv4(1, 2, 3, 4)) {
		t.Fatalf("got %v, want [1.2.3.4]", ips)
	}
}

func TestFindPhysicalInterfacesSmoke(t *testing.T) {
	ifaces, err := findPhysicalInterfaces()
	if err != nil {
		t.Fatalf("findPhysicalInterfaces failed: %v", err)
	}
	t.Logf("found %d physical interface(s): %+v", len(ifaces), ifaces)
}

