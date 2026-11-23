//go:build windows

package tcp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	ipUnicastIf              = 31
	errInsufficientBuffer    = 122
	mibIPForwardRowSizeBytes = 56
)

var (
	modIphlpapi          = syscall.NewLazyDLL("iphlpapi.dll")
	procGetIPForwardTable = modIphlpapi.NewProc("GetIpForwardTable")
)

type mibIPForwardRow struct {
	ForwardDest      uint32
	ForwardMask      uint32
	ForwardPolicy    uint32
	ForwardNextHop   uint32
	ForwardIfIndex   uint32
	ForwardType      uint32
	ForwardProto     uint32
	ForwardAge       uint32
	ForwardNextHopAS uint32
	ForwardMetric1   uint32
	ForwardMetric2   uint32
	ForwardMetric3   uint32
	ForwardMetric4   uint32
	ForwardMetric5   uint32
}

type physicalInterface struct {
	Index  uint32
	Name   string
	IPv4   net.IP
	IPNet  *net.IPNet
	Metric uint32
}

// DialDirect connects to addr by binding directly to a physical network interface
// (via IP_UNICAST_IF), bypassing virtual TUN/VPN adapters on Windows.
func DialDirect(ctx context.Context, addr string, tlsCfg *tls.Config) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("split host port %q: %w", addr, err)
	}

	ifaces, err := findPhysicalInterfaces()
	if err != nil {
		return nil, fmt.Errorf("find physical interfaces: %w", err)
	}
	if len(ifaces) == 0 {
		return nil, errors.New("no physical network interface available")
	}

	var targetIPs []net.IP
	if ip := net.ParseIP(host); ip != nil {
		targetIPs = []net.IP{ip}
	} else {
		targetIPs = resolveViaOSOrDirect(ctx, host, ifaces)
		if len(targetIPs) == 0 {
			return nil, fmt.Errorf("direct DNS lookup failed for %q", host)
		}
	}

	var effectiveTLS *tls.Config
	if tlsCfg != nil {
		effectiveTLS = tlsCfg.Clone()
		if effectiveTLS.ServerName == "" && net.ParseIP(host) == nil {
			effectiveTLS.ServerName = host
		}
	}

	var lastErr error
	for _, targetIP := range targetIPs {
		ip4 := targetIP.To4()
		if ip4 == nil {
			continue
		}
		ordered := orderInterfacesForTarget(ifaces, ip4)
		targetAddr := net.JoinHostPort(ip4.String(), port)
		for _, nic := range ordered {
			conn, err := dialOnInterface(ctx, targetAddr, nic, effectiveTLS)
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
	}

	if lastErr == nil {
		lastErr = errors.New("no IPv4 target address resolved")
	}
	return nil, lastErr
}

// ListenPacketDirect binds a UDP socket directly to the primary physical network
// interface (via IP_UNICAST_IF), bypassing virtual TUN/VPN adapters on Windows.
func ListenPacketDirect(ctx context.Context) (net.PacketConn, error) {
	ifaces, err := findPhysicalInterfaces()
	if err != nil {
		return nil, fmt.Errorf("find physical interfaces: %w", err)
	}
	if len(ifaces) == 0 {
		return nil, errors.New("no physical network interface available")
	}

	var lastErr error
	for _, nic := range ifaces {
		beIndex := hostToBigEndianUint32(nic.Index)
		lc := net.ListenConfig{
			Control: func(network, address string, c syscall.RawConn) error {
				var sockErr error
				if err := c.Control(func(fd uintptr) {
					sockErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, ipUnicastIf, int(int32(beIndex)))
				}); err != nil {
					return err
				}
				return sockErr
			},
		}
		pc, err := lc.ListenPacket(ctx, "udp4", net.JoinHostPort(nic.IPv4.String(), "0"))
		if err == nil {
			return pc, nil
		}
		lastErr = err
	}
	return nil, lastErr
}

func dialOnInterface(ctx context.Context, targetAddr string, nic physicalInterface, tlsCfg *tls.Config) (net.Conn, error) {
	beIndex := hostToBigEndianUint32(nic.Index)
	dialer := &net.Dialer{
		Timeout:   6 * time.Second,
		KeepAlive: 30 * time.Second,
		LocalAddr: &net.TCPAddr{IP: nic.IPv4},
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, ipUnicastIf, int(int32(beIndex)))
			}); err != nil {
				return err
			}
			return sockErr
		},
	}

	if tlsCfg != nil {
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    tlsCfg,
		}
		return tlsDialer.DialContext(ctx, "tcp4", targetAddr)
	}
	return dialer.DialContext(ctx, "tcp4", targetAddr)
}

func resolveViaOSOrDirect(ctx context.Context, host string, ifaces []physicalInterface) []net.IP {
	// Try OS resolver first; reject Fake-IP ranges (198.18.0.0/15) used by TUN proxies.
	if ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host); err == nil {
		var realIPs []net.IP
		for _, ip := range ips {
			if ip4 := ip.To4(); ip4 != nil && !isFakeIPv4(ip4) {
				realIPs = append(realIPs, ip4)
			}
		}
		if len(realIPs) > 0 {
			return realIPs
		}
	}

	// Fallback: query physical NIC's DHCP/static DNS first (for intranet domains), then public DNS.
	dnsServers := append(discoverPhysicalDNSServers(), "223.5.5.5:53", "119.29.29.29:53", "8.8.8.8:53")
	for _, nic := range ifaces {
		for _, dnsAddr := range dnsServers {
			if ips, err := queryDNSOverInterface(ctx, host, dnsAddr, nic); err == nil && len(ips) > 0 {
				return ips
			}
		}
	}
	return nil
}

func discoverPhysicalDNSServers() []string {
	subkey, err := syscall.UTF16PtrFromString(`SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces`)
	if err != nil {
		return nil
	}
	var root syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, subkey, 0, syscall.KEY_READ, &root); err != nil {
		return nil
	}
	defer syscall.RegCloseKey(root)

	seen := make(map[string]struct{})
	var out []string
	nameBuf := make([]uint16, 256)
	for idx := uint32(0); ; idx++ {
		n := uint32(len(nameBuf))
		if err := syscall.RegEnumKeyEx(root, idx, &nameBuf[0], &n, nil, nil, nil, nil); err != nil {
			break
		}
		var ifKey syscall.Handle
		if err := syscall.RegOpenKeyEx(root, &nameBuf[0], 0, syscall.KEY_READ, &ifKey); err != nil {
			continue
		}
		for _, valName := range []string{"NameServer", "DhcpNameServer"} {
			for _, ipStr := range readRegStringList(ifKey, valName) {
				ip := net.ParseIP(ipStr)
				if ip == nil {
					continue
				}
				ip4 := ip.To4()
				if ip4 == nil || ip4.IsLoopback() || ip4.IsUnspecified() || isFakeIPv4(ip4) {
					continue
				}
				addr := net.JoinHostPort(ip4.String(), "53")
				if _, ok := seen[addr]; !ok {
					seen[addr] = struct{}{}
					out = append(out, addr)
				}
			}
		}
		_ = syscall.RegCloseKey(ifKey)
	}
	return out
}

func readRegStringList(key syscall.Handle, valueName string) []string {
	ptr, err := syscall.UTF16PtrFromString(valueName)
	if err != nil {
		return nil
	}
	var typ, size uint32
	if err := syscall.RegQueryValueEx(key, ptr, nil, &typ, nil, &size); err != nil || size == 0 {
		return nil
	}
	buf := make([]uint16, (size+1)/2)
	if err := syscall.RegQueryValueEx(key, ptr, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &size); err != nil {
		return nil
	}
	raw := syscall.UTF16ToString(buf)
	return strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	})
}

func queryDNSOverInterface(ctx context.Context, host, dnsAddr string, nic physicalInterface) ([]net.IP, error) {
	qCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	beIndex := hostToBigEndianUint32(nic.Index)
	dialer := &net.Dialer{
		LocalAddr: &net.UDPAddr{IP: nic.IPv4},
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			if err := c.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, ipUnicastIf, int(int32(beIndex)))
			}); err != nil {
				return err
			}
			return sockErr
		},
	}

	conn, err := dialer.DialContext(qCtx, "udp4", dnsAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if deadline, ok := qCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	txID, query, err := buildDNSAQuery(host)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseDNSAResponse(buf[:n], txID)
}

func buildDNSAQuery(host string) (uint16, []byte, error) {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return 0, nil, errors.New("empty hostname")
	}

	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		idBytes = [2]byte{0x12, 0x34}
	}
	txID := binary.BigEndian.Uint16(idBytes[:])

	pkt := make([]byte, 12, 64)
	binary.BigEndian.PutUint16(pkt[0:2], txID)
	binary.BigEndian.PutUint16(pkt[2:4], 0x0100) // Standard query, recursion desired
	binary.BigEndian.PutUint16(pkt[4:6], 1)      // QDCOUNT = 1

	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 {
			return 0, nil, fmt.Errorf("invalid DNS label %q", label)
		}
		pkt = append(pkt, byte(len(label)))
		pkt = append(pkt, label...)
	}
	pkt = append(pkt, 0) // root label
	pkt = append(pkt, 0, 1, 0, 1) // QTYPE = A (1), QCLASS = IN (1)
	return txID, pkt, nil
}

func parseDNSAResponse(pkt []byte, expectedID uint16) ([]net.IP, error) {
	if len(pkt) < 12 {
		return nil, errors.New("short DNS response")
	}
	if binary.BigEndian.Uint16(pkt[0:2]) != expectedID {
		return nil, errors.New("DNS transaction ID mismatch")
	}
	qdCount := int(binary.BigEndian.Uint16(pkt[4:6]))
	anCount := int(binary.BigEndian.Uint16(pkt[6:8]))

	off := 12
	for i := 0; i < qdCount; i++ {
		next, err := skipDNSName(pkt, off)
		if err != nil {
			return nil, err
		}
		off = next + 4 // QTYPE + QCLASS
		if off > len(pkt) {
			return nil, errors.New("truncated DNS question")
		}
	}

	var ips []net.IP
	for i := 0; i < anCount; i++ {
		next, err := skipDNSName(pkt, off)
		if err != nil {
			return nil, err
		}
		if next+10 > len(pkt) {
			return nil, errors.New("truncated DNS answer")
		}
		rrType := binary.BigEndian.Uint16(pkt[next : next+2])
		rdLen := int(binary.BigEndian.Uint16(pkt[next+8 : next+10]))
		rdataStart := next + 10
		rdataEnd := rdataStart + rdLen
		if rdataEnd > len(pkt) {
			return nil, errors.New("truncated DNS rdata")
		}
		if rrType == 1 && rdLen == 4 {
			ip := net.IPv4(pkt[rdataStart], pkt[rdataStart+1], pkt[rdataStart+2], pkt[rdataStart+3])
			if !isFakeIPv4(ip) {
				ips = append(ips, ip)
			}
		}
		off = rdataEnd
	}
	return ips, nil
}

func skipDNSName(pkt []byte, off int) (int, error) {
	for {
		if off >= len(pkt) {
			return 0, errors.New("DNS name out of bounds")
		}
		l := int(pkt[off])
		if l == 0 {
			return off + 1, nil
		}
		if l&0xC0 == 0xC0 {
			if off+2 > len(pkt) {
				return 0, errors.New("DNS pointer out of bounds")
			}
			return off + 2, nil
		}
		off += 1 + l
	}
}

func findPhysicalInterfaces() ([]physicalInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	defaultMetrics := defaultRouteMetricsByIfIndex()

	var result []physicalInterface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if len(iface.HardwareAddr) == 0 || isVirtualInterfaceName(iface.Name) {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() || isFakeIPv4(ip4) {
				continue
			}
			metric := uint32(10000)
			if m, hasDefault := defaultMetrics[uint32(iface.Index)]; hasDefault {
				metric = m
			}
			result = append(result, physicalInterface{
				Index:  uint32(iface.Index),
				Name:   iface.Name,
				IPv4:   ip4,
				IPNet:  ipNet,
				Metric: metric,
			})
			break
		}
	}

	sort.SliceStable(result, func(i, j int) bool {
		return result[i].Metric < result[j].Metric
	})
	return result, nil
}

func defaultRouteMetricsByIfIndex() map[uint32]uint32 {
	metrics := make(map[uint32]uint32)
	var size uint32
	r1, _, _ := procGetIPForwardTable.Call(0, uintptr(unsafe.Pointer(&size)), 0)
	if r1 != errInsufficientBuffer || size < 4 {
		return metrics
	}
	buf := make([]byte, size)
	r1, _, _ = procGetIPForwardTable.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0)
	if r1 != 0 {
		return metrics
	}

	count := binary.LittleEndian.Uint32(buf[0:4])
	maxRows := (len(buf) - 4) / mibIPForwardRowSizeBytes
	if int(count) > maxRows {
		count = uint32(maxRows)
	}
	for i := 0; i < int(count); i++ {
		off := 4 + i*mibIPForwardRowSizeBytes
		row := (*mibIPForwardRow)(unsafe.Pointer(&buf[off]))
		if row.ForwardDest == 0 && row.ForwardMask == 0 && row.ForwardNextHop != 0 {
			if cur, exists := metrics[row.ForwardIfIndex]; !exists || row.ForwardMetric1 < cur {
				metrics[row.ForwardIfIndex] = row.ForwardMetric1
			}
		}
	}
	return metrics
}

func orderInterfacesForTarget(ifaces []physicalInterface, targetIP net.IP) []physicalInterface {
	ordered := make([]physicalInterface, 0, len(ifaces))
	var rest []physicalInterface
	for _, nic := range ifaces {
		if nic.IPNet != nil && nic.IPNet.Contains(targetIP) {
			ordered = append(ordered, nic)
		} else {
			rest = append(rest, nic)
		}
	}
	return append(ordered, rest...)
}

func isVirtualInterfaceName(name string) bool {
	lower := strings.ToLower(name)
	for _, kw := range []string{
		"wintun", "clash", "mihomo", "meta", "sing", "tun", "tap",
		"wireguard", "tailscale", "zerotier", "utun", "vpn",
		"vethernet", "hyper-v", "wsl", "vmware", "virtualbox", "vbox", "loopback",
	} {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func isFakeIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	return ip4[0] == 198 && (ip4[1] == 18 || ip4[1] == 19)
}

func hostToBigEndianUint32(v uint32) uint32 {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	return *(*uint32)(unsafe.Pointer(&b[0]))
}
