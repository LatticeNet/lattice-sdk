package beacon

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Ports.
const (
	// PortRandomMin and PortRandomMax bound the listen port the control
	// plane assigns a node at random, away from fixed well-known defaults
	// that land on scan lists.
	PortRandomMin = 40000
	PortRandomMax = 59999
	// PortOverrideMin is the lowest listen port an operator may choose:
	// the beacon never takes a privileged port.
	PortOverrideMin = 1024
)

// Errors the address rules return.
var (
	ErrNotIPv4Literal = errors.New("beacon: not an IPv4 literal")
	ErrAddressRefused = errors.New("beacon: address class refused")
	ErrPort           = errors.New("beacon: port out of range")
)

// AddressRefused reports whether a beacon may never use a as an endpoint or
// a bind address: anything but IPv4, unspecified (0.0.0.0/8), loopback
// (127.0.0.0/8), link-local (169.254.0.0/16, which holds cloud metadata),
// multicast (224.0.0.0/4) and the reserved 240.0.0.0/4 with the broadcast
// address. Private and shared ranges stay allowed: a NAT node may bind its
// private address, and a beacon target is always a node the control plane
// resolved, never an address an operator typed.
func AddressRefused(a netip.Addr) bool {
	if !a.Is4() {
		return true
	}
	b := a.As4()
	switch {
	case b[0] == 0, b[0] == 127:
		return true
	case b[0] == 169 && b[1] == 254:
		return true
	case b[0] >= 224:
		return true
	}
	return false
}

// ParseEndpoint reads an advertised endpoint: an IPv4 literal and a port
// (for a NAT node, the mapped public address and port). Host names are
// refused, so a source can never be pointed at a third party or rebound to
// an internal address by DNS, and so is every class AddressRefused names.
// Sources apply the same rule before they send.
func ParseEndpoint(s string) (netip.AddrPort, error) {
	host, portText, ok := strings.Cut(strings.TrimSpace(s), ":")
	if !ok || strings.Contains(portText, ":") {
		return netip.AddrPort{}, fmt.Errorf("%w: endpoint %q is not address:port", ErrNotIPv4Literal, s)
	}
	addr, err := ParseIPv4(host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || portText != strconv.Itoa(port) {
		return netip.AddrPort{}, fmt.Errorf("%w: endpoint port %q", ErrPort, portText)
	}
	return netip.AddrPortFrom(addr, uint16(port)), nil
}

// ParseIPv4 reads a bind address or an endpoint's host: a dotted-quad IPv4
// literal in canonical form, of a class AddressRefused allows. The agent
// binds exactly this address, never the wildcard.
func ParseIPv4(s string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil || !addr.Is4() || addr.Zone() != "" || addr.String() != s {
		return netip.Addr{}, fmt.Errorf("%w: %q", ErrNotIPv4Literal, s)
	}
	if AddressRefused(addr) {
		return netip.Addr{}, fmt.Errorf("%w: %s", ErrAddressRefused, s)
	}
	return addr, nil
}

// ValidListenPort reports whether port may be a beacon's listen port:
// PortOverrideMin to 65535.
func ValidListenPort(port int) bool {
	return port >= PortOverrideMin && port <= 65535
}
