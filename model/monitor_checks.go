package model

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/textproto"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// Check kinds, expectations and destinations of design 29 M2a (lattice
// docs, design 29 D1, D2 and D10). The control plane and the agents read
// the same rules from here, so a check the control plane accepts is one an
// agent will run, and an agent refuses what the control plane would.

// MonitorTypeBeacon sends authenticated UDP requests to a node's beacon
// (design 29 D3, D12). A beacon check always names TargetNode and never an
// address: the control plane resolves Target to the node's advertised
// endpoint (address:port) each time it hands the check out, and the source
// signs with the path key it holds for that node. Agents that run it report
// it in Node.ProbeMethods.
const MonitorTypeBeacon = "beacon"

// Multi-packet runs (icmp and beacon).
const (
	MonitorPacketsDefault = 5
	MonitorPacketsMax     = 10
	// MonitorPacketSpacingMs is the gap between two echoes of one run. An
	// echo waits Monitor.TimeoutSec for its reply, so a run lasts at most
	// (packets-1) times the spacing plus the timeout, which a save keeps
	// under the interval.
	MonitorPacketSpacingMs = 200
	// MonitorPacketsPerSecondMax bounds, per (source, target address), the
	// packets per second of every enabled multi-packet check together
	// (packets over interval, summed), operator and generated alike.
	MonitorPacketsPerSecondMax = 2
)

// MonitorPackets is a monitor's packets per run: Packets, or the default
// when it is zero.
func MonitorPackets(m Monitor) int {
	if m.Packets <= 0 {
		return MonitorPacketsDefault
	}
	return m.Packets
}

// MonitorKindSendsPackets reports whether a kind sends several packets per
// run.
func MonitorKindSendsPackets(kind string) bool {
	return kind == MonitorTypeICMP || kind == MonitorTypeBeacon
}

// Probe methods an agent reports (Node.ProbeMethods).

// legacyProbeMethods are what an agent that reports no methods runs.
var legacyProbeMethods = []string{MonitorTypeHTTP, MonitorTypeTCP}

// KnownProbeMethod reports whether kind is one an agent may report.
func KnownProbeMethod(kind string) bool {
	switch kind {
	case MonitorTypeTCP, MonitorTypeHTTP, MonitorTypeICMP, MonitorTypeBeacon:
		return true
	}
	return false
}

// NormalizeProbeMethods keeps the known kinds of a report, once each and
// sorted; nil when none is known.
func NormalizeProbeMethods(in []string) []string {
	var out []string
	for _, raw := range in {
		kind := strings.TrimSpace(raw)
		if KnownProbeMethod(kind) && !slices.Contains(out, kind) {
			out = append(out, kind)
		}
	}
	slices.Sort(out)
	return out
}

// EffectiveProbeMethods is what an agent runs given what it reported: the
// report, or tcp and http for an agent that reported nothing.
func EffectiveProbeMethods(reported []string) []string {
	if len(reported) == 0 {
		return slices.Clone(legacyProbeMethods)
	}
	return NormalizeProbeMethods(reported)
}

// ProbeMethodSupported reports whether an agent that reported these
// methods runs kind.
func ProbeMethodSupported(reported []string, kind string) bool {
	return slices.Contains(EffectiveProbeMethods(reported), kind)
}

// HTTP expectations.

// MonitorExpectStatusDefault is the passing status set of an http check
// that names none: 200 to 399, what a check passed on before the field.
const MonitorExpectStatusDefault = "200-399"

// monitorStatusSetMaxParts bounds the entries of an expect_status list.
const monitorStatusSetMaxParts = 16

// MonitorStatusRange is an inclusive range of HTTP status codes.
type MonitorStatusRange struct {
	Lo int
	Hi int
}

// MonitorStatusSet is a parsed expect_status: sorted, merged ranges.
type MonitorStatusSet []MonitorStatusRange

// ParseMonitorStatusSet reads an expect_status list: codes and ranges
// ("200", "200-299") between 100 and 599, separated by commas, at most 16.
// An empty list is the default set.
func ParseMonitorStatusSet(raw string) (MonitorStatusSet, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = MonitorExpectStatusDefault
	}
	parts := strings.Split(raw, ",")
	if len(parts) > monitorStatusSetMaxParts {
		return nil, fmt.Errorf("expect_status has %d entries; at most %d", len(parts), monitorStatusSetMaxParts)
	}
	ranges := make([]MonitorStatusRange, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := parseStatusCode(lo)
		if err != nil {
			return nil, fmt.Errorf("expect_status entry %q: %w", part, err)
		}
		b := a
		if isRange {
			if b, err = parseStatusCode(hi); err != nil {
				return nil, fmt.Errorf("expect_status entry %q: %w", part, err)
			}
			if b < a {
				return nil, fmt.Errorf("expect_status entry %q runs backwards", part)
			}
		}
		ranges = append(ranges, MonitorStatusRange{Lo: a, Hi: b})
	}
	slices.SortFunc(ranges, func(x, y MonitorStatusRange) int { return x.Lo - y.Lo })
	merged := MonitorStatusSet{ranges[0]}
	for _, r := range ranges[1:] {
		last := &merged[len(merged)-1]
		if r.Lo <= last.Hi+1 {
			last.Hi = max(last.Hi, r.Hi)
			continue
		}
		merged = append(merged, r)
	}
	return merged, nil
}

func parseStatusCode(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	if len(raw) != 3 {
		return 0, errors.New("a status is three digits, 100 to 599")
	}
	code, err := strconv.Atoi(raw)
	if err != nil || code < 100 || code > 599 {
		return 0, errors.New("a status is three digits, 100 to 599")
	}
	return code, nil
}

// Contains reports whether code passes.
func (set MonitorStatusSet) Contains(code int) bool {
	for _, r := range set {
		if code >= r.Lo && code <= r.Hi {
			return true
		}
	}
	return false
}

// String is the canonical list: sorted, merged, no spaces.
func (set MonitorStatusSet) String() string {
	parts := make([]string, 0, len(set))
	for _, r := range set {
		if r.Lo == r.Hi {
			parts = append(parts, strconv.Itoa(r.Lo))
		} else {
			parts = append(parts, strconv.Itoa(r.Lo)+"-"+strconv.Itoa(r.Hi))
		}
	}
	return strings.Join(parts, ",")
}

// HTTP request headers.

// MonitorHeader is one request header of an http check. Value travels only
// from an editor to the control plane and from the control plane to the
// check's assigned agents. Every read the control plane answers drops the
// Value of a secret header and sets Set instead; Set means nothing anywhere
// else.
type MonitorHeader struct {
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
	Secret bool   `json:"secret,omitempty"`
	Set    bool   `json:"set,omitempty"`
}

// Bounds of an http check's headers.
const (
	MonitorHeadersMax     = 8
	MonitorHeaderNameMax  = 64
	MonitorHeaderValueMax = 4096
)

// Header edit operations (MonitorHeaderEdit.Op).
const (
	// MonitorHeaderKeep asserts the header exists and leaves it as it is;
	// the edit is refused when it does not, so a stale editor notices.
	MonitorHeaderKeep = "keep"
	// MonitorHeaderSet adds the header or replaces its value and secrecy.
	// Value is required.
	MonitorHeaderSet = "set"
	// MonitorHeaderDelete removes the header; deleting one that is not
	// there changes nothing.
	MonitorHeaderDelete = "delete"
)

// MonitorHeaderEdit is one operation of MonitorUpdate.Headers. A name may
// appear once per edit. Names compare without regard to case.
type MonitorHeaderEdit struct {
	Name   string `json:"name"`
	Op     string `json:"op"`
	Value  string `json:"value,omitempty"`
	Secret bool   `json:"secret,omitempty"`
}

// monitorForbiddenHeaders are set by the agent's HTTP stack or change how
// the request travels, so a check may not carry them. Host stays the URL's,
// so the origin a secret is bound to is the one the request reaches.
var monitorForbiddenHeaders = map[string]bool{
	"Connection":        true,
	"Content-Length":    true,
	"Expect":            true,
	"Host":              true,
	"Keep-Alive":        true,
	"Proxy-Connection":  true,
	"Te":                true,
	"Trailer":           true,
	"Transfer-Encoding": true,
	"Upgrade":           true,
}

// CanonicalMonitorHeaderName is the form names are stored and compared in
// ("x-api-key" becomes "X-Api-Key").
func CanonicalMonitorHeaderName(name string) string {
	return textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(name))
}

// ValidateMonitorHeader checks one header's name and value.
func ValidateMonitorHeader(name, value string) error {
	if name == "" || len(name) > MonitorHeaderNameMax {
		return fmt.Errorf("a header name is 1 to %d characters", MonitorHeaderNameMax)
	}
	for i := 0; i < len(name); i++ {
		if !isHeaderTokenByte(name[i]) {
			return fmt.Errorf("header name %q has a character a header name cannot carry", name)
		}
	}
	canonical := CanonicalMonitorHeaderName(name)
	if monitorForbiddenHeaders[canonical] || strings.HasPrefix(canonical, "Proxy-") {
		return fmt.Errorf("header %s cannot be set on a check", canonical)
	}
	if value == "" || len(value) > MonitorHeaderValueMax {
		return fmt.Errorf("header %s needs a value of 1 to %d bytes", canonical, MonitorHeaderValueMax)
	}
	for i := 0; i < len(value); i++ {
		if c := value[i]; (c < 0x20 && c != '\t') || c == 0x7f {
			return fmt.Errorf("header %s value has a control character", canonical)
		}
	}
	return nil
}

func isHeaderTokenByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// MonitorHasSecrets reports whether any header of m is secret.
func MonitorHasSecrets(m Monitor) bool {
	for _, h := range m.Headers {
		if h.Secret {
			return true
		}
	}
	return false
}

// MonitorOrigin is the origin of an http or https URL as secrets are bound
// to it: scheme://host:port, scheme and host in lower case, the port always
// written (80 or 443 when the URL leaves it out), an IPv6 host bracketed.
func MonitorOrigin(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", fmt.Errorf("target is not a URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	switch scheme {
	case "http":
		if port == "" {
			port = "80"
		}
	case "https":
		if port == "" {
			port = "443"
		}
	default:
		return "", errors.New("target must be an http or https URL")
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", errors.New("target URL has no host")
	}
	return scheme + "://" + net.JoinHostPort(host, port), nil
}

// Destinations.

// monitorMetadataPrefixes are cloud metadata services, refused even when
// a broader rule would not catch them.
var monitorMetadataPrefixes = []netip.Prefix{
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
}

// monitorRefusedPrefixes are private, shared and reserved IPv4 ranges that
// netip's predicates do not name.
var monitorRefusedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),      // "this network"
	netip.MustParsePrefix("100.64.0.0/10"),  // carrier-grade NAT, RFC 6598
	netip.MustParsePrefix("192.0.0.0/24"),   // IETF protocol assignments, RFC 6890
	netip.MustParsePrefix("192.88.99.0/24"), // 6to4 relay anycast, deprecated, RFC 7526
	netip.MustParsePrefix("198.18.0.0/15"),  // benchmarking, RFC 2544
	netip.MustParsePrefix("240.0.0.0/4"),    // reserved, RFC 1112, broadcast included
}

// IPv6 forms that carry or reach IPv4 space. The first three are judged by
// the IPv4 address they embed; the others are refused outright.
var (
	monitorNAT64WellKnown = netip.MustParsePrefix("64:ff9b::/96")    // RFC 6052, last 32 bits
	monitorIPv4Translated = netip.MustParsePrefix("::ffff:0:0:0/96") // RFC 2765, last 32 bits
	monitorSixToFour      = netip.MustParsePrefix("2002::/16")       // RFC 3056, bits 16 to 47
	monitorTransitionDeny = []netip.Prefix{
		netip.MustParsePrefix("64:ff9b:1::/48"), // local-use NAT64, RFC 8215
		netip.MustParsePrefix("::/96"),          // IPv4-compatible, deprecated
		netip.MustParsePrefix("fec0::/10"),      // site-local, deprecated
		netip.MustParsePrefix("2001::/32"),      // Teredo
		netip.MustParsePrefix("100::/64"),       // discard-only, RFC 6666
	}
)

// MonitorDestinationRefused reports whether an agent must refuse to dial
// addr for a check whose target is not a node reference (Monitor.TargetNode
// empty): loopback, link-local, cloud metadata, multicast, private
// (RFC 1918, fc00::/7), carrier-grade NAT, reserved, benchmarking,
// unspecified and broadcast addresses, and IPv6 transition forms that reach
// IPv4 space (NAT64, 6to4 and IPv4-translated addresses judged by the IPv4
// address they embed; local-use NAT64, IPv4-compatible, site-local and
// Teredo refused). An IPv4-mapped address is judged as its IPv4 address and
// a zone never changes the verdict. An agent resolves a host name once,
// judges every address it got, and dials only an address it judged.
func MonitorDestinationRefused(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	if !addr.IsValid() || addr.IsUnspecified() || addr.IsLoopback() || addr.IsMulticast() ||
		addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() ||
		addr.IsPrivate() {
		return true
	}
	for _, p := range monitorMetadataPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	if addr.Is4() {
		for _, p := range monitorRefusedPrefixes {
			if p.Contains(addr) {
				return true
			}
		}
		return false
	}
	for _, p := range monitorTransitionDeny {
		if p.Contains(addr) {
			return true
		}
	}
	b := addr.As16()
	var embedded [4]byte
	switch {
	case monitorNAT64WellKnown.Contains(addr), monitorIPv4Translated.Contains(addr):
		copy(embedded[:], b[12:16])
	case monitorSixToFour.Contains(addr):
		copy(embedded[:], b[2:6])
	default:
		return false
	}
	return MonitorDestinationRefused(netip.AddrFrom4(embedded))
}
