package model

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
)

// The DNS check method of design 32 S5a. A dns check asks one resolver one
// question from each source and judges the answer. The control plane and
// the agents read the same rules from here: the resolver endpoint forms,
// the question, and the canonical form of an expected or answered value,
// so an expected value the control plane stored compares with an answer
// the agent decoded as one string.

// MonitorTypeDNS asks Monitor.Target, a resolver endpoint
// (ParseDNSResolver), the question DNSName and DNSType, and judges the
// answer against DNSExpect and DNSExpectRcode. Agents that run it report it
// in Node.ProbeMethods.
const MonitorTypeDNS = "dns"

// Resolver transports, the schemes of a dns check's target.
const (
	// DNSTransportDoH is DNS over HTTPS (RFC 8484): a POST of
	// application/dns-message to the URL.
	DNSTransportDoH = "https"
	// DNSTransportDoT is DNS over TLS (RFC 7858): the message behind a
	// two-byte length over a TLS connection.
	DNSTransportDoT = "tls"
	// DNSTransportUDP is plain DNS over UDP; a truncated answer is asked
	// again once over TCP.
	DNSTransportUDP = "udp"
	// DNSTransportTCP is plain DNS over TCP.
	DNSTransportTCP = "tcp"
)

// Default ports of the transports.
const (
	DNSPortDoH   = 443
	DNSPortDoT   = 853
	DNSPortPlain = 53
)

// Bounds of a dns check and its results.
const (
	// MonitorDNSNameMax is the longest question name, in bytes, without
	// the trailing dot.
	MonitorDNSNameMax = 253
	// MonitorDNSExpectMax bounds Monitor.DNSExpect.
	MonitorDNSExpectMax = 16
	// MonitorDNSAnswersMax bounds MonitorResult.DNSAnswers.
	MonitorDNSAnswersMax = 16
	// MonitorDNSValueMax bounds one expected or reported value, in bytes.
	MonitorDNSValueMax = 255
	// MonitorDNSResponseMax is the most an agent reads of one response.
	MonitorDNSResponseMax = 64 << 10
)

// Question types a dns check may ask (Monitor.DNSType). HTTPS and SVCB are
// left out: their records decode as opaque bytes, which nothing compares.
const (
	DNSTypeA     = "A"
	DNSTypeAAAA  = "AAAA"
	DNSTypeCNAME = "CNAME"
	DNSTypeTXT   = "TXT"
	DNSTypeMX    = "MX"
	DNSTypeNS    = "NS"
)

// DNSTypes are the question types in the order a console offers them.
var DNSTypes = []string{DNSTypeA, DNSTypeAAAA, DNSTypeCNAME, DNSTypeTXT, DNSTypeMX, DNSTypeNS}

// Response codes a dns check may expect (Monitor.DNSExpectRcode). Empty
// reads as DNSRcodeNoError.
const (
	DNSRcodeNoError  = "NOERROR"
	DNSRcodeNXDomain = "NXDOMAIN"
)

// Why a dns run failed. MonitorResult.Error starts with one of these codes
// and a colon, so a console can name the failure without parsing prose. A
// failure is down, not unknown: these never go in MonitorResult.Reason.
const (
	// DNSFailureRcode: the response code was not the expected one;
	// MonitorResult.DNSRcode carries it.
	DNSFailureRcode = "dns_rcode"
	// DNSFailureMismatch: an expected value is not in the answer.
	DNSFailureMismatch = "dns_mismatch"
	// DNSFailureNoAnswer: the response was NOERROR with no answer of the
	// asked type.
	DNSFailureNoAnswer = "dns_no_answer"
	// DNSFailureTransport: the query got no decodable response: the
	// connection, the TLS handshake (the certificate included), the HTTP
	// status, the timeout or a response that is too large or malformed.
	DNSFailureTransport = "dns_transport"
)

// DNSResolver is a parsed dns check target.
type DNSResolver struct {
	// Transport is a DNSTransport* value, the target's scheme.
	Transport string
	// Host is a lower-case name or an IP literal, without brackets.
	Host string
	// Port is the port written, or the transport's default.
	Port int
	// Path is a DoH URL's path; empty for every other transport.
	Path string
}

// ParseDNSResolver reads a dns check target: https://host[:port]/path for
// DoH, tls://host[:port] for DoT, udp://host[:port] and tcp://host[:port]
// for plain DNS. The host is a name or an IP literal (an IPv6 one in
// brackets). A target carries no user info, query or fragment, and only a
// DoH target has a path, which it must have. It does not judge whether the
// host is a public destination; see MonitorDestinationRefused.
func ParseDNSResolver(raw string) (DNSResolver, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.Opaque != "" || u.Host == "" {
		return DNSResolver{}, errors.New("a dns check's target is a resolver endpoint: https://host/path, tls://host, udp://host or tcp://host, each with an optional :port")
	}
	r := DNSResolver{Transport: strings.ToLower(u.Scheme)}
	switch r.Transport {
	case DNSTransportDoH:
		r.Port = DNSPortDoH
	case DNSTransportDoT:
		r.Port = DNSPortDoT
	case DNSTransportUDP, DNSTransportTCP:
		r.Port = DNSPortPlain
	default:
		return DNSResolver{}, fmt.Errorf("a dns check's target scheme is https (DoH), tls (DoT), udp or tcp, not %q", u.Scheme)
	}
	if u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return DNSResolver{}, errors.New("a dns check's target carries no user name, query or fragment")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return DNSResolver{}, fmt.Errorf("a dns check's target has port %q; it must be 1 to 65535", port)
		}
		r.Port = n
	} else if strings.HasSuffix(u.Host, ":") {
		return DNSResolver{}, errors.New("a dns check's target names an empty port")
	}
	host := u.Hostname()
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return DNSResolver{}, errors.New("a dns check's target address cannot carry a zone")
		}
		if addr.Is6() && !strings.HasPrefix(u.Host, "[") {
			return DNSResolver{}, errors.New("a dns check's IPv6 target is written in brackets")
		}
		r.Host = addr.String()
	} else {
		name, err := NormalizeDNSName(host)
		if err != nil {
			return DNSResolver{}, fmt.Errorf("a dns check's target host %q: %w", host, err)
		}
		r.Host = name
	}
	if r.Transport == DNSTransportDoH {
		if u.EscapedPath() == "" || u.EscapedPath() == "/" {
			return DNSResolver{}, errors.New("a DoH target names its path, such as https://dns.example/dns-query")
		}
		r.Path = u.EscapedPath()
	} else if u.EscapedPath() != "" && u.EscapedPath() != "/" {
		return DNSResolver{}, fmt.Errorf("only a DoH target has a path; a %s target is %s://host[:port]", r.Transport, r.Transport)
	}
	return r, nil
}

// Encrypted reports whether the transport verifies a certificate (DoH and
// DoT), so a run records the certificate's expiry.
func (r DNSResolver) Encrypted() bool {
	return r.Transport == DNSTransportDoH || r.Transport == DNSTransportDoT
}

// HostPort is the host and port a run connects to.
func (r DNSResolver) HostPort() string {
	host := r.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return host + ":" + strconv.Itoa(r.Port)
}

// String is the canonical target: the scheme and host in lower case and
// the port written only when it is not the transport's default, so two
// spellings of one endpoint are one target.
func (r DNSResolver) String() string {
	host := r.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	def := DNSPortPlain
	switch r.Transport {
	case DNSTransportDoH:
		def = DNSPortDoH
	case DNSTransportDoT:
		def = DNSPortDoT
	}
	if r.Port != def {
		host += ":" + strconv.Itoa(r.Port)
	}
	return r.Transport + "://" + host + r.Path
}

// URL is a DoH target's request URL; empty for the other transports.
func (r DNSResolver) URL() string {
	if r.Transport != DNSTransportDoH {
		return ""
	}
	return "https://" + r.HostPort() + r.Path
}

// NormalizeDNSName checks a question name and returns its canonical form:
// lower case, without the trailing dot. A name is at most
// MonitorDNSNameMax bytes of letters, digits, hyphens, underscores and
// dots, in labels of 1 to 63 bytes; it is always asked as fully qualified.
func NormalizeDNSName(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
	if name == "" {
		return "", errors.New("a dns check asks a name, such as example.com")
	}
	if len(name) > MonitorDNSNameMax {
		return "", fmt.Errorf("a name is at most %d bytes; this one is %d", MonitorDNSNameMax, len(name))
	}
	for label := range strings.SplitSeq(name, ".") {
		if label == "" {
			return "", fmt.Errorf("name %q has an empty label", raw)
		}
		if len(label) > 63 {
			return "", fmt.Errorf("name %q has a label longer than 63 bytes", raw)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", fmt.Errorf("name %q has %q; a name is letters, digits, hyphens, underscores and dots (write an internationalized name in its xn-- form)", raw, string(rune(c)))
			}
		}
	}
	return name, nil
}

// NormalizeDNSType is a question type in canonical form: upper case, and
// DNSTypeA when empty.
func NormalizeDNSType(raw string) (string, error) {
	typ := strings.ToUpper(strings.TrimSpace(raw))
	if typ == "" {
		return DNSTypeA, nil
	}
	if !slices.Contains(DNSTypes, typ) {
		return "", fmt.Errorf("dns_type is one of %s, not %q", strings.Join(DNSTypes, ", "), raw)
	}
	return typ, nil
}

// NormalizeDNSExpectRcode is an expected response code in canonical form:
// empty for NOERROR, DNSRcodeNXDomain for a name that must not resolve.
func NormalizeDNSExpectRcode(raw string) (string, error) {
	switch code := strings.ToUpper(strings.TrimSpace(raw)); code {
	case "", DNSRcodeNoError:
		return "", nil
	case DNSRcodeNXDomain:
		return code, nil
	}
	return "", fmt.Errorf("dns_expect_rcode is %s or %s, not %q", DNSRcodeNoError, DNSRcodeNXDomain, raw)
}

// CanonicalDNSValue is an expected or answered value of a question type in
// the form the two are compared in: an A or AAAA value as its parsed
// address (an A value IPv4, an AAAA value IPv6), a CNAME, MX or NS value as
// a name in lower case without the trailing dot (an MX value is the
// exchange, without its preference), and a TXT value as the record's
// strings joined, compared exactly. A value is 1 to MonitorDNSValueMax
// bytes.
func CanonicalDNSValue(typ, raw string) (string, error) {
	switch typ {
	case DNSTypeA, DNSTypeAAAA:
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil || addr.Zone() != "" {
			return "", fmt.Errorf("%q is not an address", raw)
		}
		if typ == DNSTypeA && !addr.Is4() {
			return "", fmt.Errorf("an A answer is an IPv4 address, not %q", raw)
		}
		if typ == DNSTypeAAAA && !addr.Is6() {
			return "", fmt.Errorf("an AAAA answer is an IPv6 address, not %q", raw)
		}
		return addr.String(), nil
	case DNSTypeCNAME, DNSTypeMX, DNSTypeNS:
		name, err := NormalizeDNSName(raw)
		if err != nil {
			return "", fmt.Errorf("a %s answer is a name: %w", typ, err)
		}
		return name, nil
	case DNSTypeTXT:
		if raw == "" || len(raw) > MonitorDNSValueMax {
			return "", fmt.Errorf("a TXT value is 1 to %d bytes", MonitorDNSValueMax)
		}
		return raw, nil
	}
	return "", fmt.Errorf("dns_type %q has no values", typ)
}
