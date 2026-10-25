package model

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

func TestParseDNSResolver(t *testing.T) {
	for _, tc := range []struct {
		raw       string
		transport string
		host      string
		port      int
		path      string
		canonical string
	}{
		{"https://dns.google/dns-query", DNSTransportDoH, "dns.google", 443, "/dns-query", "https://dns.google/dns-query"},
		{"HTTPS://DNS.Example:8443/q/abc", DNSTransportDoH, "dns.example", 8443, "/q/abc", "https://dns.example:8443/q/abc"},
		{"tls://1.1.1.1", DNSTransportDoT, "1.1.1.1", 853, "", "tls://1.1.1.1"},
		{"tls://dns.example:853/", DNSTransportDoT, "dns.example", 853, "", "tls://dns.example"},
		{" udp://8.8.8.8:53 ", DNSTransportUDP, "8.8.8.8", 53, "", "udp://8.8.8.8"},
		{"tcp://[2606:4700:4700::1111]:5353", DNSTransportTCP, "2606:4700:4700::1111", 5353, "", "tcp://[2606:4700:4700::1111]:5353"},
	} {
		r, err := ParseDNSResolver(tc.raw)
		if err != nil {
			t.Fatalf("%q: %v", tc.raw, err)
		}
		if r.Transport != tc.transport || r.Host != tc.host || r.Port != tc.port || r.Path != tc.path {
			t.Fatalf("%q parsed as %+v", tc.raw, r)
		}
		if r.String() != tc.canonical {
			t.Fatalf("%q canonical = %q, want %q", tc.raw, r.String(), tc.canonical)
		}
		again, err := ParseDNSResolver(r.String())
		if err != nil || again != r {
			t.Fatalf("%q: the canonical form does not parse back: %+v %v", tc.raw, again, err)
		}
	}
	r, _ := ParseDNSResolver("tcp://[2606:4700:4700::1111]:5353")
	if r.HostPort() != "[2606:4700:4700::1111]:5353" || r.Encrypted() || r.URL() != "" {
		t.Fatalf("plain resolver = %q %v %q", r.HostPort(), r.Encrypted(), r.URL())
	}
	r, _ = ParseDNSResolver("https://dns.example:8443/dns-query")
	if !r.Encrypted() || r.URL() != "https://dns.example:8443/dns-query" {
		t.Fatalf("DoH resolver = %v %q", r.Encrypted(), r.URL())
	}

	for _, raw := range []string{
		"", "dns.google", "8.8.8.8:53", "udp:8.8.8.8", "quic://dns.example", "http://dns.example/dns-query",
		"https://dns.example", "https://dns.example/", "udp://dns.example/path", "tls://dns.example:0",
		"tcp://dns.example:65536", "tcp://dns.example:", "https://user:pw@dns.example/dns-query",
		"https://dns.example/dns-query?token=1", "https://dns.example/dns-query#x", "udp://fe80::1%25eth0",
		"udp://[fe80::1%25eth0]", "udp://exa mple.com", "udp://bad_label..com",
	} {
		if r, err := ParseDNSResolver(raw); err == nil {
			t.Errorf("%q accepted as %+v", raw, r)
		}
	}
}

func TestNormalizeDNSName(t *testing.T) {
	for raw, want := range map[string]string{
		"Example.COM.":                  "example.com",
		" _dmarc.example.com ":          "_dmarc.example.com",
		"xn--bcher-kva.example":         "xn--bcher-kva.example",
		"a-b.c":                         "a-b.c",
		strings.Repeat("a.", 126) + "a": strings.Repeat("a.", 126) + "a",
	} {
		got, err := NormalizeDNSName(raw)
		if err != nil || got != want {
			t.Errorf("%q = %q %v, want %q", raw, got, err, want)
		}
	}
	for _, raw := range []string{
		"", ".", "a..b", "exa mple.com", "bücher.example", "a/b", strings.Repeat("a", 64) + ".com",
		strings.Repeat("a.", 127) + "a",
	} {
		if got, err := NormalizeDNSName(raw); err == nil {
			t.Errorf("%q accepted as %q", raw, got)
		}
	}
}

func TestNormalizeDNSTypeAndRcode(t *testing.T) {
	if typ, err := NormalizeDNSType(""); err != nil || typ != DNSTypeA {
		t.Fatalf("empty type = %q %v", typ, err)
	}
	if typ, err := NormalizeDNSType(" aaaa "); err != nil || typ != DNSTypeAAAA {
		t.Fatalf("aaaa = %q %v", typ, err)
	}
	for _, raw := range []string{"HTTPS", "SVCB", "ANY", "SOA", "PTR"} {
		if _, err := NormalizeDNSType(raw); err == nil {
			t.Errorf("type %s accepted", raw)
		}
	}
	for raw, want := range map[string]string{"": "", "noerror": "", "NOERROR": "", "nxdomain": DNSRcodeNXDomain} {
		if got, err := NormalizeDNSExpectRcode(raw); err != nil || got != want {
			t.Errorf("rcode %q = %q %v", raw, got, err)
		}
	}
	for _, raw := range []string{"SERVFAIL", "REFUSED", "3"} {
		if _, err := NormalizeDNSExpectRcode(raw); err == nil {
			t.Errorf("rcode %s accepted", raw)
		}
	}
}

func TestCanonicalDNSValue(t *testing.T) {
	for _, tc := range []struct{ typ, raw, want string }{
		{DNSTypeA, " 192.0.2.1 ", "192.0.2.1"},
		{DNSTypeAAAA, "2001:DB8:0:0::1", "2001:db8::1"},
		{DNSTypeAAAA, "::ffff:192.0.2.1", "::ffff:192.0.2.1"},
		{DNSTypeCNAME, "Edge.Example.NET.", "edge.example.net"},
		{DNSTypeMX, "mx1.example.com", "mx1.example.com"},
		{DNSTypeNS, "NS1.example.com.", "ns1.example.com"},
		{DNSTypeTXT, "v=spf1 -all", "v=spf1 -all"},
		{DNSTypeTXT, " Keep Spaces ", " Keep Spaces "},
	} {
		got, err := CanonicalDNSValue(tc.typ, tc.raw)
		if err != nil || got != tc.want {
			t.Errorf("%s %q = %q %v, want %q", tc.typ, tc.raw, got, err, tc.want)
		}
	}
	for _, tc := range []struct{ typ, raw string }{
		{DNSTypeA, "2001:db8::1"},
		{DNSTypeA, "::ffff:192.0.2.1"},
		{DNSTypeA, "example.com"},
		{DNSTypeAAAA, "192.0.2.1"},
		{DNSTypeAAAA, "fe80::1%eth0"},
		{DNSTypeCNAME, "not a name"},
		{DNSTypeMX, "10 mx1.example.com"},
		{DNSTypeTXT, ""},
		{DNSTypeTXT, strings.Repeat("x", MonitorDNSValueMax+1)},
		{"HTTPS", "anything"},
	} {
		if got, err := CanonicalDNSValue(tc.typ, tc.raw); err == nil {
			t.Errorf("%s %q accepted as %q", tc.typ, tc.raw, got)
		}
	}
}

// TestDNSFieldsAreAdditive pins that a check of any other kind, and its
// result, carry none of the dns keys on the wire, so an agent or console
// that predates them reads what it always did.
func TestDNSFieldsAreAdditive(t *testing.T) {
	for _, v := range []any{
		Monitor{ID: "mon_1", Type: MonitorTypeTCP, Target: "example.com:443"},
		MonitorResult{MonitorID: "mon_1", NodeID: "n1", Success: true},
		CheckDefinitionSpec{Name: "x", Type: MonitorTypeTCP},
		MonitorUpdate{ID: "mon_1", Version: 1},
	} {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "dns_") {
			t.Fatalf("%T carries a dns key when unset: %s", v, raw)
		}
	}
	raw, _ := json.Marshal(MonitorResult{DNSRcode: "SERVFAIL", DNSAnswers: []string{"192.0.2.1"}})
	var back MonitorResult
	if err := json.Unmarshal(raw, &back); err != nil || back.DNSRcode != "SERVFAIL" || !slices.Equal(back.DNSAnswers, []string{"192.0.2.1"}) {
		t.Fatalf("dns result round trip = %+v %v (%s)", back, err, raw)
	}
	if !KnownProbeMethod(MonitorTypeDNS) {
		t.Fatal("dns is not a probe method an agent may report")
	}
}
