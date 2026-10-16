package model

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestParseMonitorStatusSet(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		pass    []int
		fail    []int
		wantErr string
	}{
		{in: "", want: "200-399", pass: []int{200, 301, 399}, fail: []int{199, 400, 503}},
		{in: " 204 ", want: "204", pass: []int{204}, fail: []int{200}},
		{in: "200-299, 301,404", want: "200-299,301,404", pass: []int{250, 301, 404}, fail: []int{300, 302}},
		{in: "301,200-299,300", want: "200-301", pass: []int{300, 301}, fail: []int{302}},
		{in: "200-250,240-260", want: "200-260"},
		{in: "599", want: "599"},
		{in: "99", wantErr: "three digits"},
		{in: "600", wantErr: "three digits"},
		{in: "2xx", wantErr: "three digits"},
		{in: "299-200", wantErr: "backwards"},
		{in: "200,,300", wantErr: "three digits"},
		{in: "200-", wantErr: "three digits"},
		{in: strings.Repeat("200,", 16) + "200", wantErr: "at most 16"},
	}
	for _, tc := range cases {
		set, err := ParseMonitorStatusSet(tc.in)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("%q: err = %v, want %q", tc.in, err, tc.wantErr)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", tc.in, err)
			continue
		}
		if got := set.String(); got != tc.want {
			t.Errorf("%q: canonical = %q, want %q", tc.in, got, tc.want)
		}
		for _, code := range tc.pass {
			if !set.Contains(code) {
				t.Errorf("%q: %d should pass", tc.in, code)
			}
		}
		for _, code := range tc.fail {
			if set.Contains(code) {
				t.Errorf("%q: %d should fail", tc.in, code)
			}
		}
	}
}

func TestValidateMonitorHeader(t *testing.T) {
	ok := [][2]string{
		{"Authorization", "Bearer abc"},
		{"x-api-key", "k\tv"},
		{"Cookie", "a=b"},
		{"X-" + strings.Repeat("a", MonitorHeaderNameMax-2), strings.Repeat("v", MonitorHeaderValueMax)},
	}
	for _, h := range ok {
		if err := ValidateMonitorHeader(h[0], h[1]); err != nil {
			t.Errorf("%q: %v", h[0], err)
		}
	}
	bad := [][2]string{
		{"", "v"},
		{"X Space", "v"},
		{"X:Colon", "v"},
		{strings.Repeat("a", MonitorHeaderNameMax+1), "v"},
		{"Host", "example.com"},
		{"host", "example.com"},
		{"Transfer-Encoding", "chunked"},
		{"Proxy-Authorization", "x"},
		{"X-Ok", ""},
		{"X-Ok", "line\r\nX-Injected: 1"},
		{"X-Ok", "nul\x00"},
		{"X-Ok", strings.Repeat("v", MonitorHeaderValueMax+1)},
	}
	for _, h := range bad {
		if err := ValidateMonitorHeader(h[0], h[1]); err == nil {
			t.Errorf("%q=%q accepted", h[0], h[1])
		}
	}
	if got := CanonicalMonitorHeaderName(" x-api-KEY "); got != "X-Api-Key" {
		t.Fatalf("canonical = %q", got)
	}
}

func TestMonitorOrigin(t *testing.T) {
	cases := map[string]string{
		"https://Example.COM/health?x=1": "https://example.com:443",
		"HTTPS://example.com:8443/":      "https://example.com:8443",
		"http://example.com":             "http://example.com:80",
		"https://[2001:db8::1]/x":        "https://[2001:db8::1]:443",
		"https://user:pw@example.com/":   "https://example.com:443",
	}
	for in, want := range cases {
		got, err := MonitorOrigin(in)
		if err != nil || got != want {
			t.Errorf("%q: origin = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"ftp://example.com/", "https:///x", "example.com", "://"} {
		if got, err := MonitorOrigin(in); err == nil {
			t.Errorf("%q: origin %q accepted", in, got)
		}
	}
}

func TestMonitorDestinationRefused(t *testing.T) {
	refused := []string{
		"127.0.0.1", "::1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254",
		"169.254.1.1", "fd00:ec2::254", "fc00::1", "fe80::1", "224.0.0.1", "ff02::1",
		"0.0.0.0", "::", "0.1.2.3", "100.64.0.1", "255.255.255.255", "::ffff:10.0.0.1",
		"::ffff:127.0.0.1",
	}
	for _, raw := range refused {
		if !MonitorDestinationRefused(netip.MustParseAddr(raw)) {
			t.Errorf("%s allowed", raw)
		}
	}
	allowed := []string{"1.1.1.1", "8.8.8.8", "2606:4700:4700::1111", "::ffff:1.1.1.1", "203.0.113.7"}
	for _, raw := range allowed {
		if MonitorDestinationRefused(netip.MustParseAddr(raw)) {
			t.Errorf("%s refused", raw)
		}
	}
	if !MonitorDestinationRefused(netip.Addr{}) {
		t.Error("the zero address allowed")
	}
}

func TestProbeMethods(t *testing.T) {
	if got := EffectiveProbeMethods(nil); !slices.Equal(got, []string{"http", "tcp"}) {
		t.Fatalf("legacy = %v", got)
	}
	if !ProbeMethodSupported(nil, MonitorTypeTCP) || ProbeMethodSupported(nil, MonitorTypeICMP) {
		t.Fatal("a legacy agent runs exactly tcp and http")
	}
	got := NormalizeProbeMethods([]string{" icmp", "tcp", "gopher", "icmp", "http", "beacon"})
	if !slices.Equal(got, []string{"beacon", "http", "icmp", "tcp"}) {
		t.Fatalf("normalized = %v", got)
	}
	if NormalizeProbeMethods([]string{"gopher"}) != nil {
		t.Fatal("a report of no known kind must read as no report")
	}
	if !ProbeMethodSupported([]string{"tcp", "http", "icmp"}, MonitorTypeICMP) {
		t.Fatal("icmp reported but not supported")
	}
	if ProbeMethodSupported([]string{"tcp", "icmp"}, MonitorTypeHTTP) {
		t.Fatal("a report is taken as the whole list")
	}
	if MonitorPackets(Monitor{}) != MonitorPacketsDefault || MonitorPackets(Monitor{Packets: 3}) != 3 {
		t.Fatal("packets default")
	}
	if !MonitorKindSendsPackets(MonitorTypeICMP) || MonitorKindSendsPackets(MonitorTypeTCP) {
		t.Fatal("packet kinds")
	}
}

// Every M2a field is additive: absent on a monitor, a result, a node and a
// bucket that never set it, so deployed agents and consoles decode what they
// always did.
func TestM2aFieldsOmittedUntilSet(t *testing.T) {
	for name, v := range map[string]any{
		"monitor": Monitor{ID: "mon_x", Type: MonitorTypeTCP},
		"result":  MonitorResult{MonitorID: "mon_x"},
		"node":    Node{ID: "n1"},
		"bucket":  PathBucket{},
		"config":  LatencyProbeConfig{},
		"pair":    LatencyProbePairState{},
		"plan":    LatencyProbeNode{},
	} {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{
			"target_node", "packets", "expect_status", "headers", "secrets_origin",
			`"sent"`, `"lost"`, "rtts_ms", `"reason"`, "probe_methods", "probe_refusals",
			`"method"`, "source_methods", "icmp_target", "icmp_monitor_id",
		} {
			if strings.Contains(string(raw), field) {
				t.Errorf("%s carries %s while unset: %s", name, field, raw)
			}
		}
	}
	var upd MonitorUpdate
	body := `{"id":"mon_x","version":2,"headers":[{"name":"Authorization","op":"keep"},{"name":"X-Key","op":"set","value":"v","secret":true}]}`
	if err := json.Unmarshal([]byte(body), &upd); err != nil {
		t.Fatal(err)
	}
	if len(upd.Headers) != 2 || upd.Headers[1].Op != MonitorHeaderSet || !upd.Headers[1].Secret || upd.Packets != nil {
		t.Fatalf("update = %+v", upd)
	}
}
