package model

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/LatticeNet/lattice-sdk/plugin"
)

const (
	catalogueLineA = "3f2b8c1e-7d4a-4e5f-9a6b-1c2d3e4f5a6b"
	catalogueLineB = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
)

func catalogueTestTime(t *testing.T, value string) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return at
}

// fullCatalogueRow sets every field, with values of realistic length.
func fullCatalogueRow(t *testing.T) LineCatalogueRow {
	udp := true
	return LineCatalogueRow{
		LineUUID: catalogueLineA, LineHashID: "lh_5f0c2a9e41d7b3c8", NodeID: "node-tokyo-03", NodeName: "Tokyo 03 (IIJ)",
		Name: "vless-reality-443", NodeTags: []string{"premium", "asia"}, GroupIDs: []string{"grp_asia"},
		Geo: &NodeGeo{Country: "JP", Region: "Tokyo", City: "Tokyo", ASN: 2497, ASOrg: "IIJ", Provider: "IIJ",
			Source: "operator", UpdatedAt: catalogueTestTime(t, "2026-10-01T00:00:00Z")},
		Machine:   &LineCatalogueMachine{Vendor: "IIJ", Region: "ap-northeast-1", NextRenewal: catalogueTestTime(t, "2026-11-15T00:00:00Z")},
		DDNSNames: []LineCatalogueDDNSName{{Name: "tyo3.example.net", Verified: true}, {Name: "tyo3-v6.example.net"}},
		Protocol:  "vless", Transport: "tcp", Security: "reality", PublicHost: "203.0.113.30", PublicPort: 443,
		ProviderEdge: "edge.provider.example", Addresses: []string{"203.0.113.30", "2001:db8::30"},
		Managed: true, Overlay: true, OverlayStatus: "applied", Status: "ok", ServiceState: "running",
		Chain: LineCatalogueChain{Role: LineChainRoleEntry, Root: true, DownstreamLineUUID: catalogueLineB, PathState: LinePathConverged,
			ExitGeo: &NodeGeo{Country: "US", City: "Los Angeles", Source: "probe", UpdatedAt: catalogueTestTime(t, "2026-10-07T12:00:00Z")}},
		Probe: &LineCatalogueProbe{Verdict: LineProbeVerdictPass, At: catalogueTestTime(t, "2026-10-08T01:00:00Z"), Vantage: "control-plane",
			ConsecutiveFailures: 0, ColdP50MS: 230, UDPOK: &udp},
		Usage: &LineCatalogueUsage{IdentityID: "vu_7", UsedBytes: 1 << 30, From: catalogueTestTime(t, "2026-10-01T00:00:00Z"), To: catalogueTestTime(t, "2026-11-01T00:00:00Z")},
		Template: &LineCatalogueTemplate{Protocol: "vless", Host: "203.0.113.30", Port: 443,
			Params: map[string]string{"security": "reality", "type": "tcp", "sni": "www.example.com", "pbk": "Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5", "sid": "6ba85179e30d4fc2", "fp": "chrome"},
			Digest: "sha256:4b2a91d5e8c3f07a6e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f"},
		Extra: map[string]json.RawMessage{"ip_quality": json.RawMessage(`"high"`)},
	}
}

// The row is the contract the catalogue lane serves and the plugin reads.
// These are its wire names, frozen.
func TestLineCatalogueRowWireNames(t *testing.T) {
	want := `{"line_uuid":"` + catalogueLineA + `","line_hash_id":"lh_5f0c2a9e41d7b3c8","node_id":"node-tokyo-03","node_name":"Tokyo 03 (IIJ)",` +
		`"name":"vless-reality-443","node_tags":["premium","asia"],"group_ids":["grp_asia"],` +
		`"geo":{"country":"JP","region":"Tokyo","city":"Tokyo","asn":2497,"as_org":"IIJ","provider":"IIJ","source":"operator","updated_at":"2026-10-01T00:00:00Z"},` +
		`"machine":{"vendor":"IIJ","region":"ap-northeast-1","next_renewal":"2026-11-15T00:00:00Z"},` +
		`"ddns_names":[{"name":"tyo3.example.net","verified":true},{"name":"tyo3-v6.example.net"}],` +
		`"protocol":"vless","transport":"tcp","security":"reality","public_host":"203.0.113.30","public_port":443,` +
		`"provider_edge":"edge.provider.example","addresses":["203.0.113.30","2001:db8::30"],` +
		`"managed":true,"overlay":true,"overlay_status":"applied","status":"ok","service_state":"running",` +
		`"chain":{"role":"entry","root":true,"downstream_line_uuid":"` + catalogueLineB + `","path_state":"converged",` +
		`"exit_geo":{"country":"US","city":"Los Angeles","source":"probe","updated_at":"2026-10-07T12:00:00Z"}},` +
		`"probe":{"verdict":"pass","at":"2026-10-08T01:00:00Z","vantage":"control-plane","consecutive_failures":0,"cold_p50_ms":230,"udp_ok":true},` +
		`"usage":{"identity_id":"vu_7","used_bytes":1073741824,"from":"2026-10-01T00:00:00Z","to":"2026-11-01T00:00:00Z"},` +
		`"template":{"protocol":"vless","host":"203.0.113.30","port":443,"params":{"fp":"chrome","pbk":"Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5","security":"reality","sid":"6ba85179e30d4fc2","sni":"www.example.com","type":"tcp"},` +
		`"digest":"sha256:4b2a91d5e8c3f07a6e1d2c3b4a5f6e7d8c9b0a1f2e3d4c5b6a7f8e9d0c1b2a3f"},` +
		`"extra":{"ip_quality":"high"}}`
	row := fullCatalogueRow(t)
	if got := mustJSON(t, row); got != want {
		t.Fatalf("row encodes as\n %s\nwant %s", got, want)
	}
	if err := row.Validate(); err != nil {
		t.Fatalf("full row refused: %v", err)
	}
	var back LineCatalogueRow
	if err := json.Unmarshal([]byte(want), &back); err != nil {
		t.Fatal(err)
	}
	if mustJSON(t, back) != want {
		t.Fatal("row did not round-trip")
	}
}

// A line outside any chain, never probed, with no template yet: the chain
// block is still present and the probe block is an explicit null.
func TestLineCatalogueMinimalRowCarriesChainAndNullProbe(t *testing.T) {
	row := LineCatalogueRow{LineUUID: catalogueLineA, LineHashID: "lh_1", NodeID: "n1", Protocol: "trojan", Chain: LineCatalogueChain{Role: LineChainRoleSingle}}
	want := `{"line_uuid":"` + catalogueLineA + `","line_hash_id":"lh_1","node_id":"n1","protocol":"trojan","chain":{"role":"single"},"probe":null}`
	if got := mustJSON(t, row); got != want {
		t.Fatalf("minimal row encodes as\n %s\nwant %s", got, want)
	}
	if err := row.Validate(); err != nil {
		t.Fatalf("minimal row refused: %v", err)
	}
	if err := (LineCatalogueRow{LineUUID: catalogueLineA, LineHashID: "lh_1", NodeID: "n1", Protocol: "trojan"}).Validate(); err == nil {
		t.Fatal("row without a chain role accepted")
	}
}

func TestLineCatalogueRowRefusesBrokenIdentityAndEnums(t *testing.T) {
	cases := map[string]func(*LineCatalogueRow){
		"uppercase uuid":     func(r *LineCatalogueRow) { r.LineUUID = strings.ToUpper(catalogueLineA) },
		"uuid v1":            func(r *LineCatalogueRow) { r.LineUUID = "3f2b8c1e-7d4a-1e5f-9a6b-1c2d3e4f5a6b" },
		"no hash":            func(r *LineCatalogueRow) { r.LineHashID = "" },
		"no node":            func(r *LineCatalogueRow) { r.NodeID = "" },
		"no protocol":        func(r *LineCatalogueRow) { r.Protocol = "" },
		"control in status":  func(r *LineCatalogueRow) { r.Status = "ok\n" },
		"public port":        func(r *LineCatalogueRow) { r.PublicPort = 65536 },
		"address not ip":     func(r *LineCatalogueRow) { r.Addresses = []string{"tyo3.example.net"} },
		"address not canon":  func(r *LineCatalogueRow) { r.Addresses = []string{"2001:DB8::30"} },
		"ddns ip":            func(r *LineCatalogueRow) { r.DDNSNames = []LineCatalogueDDNSName{{Name: "203.0.113.30"}} },
		"ddns uppercase":     func(r *LineCatalogueRow) { r.DDNSNames = []LineCatalogueDDNSName{{Name: "TYO3.example.net"}} },
		"ddns shorthand ip":  func(r *LineCatalogueRow) { r.DDNSNames = []LineCatalogueDDNSName{{Name: "127.1"}} },
		"chain role":         func(r *LineCatalogueRow) { r.Chain.Role = "middle" },
		"path state":         func(r *LineCatalogueRow) { r.Chain.PathState = "stuck" },
		"downstream":         func(r *LineCatalogueRow) { r.Chain.DownstreamLineUUID = "line-b" },
		"probe verdict":      func(r *LineCatalogueRow) { r.Probe.Verdict = "unknown" },
		"probe counter":      func(r *LineCatalogueRow) { r.Probe.ConsecutiveFailures = -1 },
		"usage identity":     func(r *LineCatalogueRow) { r.Usage.IdentityID = "" },
		"usage bytes":        func(r *LineCatalogueRow) { r.Usage.UsedBytes = -1 },
		"empty tag":          func(r *LineCatalogueRow) { r.NodeTags = []string{""} },
		"overlong node name": func(r *LineCatalogueRow) { r.NodeName = strings.Repeat("n", MaxSubscriptionURIBytes+1) },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			row := fullCatalogueRow(t)
			edit(&row)
			if err := row.Validate(); err == nil {
				t.Fatal("broken row accepted")
			}
		})
	}
}

// The literal sets below are what the SDK's template guard is. They are
// written out here, not read from the maps under test, so dropping a member
// from either map fails this test instead of passing unnoticed.
var (
	pinnedReservedParams = []string{"add", "flow", "id", "port", "ps", "v"}
	pinnedTemplateParams = []string{
		"aid", "allowInsecure", "alpn", "congestion_control", "encryption", "fp", "headerType", "host", "insecure", "mode",
		"net", "path", "pbk", "pinSHA256", "security", "serviceName", "sid", "sni", "spx", "tls", "type",
	}
)

func sortedNames(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for name, member := range set {
		if member {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func TestLineTemplateParamSetsArePinned(t *testing.T) {
	for name, c := range map[string]struct {
		got  map[string]bool
		want []string
	}{"reserved": {LineTemplateReservedParams, pinnedReservedParams}, "allowed": {lineTemplateParams, pinnedTemplateParams}} {
		want := append([]string(nil), c.want...)
		sort.Strings(want)
		if got := sortedNames(c.got); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s template params = %v, want %v", name, got, want)
		}
	}
	for _, name := range pinnedReservedParams {
		if lineTemplateParams[name] {
			t.Fatalf("reserved param %q is also on the allowlist", name)
		}
	}
}

// The template is the credential-free surface: the parameters a client
// entry takes from an identity's credential, every parameter the core's
// builder does not keep (the names other protocols hold a secret under
// among them), and anything that looks like a sealed secret, a key or a URL
// are refused, as are templates past the core store's own bounds.
func TestLineCatalogueTemplateStaysCredentialFree(t *testing.T) {
	for _, key := range pinnedReservedParams {
		row := fullCatalogueRow(t)
		row.Template.Params[key] = "x"
		if err := row.Validate(); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("reserved param %q: err = %v", key, err)
		}
	}
	for _, key := range []string{
		"password", "auth", "auth_str", "auth-str", "uuid", "psk", "obfs-password", "obfs", "private-key", "privateKey",
		"pre-shared-key", "token", "username", "Security", "foo",
	} {
		row := fullCatalogueRow(t)
		row.Template.Params[key] = "x"
		if err := row.Validate(); err == nil || !strings.Contains(err.Error(), "not a connection parameter") {
			t.Fatalf("param %q outside the allowlist: err = %v", key, err)
		}
	}
	for _, key := range pinnedTemplateParams {
		row := fullCatalogueRow(t)
		row.Template.Params[key] = "x"
		if err := row.Validate(); err != nil {
			t.Fatalf("allowlisted param %q refused: %v", key, err)
		}
	}
	for name, value := range map[string]string{
		"sealed": "lat$v1$abc", "private key": "-----BEGIN PRIVATE KEY-----", "url": "vless://uuid@host:443",
	} {
		row := fullCatalogueRow(t)
		row.Template.Params["path"] = value
		if err := row.Validate(); err == nil {
			t.Fatalf("%s param value accepted", name)
		}
	}
	// The allowlist is smaller than the store's count bound, so a template
	// can carry every allowlisted param at once; the count bound still
	// refuses a larger map before any key is read.
	if len(pinnedTemplateParams) > MaxLineTemplateParams {
		t.Fatalf("%d allowlisted params exceed the %d-param bound", len(pinnedTemplateParams), MaxLineTemplateParams)
	}
	every := make(map[string]string, len(pinnedTemplateParams))
	for _, key := range pinnedTemplateParams {
		every[key] = "v"
	}
	over := make(map[string]string, MaxLineTemplateParams+1)
	for i := 0; i <= MaxLineTemplateParams; i++ {
		over[fmt.Sprintf("p%02d", i)] = "v"
	}
	{
		row := fullCatalogueRow(t)
		row.Template.Params = over
		if err := row.Validate(); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("more than %d params", MaxLineTemplateParams)) {
			t.Fatalf("params over bound: err = %v", err)
		}
	}
	edges := []struct {
		name     string
		edit     func(*LineCatalogueTemplate)
		accepted bool
	}{
		{"every allowlisted param", func(t *LineCatalogueTemplate) { t.Params = every }, true},
		{"value at bound", func(t *LineCatalogueTemplate) { t.Params["path"] = strings.Repeat("v", MaxLineTemplateValueBytes) }, true},
		{"value over bound", func(t *LineCatalogueTemplate) { t.Params["path"] = strings.Repeat("v", MaxLineTemplateValueBytes+1) }, false},
		{"dropped at bound", func(t *LineCatalogueTemplate) {
			t.Dropped = strings.Fields(strings.Repeat("obfs ", MaxLineTemplateDropped))
		}, true},
		{"dropped over bound", func(t *LineCatalogueTemplate) {
			t.Dropped = strings.Fields(strings.Repeat("obfs ", MaxLineTemplateDropped+1))
		}, false},
		{"port zero", func(t *LineCatalogueTemplate) { t.Port = 0 }, false},
		{"host with userinfo", func(t *LineCatalogueTemplate) { t.Host = "user@203.0.113.30" }, false},
		{"bracketed host", func(t *LineCatalogueTemplate) { t.Host = "[2001:db8::30]" }, false},
		{"host at 253", func(t *LineCatalogueTemplate) { t.Host = strings.Repeat("h", 253) }, true},
		{"host over 253", func(t *LineCatalogueTemplate) { t.Host = strings.Repeat("h", 254) }, false},
		{"no digest", func(t *LineCatalogueTemplate) { t.Digest = "" }, false},
	}
	for _, e := range edges {
		row := fullCatalogueRow(t)
		e.edit(row.Template)
		if err := row.Validate(); (err == nil) != e.accepted {
			t.Fatalf("%s: Validate() = %v, want accepted=%v", e.name, err, e.accepted)
		}
	}
}

// Extra is the row's open channel, so it is bounded and screened like a
// template: lowercase field names, no credential name at any depth, no
// string that looks like a sealed secret, a private key or a URL, and no
// duplicate key that would hide a value from the screen.
func TestLineCatalogueRowExtraIsBoundedAndScreened(t *testing.T) {
	withExtra := func(extra map[string]json.RawMessage) error {
		row := fullCatalogueRow(t)
		row.Extra = extra
		return row.Validate()
	}
	accepted := map[string]map[string]json.RawMessage{
		"scalar":        {"ip_quality": json.RawMessage(`"high"`)},
		"nested object": {"ip_quality": json.RawMessage(`{"score":0.9,"source":"probe","asns":[2497,"IIJ"]}`)},
		"null":          {"retired_at": json.RawMessage(`null`)},
	}
	for name, extra := range accepted {
		if err := withExtra(extra); err != nil {
			t.Fatalf("%s extra refused: %v", name, err)
		}
	}
	refused := map[string]map[string]json.RawMessage{
		"uppercase key":           {"IPQuality": json.RawMessage(`1`)},
		"hyphenated key":          {"ip-quality": json.RawMessage(`1`)},
		"empty key":               {"": json.RawMessage(`1`)},
		"digit first":             {"1x": json.RawMessage(`1`)},
		"credential key":          {"password": json.RawMessage(`"x"`)},
		"uuid key":                {"uuid": json.RawMessage(`"x"`)},
		"key with a token stem":   {"api_token": json.RawMessage(`"x"`)},
		"nested private key name": {"meta": json.RawMessage(`{"privateKey":"x"}`)},
		"credential in an array":  {"list": json.RawMessage(`[{"obfs-password":"x"}]`)},
		"nested vmess id":         {"meta": json.RawMessage(`{"vmess":{"id":"x"}}`)},
		"url string":              {"note": json.RawMessage(`"see https://x.example"`)},
		"escaped url string":      {"note": json.RawMessage(`"vless\u003a//x"`)},
		"sealed in an array":      {"a": json.RawMessage(`["ok","lat$1$abc"]`)},
		"private key text":        {"pem": json.RawMessage(`"-----BEGIN PRIVATE KEY-----"`)},
		"duplicate hides a value": {"a": json.RawMessage(`{"b":"lat$1$abc","b":"ok"}`)},
		"invalid json":            {"a": json.RawMessage(`{"b":`)},
	}
	for name, extra := range refused {
		if err := withExtra(extra); err == nil {
			t.Fatalf("%s extra accepted", name)
		}
	}
	sized := func(total int) map[string]json.RawMessage {
		key := "padding"
		return map[string]json.RawMessage{key: json.RawMessage(`"` + strings.Repeat("p", total-len(key)-2) + `"`)}
	}
	if err := withExtra(sized(MaxLineCatalogueExtraBytes)); err != nil {
		t.Fatalf("extra at %d bytes refused: %v", MaxLineCatalogueExtraBytes, err)
	}
	if err := withExtra(sized(MaxLineCatalogueExtraBytes + 1)); err == nil {
		t.Fatal("extra one byte over the bound accepted")
	}
}

// padRowTo grows a row's node tags until the row encodes to exactly size
// bytes.
func padRowTo(t *testing.T, row LineCatalogueRow, size int) LineCatalogueRow {
	t.Helper()
	row.NodeTags = append([]string(nil), row.NodeTags...)
	for {
		gap := size - len(mustJSON(t, row))
		switch {
		case gap == 0:
			return row
		case gap < 0:
			t.Fatalf("row already encodes past %d bytes", size)
		case gap > MaxSubscriptionURIBytes+3:
			row.NodeTags = append(row.NodeTags, strings.Repeat("t", MaxSubscriptionURIBytes))
		case gap >= 4:
			// A new tag costs its length plus two quotes and a comma.
			row.NodeTags = append(row.NodeTags, strings.Repeat("t", gap-3))
		default:
			row.NodeTags[0] += strings.Repeat("t", gap)
		}
	}
}

func TestLineCatalogueRowEncodedSizeBound(t *testing.T) {
	at := padRowTo(t, fullCatalogueRow(t), MaxLineCatalogueRowBytes)
	if err := at.Validate(); err != nil {
		t.Fatalf("row at %d bytes refused: %v", MaxLineCatalogueRowBytes, err)
	}
	over := padRowTo(t, fullCatalogueRow(t), MaxLineCatalogueRowBytes+1)
	if err := over.Validate(); err == nil {
		t.Fatal("row one byte over the bound accepted")
	}
}

func TestLineCatalogueSelectorFieldNames(t *testing.T) {
	want := []string{
		"chain_roles", "countries", "group_ids", "line_uuids", "node_tags", "probe_passed_within_hours",
		"protocols", "regions", "renewal_within_days", "service_states", "transports",
	}
	if got := LineCatalogueSelectorFields(); !reflect.DeepEqual(got, want) {
		t.Fatalf("selector fields = %v, want %v", got, want)
	}
	days := 30
	s := LineCatalogueSelector{Countries: []string{"JP"}, Protocols: []string{}, RenewalWithinDays: &days}
	if got := s.Fields(); !reflect.DeepEqual(got, []string{"countries", "renewal_within_days"}) {
		t.Fatalf("set fields = %v", got)
	}
	if got := s.UnsupportedFields([]string{"countries", "protocols"}); !reflect.DeepEqual(got, []string{"renewal_within_days"}) {
		t.Fatalf("unsupported fields = %v", got)
	}
	if got := s.UnsupportedFields(LineCatalogueSelectorFields()); got != nil {
		t.Fatalf("a core advertising every field leaves %v unsupported", got)
	}
	if got := (LineCatalogueSelector{}).Fields(); got != nil {
		t.Fatalf("empty selector sets %v", got)
	}
}

func TestLineCatalogueSelectorBounds(t *testing.T) {
	uuids := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("00000000-0000-4000-8000-%012x", i)
		}
		return out
	}
	values := func(n int) []string { return strings.Fields(strings.Repeat("v ", n)) }
	ptr := func(n int) *int { return &n }
	cases := []struct {
		name     string
		s        LineCatalogueSelector
		accepted bool
	}{
		{"line uuids at bound", LineCatalogueSelector{LineUUIDs: uuids(MaxSubscriptionRecordNodes)}, true},
		{"line uuids over bound", LineCatalogueSelector{LineUUIDs: uuids(MaxSubscriptionRecordNodes + 1)}, false},
		{"duplicate line", LineCatalogueSelector{LineUUIDs: []string{catalogueLineA, catalogueLineA}}, false},
		{"bad line", LineCatalogueSelector{LineUUIDs: []string{"line-a"}}, false},
		{"values at bound", LineCatalogueSelector{NodeTags: values(MaxLineCatalogueSelectorValues)}, true},
		{"values over bound", LineCatalogueSelector{NodeTags: values(MaxLineCatalogueSelectorValues + 1)}, false},
		{"empty value", LineCatalogueSelector{Countries: []string{""}}, false},
		{"unknown role", LineCatalogueSelector{ChainRoles: []string{"middle"}}, false},
		{"known role", LineCatalogueSelector{ChainRoles: []string{LineChainRoleExit}}, true},
		{"renewal zero", LineCatalogueSelector{RenewalWithinDays: ptr(0)}, true},
		{"renewal at bound", LineCatalogueSelector{RenewalWithinDays: ptr(MaxLineCatalogueRenewalDays)}, true},
		{"renewal over bound", LineCatalogueSelector{RenewalWithinDays: ptr(MaxLineCatalogueRenewalDays + 1)}, false},
		{"renewal negative", LineCatalogueSelector{RenewalWithinDays: ptr(-1)}, false},
		{"probe at one", LineCatalogueSelector{ProbePassedWithinHours: ptr(1)}, true},
		{"probe zero", LineCatalogueSelector{ProbePassedWithinHours: ptr(0)}, false},
		{"probe at bound", LineCatalogueSelector{ProbePassedWithinHours: ptr(MaxLineCatalogueProbeHours)}, true},
		{"probe over bound", LineCatalogueSelector{ProbePassedWithinHours: ptr(MaxLineCatalogueProbeHours + 1)}, false},
	}
	for _, c := range cases {
		if err := c.s.Validate(); (err == nil) != c.accepted {
			t.Fatalf("%s: Validate() = %v, want accepted=%v", c.name, err, c.accepted)
		}
	}
}

// The catalogue refuses a selector field it does not know. A strict decode
// is how: an unknown key, a duplicate key or trailing data is an error.
func TestDecodeLineCatalogueRequestIsStrict(t *testing.T) {
	good := `{"identity_id":"vu_7","selector":{"line_uuids":["` + catalogueLineB + `","` + catalogueLineA + `"],"countries":["JP"]},"cursor":"c2","limit":1000}`
	req, err := DecodeLineCatalogueRequest([]byte(good))
	if err != nil {
		t.Fatalf("valid request refused: %v", err)
	}
	if req.Selector == nil || !reflect.DeepEqual(req.Selector.LineUUIDs, []string{catalogueLineB, catalogueLineA}) || req.Limit != 1000 {
		t.Fatalf("request decoded as %+v", req)
	}
	if mustJSON(t, req) != good {
		t.Fatalf("request re-encodes as %s", mustJSON(t, req))
	}
	for name, raw := range map[string]string{
		"unknown selector field": `{"selector":{"cities":["Tokyo"]}}`,
		"unknown top field":      `{"identity":"vu_7"}`,
		"duplicate key":          `{"limit":1,"limit":2}`,
		"trailing data":          `{"limit":1} {}`,
		"limit over page":        `{"limit":1001}`,
		"negative limit":         `{"limit":-1}`,
		"empty":                  ``,
		"cursor too long":        `{"cursor":"` + strings.Repeat("c", MaxLineCatalogueTokenBytes+1) + `"}`,
	} {
		if _, err := DecodeLineCatalogueRequest([]byte(raw)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	padded := func(n int) []byte {
		prefix, suffix := `{"cursor":"x"`, `}`
		return []byte(prefix + strings.Repeat(" ", n-len(prefix)-len(suffix)) + suffix)
	}
	if _, err := DecodeLineCatalogueRequest(padded(MaxLineCatalogueRequestBytes)); err != nil {
		t.Fatalf("request at the size bound refused: %v", err)
	}
	if _, err := DecodeLineCatalogueRequest(padded(MaxLineCatalogueRequestBytes + 1)); err == nil {
		t.Fatal("request one byte over the size bound accepted")
	}
}

func TestLineCatalogueResponsePageBounds(t *testing.T) {
	page := func(n int) LineCatalogueResponse {
		resp := LineCatalogueResponse{CatalogueVersion: "cv1:9f2c", Cursor: "next", SelectorFields: LineCatalogueSelectorFields()}
		for i := 0; i < n; i++ {
			row := fullCatalogueRow(t)
			row.LineUUID = fmt.Sprintf("00000000-0000-4000-8000-%012x", i)
			resp.Rows = append(resp.Rows, row)
		}
		return resp
	}
	// A full page of realistic rows is well inside the byte bound.
	full := page(MaxLineCataloguePageRows)
	if err := full.Validate(); err != nil {
		t.Fatalf("full page refused: %v", err)
	}
	if err := page(MaxLineCataloguePageRows + 1).Validate(); err == nil {
		t.Fatal("page one row over the bound accepted")
	}
	dup := page(2)
	dup.Rows[1].LineUUID = dup.Rows[0].LineUUID
	if err := dup.Validate(); err == nil {
		t.Fatal("page listing a line twice accepted")
	}
	noVersion := page(1)
	noVersion.CatalogueVersion = ""
	if err := noVersion.Validate(); err == nil {
		t.Fatal("page without a catalogue_version accepted")
	}
	if want := `{"catalogue_version":"cv1:9f2c","rows":[]}`; mustJSON(t, LineCatalogueResponse{CatalogueVersion: "cv1:9f2c", Rows: []LineCatalogueRow{}}) != want {
		t.Fatalf("last empty page encodes as %s", mustJSON(t, LineCatalogueResponse{CatalogueVersion: "cv1:9f2c", Rows: []LineCatalogueRow{}}))
	}
}

// The byte bound is what keeps a page inside the host-call result: a page of
// dense rows under the row-count bound is refused by Validate, not by the
// host boundary. Validate sums the rows it already encoded, so this also
// checks that sum against the real encoding, byte for byte.
func TestLineCatalogueResponsePageByteBound(t *testing.T) {
	if MaxLineCataloguePageBytes >= plugin.DefaultMaxHostResponsePayloadBytes {
		t.Fatalf("page bound %d is not inside the %d host result cap", MaxLineCataloguePageBytes, plugin.DefaultMaxHostResponsePayloadBytes)
	}
	if MaxLineCatalogueRowBytes > MaxLineCataloguePageBytes {
		t.Fatal("a row at its bound would not fit a page")
	}
	build := func(rows []LineCatalogueRow) LineCatalogueResponse {
		return LineCatalogueResponse{CatalogueVersion: "cv1:9f2c", Cursor: "next", SelectorFields: LineCatalogueSelectorFields(), Rows: rows}
	}
	withUUIDs := func(template LineCatalogueRow, n int) []LineCatalogueRow {
		rows := make([]LineCatalogueRow, n)
		for i := range rows {
			rows[i] = template
			rows[i].LineUUID = fmt.Sprintf("00000000-0000-4000-8000-%012x", i)
		}
		return rows
	}

	// 1000 rows of about 4.2 KB each: inside the row-count bound, past the
	// byte bound.
	dense := build(withUUIDs(padRowTo(t, fullCatalogueRow(t), 4200), MaxLineCataloguePageRows))
	if size := len(mustJSON(t, dense)); size <= MaxLineCataloguePageBytes {
		t.Fatalf("dense fixture is only %d bytes", size)
	}
	if err := dense.Validate(); err == nil || !strings.Contains(err.Error(), "encodes to") {
		t.Fatalf("dense page past the byte bound: err = %v", err)
	}

	// 70 rows that fill the page to exactly the bound, then one byte more.
	const n = 70
	head := len(mustJSON(t, build([]LineCatalogueRow{})))
	each := (MaxLineCataloguePageBytes - head) / n
	last := MaxLineCataloguePageBytes - head - (n - 1) - (n-1)*each
	rows := withUUIDs(padRowTo(t, fullCatalogueRow(t), each), n)
	lastRow := func(size int) LineCatalogueRow {
		row := fullCatalogueRow(t)
		row.LineUUID = rows[n-1].LineUUID
		return padRowTo(t, row, size)
	}
	rows[n-1] = lastRow(last)
	exact := build(rows)
	if size := len(mustJSON(t, exact)); size != MaxLineCataloguePageBytes {
		t.Fatalf("fixture encodes to %d bytes, want %d", size, MaxLineCataloguePageBytes)
	}
	if err := exact.Validate(); err != nil {
		t.Fatalf("page at the byte bound refused: %v", err)
	}
	rows[n-1] = lastRow(last + 1)
	if err := build(rows).Validate(); err == nil {
		t.Fatal("page one byte over the byte bound accepted")
	}
}
