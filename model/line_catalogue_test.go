package model

import (
	"encoding/json"
	"fmt"
	"reflect"
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

// The template is the credential-free surface: the parameters a client
// entry takes from an identity's credential, and anything that looks like a
// sealed secret, a key or a URL, are refused, as are templates past the
// core store's own bounds.
func TestLineCatalogueTemplateStaysCredentialFree(t *testing.T) {
	for key := range LineTemplateReservedParams {
		row := fullCatalogueRow(t)
		row.Template.Params[key] = "x"
		if err := row.Validate(); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatalf("reserved param %q: err = %v", key, err)
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
	params := func(n int) map[string]string {
		out := make(map[string]string, n)
		for i := 0; i < n; i++ {
			out[fmt.Sprintf("p%02d", i)] = "v"
		}
		return out
	}
	edges := []struct {
		name     string
		edit     func(*LineCatalogueTemplate)
		accepted bool
	}{
		{"params at bound", func(t *LineCatalogueTemplate) { t.Params = params(MaxLineTemplateParams) }, true},
		{"params over bound", func(t *LineCatalogueTemplate) { t.Params = params(MaxLineTemplateParams + 1) }, false},
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
	full := page(MaxLineCataloguePageRows)
	if err := full.Validate(); err != nil {
		t.Fatalf("full page refused: %v", err)
	}
	// A page of dense rows must fit the host-call result a plugin receives.
	if size := len(mustJSON(t, full)); size > plugin.DefaultMaxHostResponsePayloadBytes {
		t.Fatalf("a full page of dense rows is %d bytes, over the %d host result cap", size, plugin.DefaultMaxHostResponsePayloadBytes)
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
