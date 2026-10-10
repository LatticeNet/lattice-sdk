package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The matcher moved here from the core (lattice-server
// internal/server/line_catalogue.go, lineCatalogueMatches). Each case below
// is one rule of the pushdown contract the core's comment stated and its
// selector tests exercised, so the moved function is the core's matcher,
// plus the one rule S2 adds: an unresolved relay's geo is unknown.
func TestSelectorMatchesIsTheServerMatcher(t *testing.T) {
	now := catalogueTestTime(t, "2026-10-10T12:00:00Z")
	days := func(n int) *int { return &n }
	base := func() LineCatalogueRow {
		return LineCatalogueRow{
			LineUUID: catalogueLineA, LineHashID: "lh_1", NodeID: "node-000", Protocol: "vless", Transport: "ws",
			ServiceState: "running", NodeTags: []string{"tier-1", "asia"}, GroupIDs: []string{"grp_a"},
			Geo:   &NodeGeo{Country: "DE", Region: "Hesse"},
			Chain: LineCatalogueChain{Role: LineChainRoleSingle},
		}
	}
	type tc struct {
		name string
		row  func(*LineCatalogueRow)
		sel  LineCatalogueSelector
		want bool
	}
	cases := []tc{
		{"empty selector matches", nil, LineCatalogueSelector{}, true},
		{"country folds case", nil, LineCatalogueSelector{Countries: []string{"de"}}, true},
		{"country is one of the list", nil, LineCatalogueSelector{Countries: []string{"JP", "DE"}}, true},
		{"country differs", nil, LineCatalogueSelector{Countries: []string{"JP"}}, false},
		{"region folds case", nil, LineCatalogueSelector{Regions: []string{"hesse"}}, true},
		{"no geo never matches a country", func(r *LineCatalogueRow) { r.Geo = nil }, LineCatalogueSelector{Countries: []string{"DE"}}, false},
		{"empty row country never matches", func(r *LineCatalogueRow) { r.Geo = &NodeGeo{Region: "Hesse"} }, LineCatalogueSelector{Countries: []string{""}}, false},
		{"exit geo wins over the node's", func(r *LineCatalogueRow) {
			r.Chain = LineCatalogueChain{Role: LineChainRoleEntry, ExitGeo: &NodeGeo{Country: "JP"}}
		}, LineCatalogueSelector{Countries: []string{"JP"}}, true},
		{"exit geo hides the node's country", func(r *LineCatalogueRow) {
			r.Chain = LineCatalogueChain{Role: LineChainRoleEntry, ExitGeo: &NodeGeo{Country: "JP"}}
		}, LineCatalogueSelector{Countries: []string{"DE"}}, false},
		{"a field the exit geo lacks does not fall back", func(r *LineCatalogueRow) {
			r.Chain = LineCatalogueChain{Role: LineChainRoleEntry, ExitGeo: &NodeGeo{Country: "JP"}}
		}, LineCatalogueSelector{Regions: []string{"Hesse"}}, false},
		{"unresolved relay never matches a country", func(r *LineCatalogueRow) {
			r.Chain = LineCatalogueChain{Role: LineChainRoleRelay, Unresolved: true}
		}, LineCatalogueSelector{Countries: []string{"DE"}}, false},
		{"unresolved relay never matches a region", func(r *LineCatalogueRow) {
			r.Chain = LineCatalogueChain{Role: LineChainRoleRelay, Unresolved: true}
		}, LineCatalogueSelector{Regions: []string{"Hesse"}}, false},
		{"unresolved relay ignores an exit geo too", func(r *LineCatalogueRow) {
			r.Chain = LineCatalogueChain{Role: LineChainRoleRelay, Unresolved: true, ExitGeo: &NodeGeo{Country: "JP"}}
		}, LineCatalogueSelector{Countries: []string{"JP"}}, false},
		{"unresolved relay still matches its other fields", func(r *LineCatalogueRow) {
			r.Chain = LineCatalogueChain{Role: LineChainRoleRelay, Unresolved: true}
		}, LineCatalogueSelector{Protocols: []string{"vless"}, ChainRoles: []string{"relay"}}, true},
		{"protocol folds case", nil, LineCatalogueSelector{Protocols: []string{"VLESS"}}, true},
		{"protocol differs", nil, LineCatalogueSelector{Protocols: []string{"trojan"}}, false},
		{"transport folds case", nil, LineCatalogueSelector{Transports: []string{"WS"}}, true},
		{"empty transport never matches", func(r *LineCatalogueRow) { r.Transport = "" }, LineCatalogueSelector{Transports: []string{"tcp"}}, false},
		{"service state folds case", nil, LineCatalogueSelector{ServiceStates: []string{"Running", "down"}}, true},
		{"service state differs", nil, LineCatalogueSelector{ServiceStates: []string{"down"}}, false},
		{"chain role is exact", nil, LineCatalogueSelector{ChainRoles: []string{"single"}}, true},
		{"chain role does not fold", nil, LineCatalogueSelector{ChainRoles: []string{"Single"}}, false},
		{"node tag any of", nil, LineCatalogueSelector{NodeTags: []string{"eu", "asia"}}, true},
		{"node tag is exact", nil, LineCatalogueSelector{NodeTags: []string{"Tier-1"}}, false},
		{"group any of", nil, LineCatalogueSelector{GroupIDs: []string{"grp_a"}}, true},
		{"group differs", nil, LineCatalogueSelector{GroupIDs: []string{"grp_b"}}, false},
		{"fields combine with AND", nil, LineCatalogueSelector{Countries: []string{"DE"}, NodeTags: []string{"eu"}}, false},
		{"renewal inside the window", func(r *LineCatalogueRow) {
			r.Machine = &LineCatalogueMachine{NextRenewal: now.Add(3 * 24 * time.Hour)}
		}, LineCatalogueSelector{RenewalWithinDays: days(7)}, true},
		{"renewal at the window's edge", func(r *LineCatalogueRow) {
			r.Machine = &LineCatalogueMachine{NextRenewal: now.Add(7 * 24 * time.Hour)}
		}, LineCatalogueSelector{RenewalWithinDays: days(7)}, true},
		{"renewal past the window", func(r *LineCatalogueRow) {
			r.Machine = &LineCatalogueMachine{NextRenewal: now.Add(40 * 24 * time.Hour)}
		}, LineCatalogueSelector{RenewalWithinDays: days(7)}, false},
		{"a renewal already past matches", func(r *LineCatalogueRow) {
			r.Machine = &LineCatalogueMachine{NextRenewal: now.Add(-24 * time.Hour)}
		}, LineCatalogueSelector{RenewalWithinDays: days(0)}, true},
		{"unknown renewal never matches", func(r *LineCatalogueRow) { r.Machine = &LineCatalogueMachine{Vendor: "x"} },
			LineCatalogueSelector{RenewalWithinDays: days(3660)}, false},
		{"no machine never matches renewal", nil, LineCatalogueSelector{RenewalWithinDays: days(3660)}, false},
		{"a null probe block never matches", nil, LineCatalogueSelector{ProbePassedWithinHours: days(24)}, false},
		{"a pass inside the window", func(r *LineCatalogueRow) {
			r.Probe = &LineCatalogueProbe{Verdict: LineProbeVerdictPass, At: now.Add(-2 * time.Hour)}
		}, LineCatalogueSelector{ProbePassedWithinHours: days(24)}, true},
		{"a pass at the window's edge", func(r *LineCatalogueRow) {
			r.Probe = &LineCatalogueProbe{Verdict: LineProbeVerdictPass, At: now.Add(-24 * time.Hour)}
		}, LineCatalogueSelector{ProbePassedWithinHours: days(24)}, true},
		{"a pass before the window", func(r *LineCatalogueRow) {
			r.Probe = &LineCatalogueProbe{Verdict: LineProbeVerdictPass, At: now.Add(-25 * time.Hour)}
		}, LineCatalogueSelector{ProbePassedWithinHours: days(24)}, false},
		{"a recent fail never matches", func(r *LineCatalogueRow) {
			r.Probe = &LineCatalogueProbe{Verdict: LineProbeVerdictFail, At: now, ConsecutiveFailures: 1}
		}, LineCatalogueSelector{ProbePassedWithinHours: days(24)}, false},
		{"the line list is the caller's", nil, LineCatalogueSelector{LineUUIDs: []string{catalogueLineB}}, true},
	}
	for _, c := range cases {
		row := base()
		if c.row != nil {
			c.row(&row)
		}
		sel := c.sel
		if got := LineCatalogueSelectorMatches(&row, &sel, now); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	row := base()
	if !LineCatalogueSelectorMatches(&row, nil, now) {
		t.Fatal("a nil selector must match every row")
	}
}

// The S2 row fields: their wire names, their validation, and the response's
// unavailable list.
func TestLineCatalogueS2FieldsWireAndValidate(t *testing.T) {
	row := fullCatalogueRow(t)
	row.Label = "Tokyo 03 (IIJ) vless-reality-443"
	row.DDNSNames = []LineCatalogueDDNSName{{Name: "tyo3.example.net", Verified: true, Target: "edge.provider.example"}}
	row.Chain.Unresolved = true
	row.Chain.PathServiceState = LineServiceStateRestarting
	raw := mustJSON(t, row)
	for _, want := range []string{
		`"name":"vless-reality-443","label":"Tokyo 03 (IIJ) vless-reality-443",`,
		`"ddns_names":[{"name":"tyo3.example.net","verified":true,"target":"edge.provider.example"}]`,
		`"unresolved":true,"path_service_state":"restarting"}`,
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("row lacks %s:\n%s", want, raw)
		}
	}
	if err := row.Validate(); err != nil {
		t.Fatalf("row with S2 fields refused: %v", err)
	}
	for name, mutate := range map[string]func(*LineCatalogueRow){
		"path service state outside the set": func(r *LineCatalogueRow) { r.Chain.PathServiceState = "stopped" },
		"ddns target with a path":            func(r *LineCatalogueRow) { r.DDNSNames[0].Target = "edge.example/x" },
		"ddns target with spaces":            func(r *LineCatalogueRow) { r.DDNSNames[0].Target = " edge.example" },
		"label over the text bound":          func(r *LineCatalogueRow) { r.Label = strings.Repeat("x", MaxSubscriptionURIBytes+1) },
	} {
		bad := row
		bad.DDNSNames = append([]LineCatalogueDDNSName(nil), row.DDNSNames...)
		mutate(&bad)
		if err := bad.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	page := LineCatalogueResponse{CatalogueVersion: "lcv1-0", Rows: []LineCatalogueRow{row}, Unavailable: []string{LineCatalogueUnavailableProbe}}
	if err := page.Validate(); err != nil {
		t.Fatalf("page with unavailable refused: %v", err)
	}
	encoded, err := json.Marshal(page)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(encoded), `"unavailable":["probe"]}`) {
		t.Fatalf("page encodes as %s", encoded[len(encoded)-60:])
	}
	page.Unavailable = []string{" probe"}
	if err := page.Validate(); err == nil {
		t.Fatal("an unavailable name with spaces accepted")
	}
}
