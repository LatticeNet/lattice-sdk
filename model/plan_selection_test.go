package model

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// A plan carries the selection it was rendered from and the record's bind
// policy, under these wire names, and the strict decoder admits both.
func TestDecodeSelectionPlanAcceptsSelectionAndPolicy(t *testing.T) {
	plan := SelectionPlan{
		Kind:      SelectionPlanKindNodes,
		Nodes:     []SelectionPlanNode{fleetPlanNode(catalogueLineA)},
		Selection: &PlanSelection{CatalogueVersion: "lcv1-0123abcd", LineUUIDs: []string{catalogueLineA, catalogueLineB}},
		Policy: &BindPolicy{
			Probe:    &ProbeExclusionPolicy{ConsecutiveFailures: 3},
			Usage:    &UsageExclusionPolicy{MaxBytesPerLine: 10 << 30},
			DDNSDial: true,
		},
	}
	raw, err := EncodeSelectionPlan(plan)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if !strings.HasSuffix(string(raw), `"selection":{"catalogue_version":"lcv1-0123abcd","line_uuids":["`+catalogueLineA+`","`+catalogueLineB+`"]},`+
		`"policy":{"probe":{"consecutive_failures":3},"usage":{"max_bytes_per_line":10737418240},"ddns_dial":true}}`) {
		t.Fatalf("plan encodes as %s", raw)
	}
	back, err := DecodeSelectionPlan(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if back.Selection == nil || back.Selection.CatalogueVersion != "lcv1-0123abcd" || !slices.Equal(back.Selection.LineUUIDs, plan.Selection.LineUUIDs) {
		t.Fatalf("selection = %+v", back.Selection)
	}
	if back.Policy == nil || back.Policy.Probe.ConsecutiveFailures != 3 || back.Policy.Usage.MaxBytesPerLine != 10<<30 || !back.Policy.DDNSDial {
		t.Fatalf("policy = %+v", back.Policy)
	}

	// An S1 plan, with neither field, decodes as before.
	s1, err := EncodeSelectionPlan(SelectionPlan{Kind: SelectionPlanKindNodes, Nodes: []SelectionPlanNode{fleetPlanNode(catalogueLineA)}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(s1), "selection") || strings.Contains(string(s1), "policy") {
		t.Fatalf("an S1 plan grew fields: %s", s1)
	}
	if back, err := DecodeSelectionPlan(s1); err != nil || back.Selection != nil || back.Policy != nil {
		t.Fatalf("S1 plan: %+v %v", back, err)
	}

	// A zero-row selection is a selection: line_uuids may be empty or null.
	for _, lines := range []string{`[]`, `null`} {
		zero := `{"kind":"nodes","nodes":[],"selection":{"catalogue_version":"lcv1-0","line_uuids":` + lines + `}}`
		if _, err := DecodeSelectionPlan([]byte(zero)); err != nil {
			t.Fatalf("zero-row selection %s refused: %v", lines, err)
		}
	}
}

func TestSelectionPlanRefusesBadSelectionAndPolicy(t *testing.T) {
	node := mustJSON(t, fleetPlanNode(catalogueLineA))
	cases := map[string]string{
		"selection without a version":   `"selection":{"line_uuids":[]}`,
		"selection version with spaces": `"selection":{"catalogue_version":" lcv1-0","line_uuids":[]}`,
		"selection upper-case uuid":     `"selection":{"catalogue_version":"lcv1-0","line_uuids":["` + strings.ToUpper(catalogueLineA) + `"]}`,
		"selection uuid twice":          `"selection":{"catalogue_version":"lcv1-0","line_uuids":["` + catalogueLineA + `","` + catalogueLineA + `"]}`,
		"selection unknown field":       `"selection":{"catalogue_version":"lcv1-0","line_uuids":[],"rows":[]}`,
		"probe failures zero":           `"policy":{"probe":{"consecutive_failures":0}}`,
		"probe failures eleven":         `"policy":{"probe":{"consecutive_failures":11}}`,
		"usage threshold zero":          `"policy":{"usage":{"max_bytes_per_line":0}}`,
		"usage threshold negative":      `"policy":{"usage":{"max_bytes_per_line":-1}}`,
		"policy unknown field":          `"policy":{"ddns_dial":true,"geo":true}`,
	}
	for name, field := range cases {
		raw := `{"kind":"nodes","nodes":[` + node + `],` + field + `}`
		if _, err := DecodeSelectionPlan([]byte(raw)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	tooMany := make([]string, MaxSubscriptionRecordNodes+1)
	for i := range tooMany {
		tooMany[i] = uuidFor(i)
	}
	plan := SelectionPlan{Kind: SelectionPlanKindNodes, Nodes: []SelectionPlanNode{fleetPlanNode(catalogueLineA)},
		Selection: &PlanSelection{CatalogueVersion: "lcv1-0", LineUUIDs: tooMany}}
	if err := plan.Validate(); err == nil {
		t.Fatal("a selection over the node bound accepted")
	}
	plan.Selection.LineUUIDs = tooMany[:MaxSubscriptionRecordNodes]
	if err := plan.Validate(); err != nil {
		t.Fatalf("a selection at the node bound refused: %v", err)
	}
	for n := 1; n <= MaxBindProbeConsecutiveFailures; n++ {
		if err := (BindPolicy{Probe: &ProbeExclusionPolicy{ConsecutiveFailures: n}}).Validate(); err != nil {
			t.Fatalf("probe failures %d refused: %v", n, err)
		}
	}
}

// uuidFor returns a distinct lowercase UUIDv4 for i.
func uuidFor(i int) string {
	const hex = "0123456789abcdef"
	digits := []byte("00000000")
	for j := 7; j >= 0; j-- {
		digits[j] = hex[i&0xf]
		i >>= 4
	}
	return string(digits) + "-0000-4000-8000-000000000000"
}

// The render cap leaves the reply's other fields and the framing half a MiB
// inside the render stdout budget, which is the plan bound.
func TestMaxRenderPlanBytesSitsInsideThePlanBound(t *testing.T) {
	if got := MaxRenderPlanBytes; got != 5767168 {
		t.Fatalf("MaxRenderPlanBytes = %d, want 5.5 MiB", got)
	}
}

// The three field lists are the contract between the plugin's plan encoder,
// convert's strip and the core's carried set; their contents are pinned.
func TestSelectionPlanFieldListsArePinned(t *testing.T) {
	lattice := []string{"line_hash_id", "node_id", "geo", "chain", "tags", "groups", "probe", "addresses"}
	if !slices.Equal(SelectionPlanLatticeFields, lattice) {
		t.Fatalf("lattice fields = %v", SelectionPlanLatticeFields)
	}
	if !slices.Equal(SelectionPlanStrippedFields, append([]string{"line_uuid"}, lattice...)) {
		t.Fatalf("stripped fields = %v", SelectionPlanStrippedFields)
	}
	carried := append([]string{"flow", "packet-encoding", "congestion-controller", "udp-relay-mode", "reduce-rtt", "up", "down",
		"_h2", "_mode", "_grpc-type", "_spider-x", "_pqv", "_v2ray-http-upgrade-ed"}, lattice...)
	if !slices.Equal(SelectionPlanCarriedFields, carried) {
		t.Fatalf("carried fields = %v", SelectionPlanCarriedFields)
	}
	if slices.Contains(SelectionPlanCarriedFields, "line_uuid") || slices.Contains(SelectionPlanLatticeFields, "_lattice") {
		t.Fatal("line_uuid is compared, never carried; _lattice is never a plan key")
	}
}

func TestRenderReplyCarriesLiveRevision(t *testing.T) {
	plan := SelectionPlan{Kind: SelectionPlanKindNodes, Nodes: []SelectionPlanNode{fleetPlanNode(catalogueLineA)}}
	reply := RenderReply{Plan: &plan, LiveRevision: "rev-live"}
	raw, err := json.Marshal(reply)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(raw), `,"live_revision":"rev-live"}`) {
		t.Fatalf("render reply encodes as %s", raw)
	}
	if err := reply.Validate(); err != nil {
		t.Fatal(err)
	}
}
