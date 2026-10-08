package model

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const testPlaceholderRandom = "0123456789abcdef0123456789abcdef"

func testPlaceholder(line, field string) string {
	return PlanPlaceholderPrefix + line + "-" + field + "-" + testPlaceholderRandom
}

func fleetPlanNode(line string) SelectionPlanNode {
	p := testPlaceholder(line, "uuid")
	return SelectionPlanNode{
		LineUUID:     line,
		Placeholders: map[string]string{"uuid": p},
		Node:         json.RawMessage(`{"name":"Tokyo 03","type":"vless","server":"203.0.113.30","port":443,"uuid":"` + p + `"}`),
	}
}

func TestSelectionPlanWireNames(t *testing.T) {
	nodes := SelectionPlan{
		Kind: SelectionPlanKindNodes,
		Nodes: []SelectionPlanNode{
			fleetPlanNode(catalogueLineA),
			{Provider: true, Node: json.RawMessage(`{"name":"provider-1","type":"trojan","server":"p.example","port":443,"password":"own"}`)},
		},
		ResponseChain: []ResponseTransformerStep{{Name: "tag", Source: "$content += '\\n'", Arguments: json.RawMessage(`{"k":"v"}`), Enabled: true}},
	}
	p := testPlaceholder(catalogueLineA, "uuid")
	want := `{"kind":"nodes","nodes":[{"line_uuid":"` + catalogueLineA + `","placeholders":{"uuid":"` + p + `"},` +
		`"node":{"name":"Tokyo 03","type":"vless","server":"203.0.113.30","port":443,"uuid":"` + p + `"}},` +
		`{"provider":true,"node":{"name":"provider-1","type":"trojan","server":"p.example","port":443,"password":"own"}}],` +
		`"response_chain":[{"name":"tag","source":"$content += '\\n'","arguments":{"k":"v"},"enabled":true}]}`
	if got := mustJSON(t, nodes); got != want {
		t.Fatalf("typed-node plan encodes as\n %s\nwant %s", got, want)
	}
	if err := nodes.Validate(); err != nil {
		t.Fatalf("typed-node plan refused: %v", err)
	}

	doc := SelectionPlan{Kind: SelectionPlanKindDocument, Document: "proxies:\n  - {name: a, uuid: " + p + "}\n", Nodes: []SelectionPlanNode{fleetPlanNode(catalogueLineA)}}
	got := mustJSON(t, doc)
	if !strings.HasPrefix(got, `{"kind":"document","nodes":[{"line_uuid":`) || !strings.HasSuffix(got, `"document":"proxies:\n  - {name: a, uuid: `+p+`}\n"}`) {
		t.Fatalf("document plan encodes as %s", got)
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("document plan refused: %v", err)
	}
}

func TestPlanPlaceholderFormat(t *testing.T) {
	p, err := NewPlanPlaceholder(catalogueLineA, "password")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(p, PlanPlaceholderPrefix+catalogueLineA+"-password-") || len(p) != len(testPlaceholder(catalogueLineA, "password")) {
		t.Fatalf("placeholder %q has the wrong shape", p)
	}
	line, field, err := ParsePlanPlaceholder(p)
	if err != nil || line != catalogueLineA || field != "password" {
		t.Fatalf("ParsePlanPlaceholder(%q) = %q, %q, %v", p, line, field, err)
	}
	if again, _ := NewPlanPlaceholder(catalogueLineA, "password"); again == p {
		t.Fatal("two placeholders for one field are equal; the random part is not fresh")
	}
	longest := strings.Repeat("f", MaxPlanPlaceholderFieldBytes)
	if p, err := NewPlanPlaceholder(catalogueLineA, longest); err != nil || len(p) != MaxPlanPlaceholderBytes {
		t.Fatalf("field at the bound: %q, %v (want %d bytes)", p, err, MaxPlanPlaceholderBytes)
	}
	for _, field := range []string{"", strings.Repeat("f", MaxPlanPlaceholderFieldBytes+1), "private-key", "Uuid", "1uuid", "uu id"} {
		if _, err := NewPlanPlaceholder(catalogueLineA, field); err == nil {
			t.Fatalf("field %q accepted", field)
		}
	}
	if _, err := NewPlanPlaceholder(strings.ToUpper(catalogueLineA), "uuid"); err == nil {
		t.Fatal("uppercase line uuid accepted")
	}
	good := testPlaceholder(catalogueLineA, "uuid")
	for name, bad := range map[string]string{
		"no prefix":       strings.TrimPrefix(good, PlanPlaceholderPrefix),
		"lowercase head":  "lattice-syn-" + strings.TrimPrefix(good, PlanPlaceholderPrefix),
		"short random":    good[:len(good)-1],
		"long random":     good + "0",
		"uppercase hex":   strings.ToUpper(good[:len(good)-32]) + strings.ToUpper(testPlaceholderRandom),
		"not v4":          testPlaceholder("3f2b8c1e-7d4a-1e5f-9a6b-1c2d3e4f5a6b", "uuid"),
		"hyphenated":      testPlaceholder(catalogueLineA, "private-key"),
		"trailing space":  good + " ",
		"leading garbage": "x" + good,
	} {
		if _, _, err := ParsePlanPlaceholder(bad); err == nil {
			t.Fatalf("%s placeholder %q accepted", name, bad)
		}
	}
}

// A script that copies a placeholder into a name or a comment raises its
// count, wherever the copy sits; malformed look-alikes do not count.
func TestCountPlanPlaceholdersFindsEveryCopy(t *testing.T) {
	a := testPlaceholder(catalogueLineA, "uuid")
	b := testPlaceholder(catalogueLineB, "password")
	doc := "proxies:\n" +
		"  - {name: tokyo, uuid: " + a + "}\n" +
		"  - {name: la, password: " + b + "}\n" +
		"# copied: " + a + "\n" +
		"  - {name: x" + a + "y, uuid: z}\n" +
		"LATTICE-SYN-" + b + "\n" +
		"LATTICE-SYN-not-a-placeholder " + a[:len(a)-1] + "\n"
	got := CountPlanPlaceholders(doc)
	want := map[string]int{a: 3, b: 2}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("counts = %v, want %v", got, want)
	}
	if got := CountPlanPlaceholders("no placeholders here"); len(got) != 0 {
		t.Fatalf("counted %v in a clean document", got)
	}
}

func TestSelectionPlanStructuralRefusals(t *testing.T) {
	other := testPlaceholder(catalogueLineB, "uuid")
	cases := map[string]SelectionPlan{
		"unknown kind":            {Kind: "graph"},
		"nodes with document":     {Kind: SelectionPlanKindNodes, Document: "x"},
		"document without text":   {Kind: SelectionPlanKindDocument},
		"document with provider":  {Kind: SelectionPlanKindDocument, Document: "x", Nodes: []SelectionPlanNode{{Provider: true, Node: json.RawMessage(`{}`)}}},
		"node not an object":      {Kind: SelectionPlanKindNodes, Nodes: []SelectionPlanNode{{LineUUID: catalogueLineA, Node: json.RawMessage(`["x"]`)}}},
		"node missing":            {Kind: SelectionPlanKindNodes, Nodes: []SelectionPlanNode{{LineUUID: catalogueLineA}}},
		"provider with line":      {Kind: SelectionPlanKindNodes, Nodes: []SelectionPlanNode{{Provider: true, LineUUID: catalogueLineA, Node: json.RawMessage(`{}`)}}},
		"placeholders, no line":   {Kind: SelectionPlanKindNodes, Nodes: []SelectionPlanNode{{Placeholders: map[string]string{"uuid": other}, Node: json.RawMessage(`{}`)}}},
		"placeholder other line":  {Kind: SelectionPlanKindNodes, Nodes: []SelectionPlanNode{{LineUUID: catalogueLineA, Placeholders: map[string]string{"uuid": other}, Node: json.RawMessage(`{}`)}}},
		"placeholder other field": {Kind: SelectionPlanKindNodes, Nodes: []SelectionPlanNode{{LineUUID: catalogueLineA, Placeholders: map[string]string{"password": testPlaceholder(catalogueLineA, "uuid")}, Node: json.RawMessage(`{}`)}}},
		"malformed placeholder":   {Kind: SelectionPlanKindNodes, Nodes: []SelectionPlanNode{{LineUUID: catalogueLineA, Placeholders: map[string]string{"uuid": "real-uuid"}, Node: json.RawMessage(`{}`)}}},
		"bad line uuid":           {Kind: SelectionPlanKindNodes, Nodes: []SelectionPlanNode{{LineUUID: "line-a", Node: json.RawMessage(`{}`)}}},
		"bad response chain":      {Kind: SelectionPlanKindNodes, ResponseChain: []ResponseTransformerStep{{Name: "empty"}}},
		// A plan that arrives inside a render reply is validated, not decoded
		// by DecodeSelectionPlan, so Validate scans each node itself.
		"duplicate key in a node": {Kind: SelectionPlanKindNodes, Nodes: []SelectionPlanNode{{Provider: true, Node: json.RawMessage(`{"server":"a.example","server":"evil.example"}`)}}},
	}
	for name, plan := range cases {
		if err := plan.Validate(); err == nil {
			t.Fatalf("%s: plan accepted", name)
		}
	}
	// A fleet node without a line is the core's to exclude with no_line,
	// not a broken plan.
	noLine := SelectionPlan{Kind: SelectionPlanKindNodes, Nodes: []SelectionPlanNode{{Node: json.RawMessage(`{"name":"injected","server":"evil.example"}`)}}}
	if err := noLine.Validate(); err != nil {
		t.Fatalf("plan with a lineless fleet node refused: %v", err)
	}
}

func TestSelectionPlanNodeCountAtTheBound(t *testing.T) {
	plan := SelectionPlan{Kind: SelectionPlanKindNodes}
	for i := 0; i < MaxSubscriptionRecordNodes; i++ {
		plan.Nodes = append(plan.Nodes, SelectionPlanNode{Provider: true, Node: json.RawMessage(`{}`)})
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("plan at %d nodes refused: %v", MaxSubscriptionRecordNodes, err)
	}
	plan.Nodes = append(plan.Nodes, SelectionPlanNode{Provider: true, Node: json.RawMessage(`{}`)})
	if err := plan.Validate(); err == nil {
		t.Fatal("plan one node over the bound accepted")
	}
}

func TestSelectionPlanExcessClones(t *testing.T) {
	plan := SelectionPlan{Kind: SelectionPlanKindNodes}
	add := func(n SelectionPlanNode, times int) {
		for i := 0; i < times; i++ {
			plan.Nodes = append(plan.Nodes, n)
		}
	}
	add(fleetPlanNode(catalogueLineA), MaxPlanClonesPerLine)
	add(fleetPlanNode(catalogueLineB), 1)
	add(SelectionPlanNode{Node: json.RawMessage(`{}`)}, 6)
	if got := plan.ExcessClones(); got != nil {
		t.Fatalf("four clones of a line reported excess %v", got)
	}
	add(fleetPlanNode(catalogueLineA), 2)
	if got, want := plan.ExcessClones(), []int{11, 12}; !reflect.DeepEqual(got, want) {
		t.Fatalf("excess clones = %v, want %v", got, want)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("a plan with excess clones is the core's to trim, not broken: %v", err)
	}
}

func TestSelectionPlanEncodedSizeAtTheBound(t *testing.T) {
	plan := func(n int) SelectionPlan {
		return SelectionPlan{Kind: SelectionPlanKindDocument, Document: strings.Repeat("d", n), Nodes: []SelectionPlanNode{fleetPlanNode(catalogueLineA)}}
	}
	overhead := len(mustJSON(t, plan(1))) - 1
	atBound := plan(MaxSelectionPlanBytes - overhead)
	raw, err := EncodeSelectionPlan(atBound)
	if err != nil || len(raw) != MaxSelectionPlanBytes {
		t.Fatalf("plan at the bound: %d bytes, %v", len(raw), err)
	}
	back, err := DecodeSelectionPlan(raw)
	if err != nil || back.Document != atBound.Document {
		t.Fatalf("plan at the bound did not decode: %v", err)
	}
	over := plan(MaxSelectionPlanBytes - overhead + 1)
	if _, err := EncodeSelectionPlan(over); err == nil {
		t.Fatal("plan one byte over the bound encoded")
	}
	if _, err := DecodeSelectionPlan([]byte(mustJSON(t, over))); err == nil {
		t.Fatal("plan one byte over the bound decoded")
	}
	for name, raw := range map[string]string{
		"unknown field":         `{"kind":"nodes","nodes":[],"identity":"vu_7"}`,
		"trailing data":         `{"kind":"nodes","nodes":[]} {}`,
		"invalid plan":          `{"kind":"nodes","nodes":[],"document":"x"}`,
		"duplicate top key":     `{"kind":"document","kind":"nodes","nodes":[]}`,
		"duplicate node key":    `{"kind":"nodes","nodes":[{"provider":true,"node":{"server":"a.example","server":"evil.example"}}]}`,
		"duplicate nested key":  `{"kind":"nodes","nodes":[{"provider":true,"node":{"reality-opts":{"short-id":"a","short-id":"b"}}}]}`,
		"duplicate placeholder": `{"kind":"nodes","nodes":[{"line_uuid":"` + catalogueLineA + `","placeholders":{"uuid":"x","uuid":"` + testPlaceholder(catalogueLineA, "uuid") + `"},"node":{}}]}`,
	} {
		if _, err := DecodeSelectionPlan([]byte(raw)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

// The design's size target: a 4096-node plan of Reality nodes with transport
// options, and the convert request carrying the same nodes once bound, each
// stay under 6 MiB. The node here is a dense stand-in for the S1 node model.
func TestSelectionPlanAt4096RealityNodesFitsTheBound(t *testing.T) {
	plan := SelectionPlan{Kind: SelectionPlanKindNodes}
	convert := ConvertRequest{Target: "sing-box"}
	for i := 0; i < MaxSubscriptionRecordNodes; i++ {
		line := fmt.Sprintf("%08x-0000-4000-8000-%012x", i, i)
		p := testPlaceholder(line, "uuid")
		node := fmt.Sprintf(`{"name":"JP Tokyo %04d IIJ premium","type":"vless","server":"tyo%04d.edge.example.net","port":443,`+
			`"uuid":"%s","flow":"xtls-rprx-vision","network":"grpc","tls":true,"udp":true,"servername":"www.example-camouflage.com",`+
			`"client-fingerprint":"chrome","alpn":["h2","http/1.1"],"reality-opts":{"public-key":"Zm9vYmFyYmF6cXV4cXV1eGNvcmdlZ3JhdWx0Z2FycGx5","short-id":"6ba85179e30d4fc2"},`+
			`"grpc-opts":{"grpc-service-name":"lattice-grpc-%04d"},"line_uuid":"%s","node_id":"node-tokyo-%04d","geo":{"country":"JP","city":"Tokyo"}}`,
			i, i, p, i, line, i)
		plan.Nodes = append(plan.Nodes, SelectionPlanNode{LineUUID: line, Placeholders: map[string]string{"uuid": p}, Node: json.RawMessage(node)})
		bound := strings.Replace(node, p, "c7f3e2a1-9b8d-4c6e-a5f4-3b2a1c0d9e8f", 1)
		convert.Nodes = append(convert.Nodes, json.RawMessage(bound))
	}
	raw, err := EncodeSelectionPlan(plan)
	if err != nil {
		t.Fatalf("4096-node plan: %v", err)
	}
	request, err := EncodeConvertRequest(convert)
	if err != nil {
		t.Fatalf("4096-node convert request: %v", err)
	}
	t.Logf("4096 nodes: plan %d bytes, convert request %d bytes", len(raw), len(request))
}
