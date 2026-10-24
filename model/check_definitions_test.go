package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The stored selector shape is design 32 D5's, key for key, and an empty
// selector carries no key at all, so it cannot read as a whole-fleet one.
func TestTargetSelectorWireShape(t *testing.T) {
	raw, err := json.Marshal(TargetSelector{Nodes: []string{"node-a"}, Groups: []string{"asia"}, All: true, Exclude: []string{"node-b"}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"nodes":["node-a"],"groups":["asia"],"all":true,"exclude":["node-b"]}`
	if string(raw) != want {
		t.Fatalf("selector JSON = %s, want %s", raw, want)
	}
	raw, err = json.Marshal(TargetSelector{})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{}` {
		t.Fatalf("empty selector JSON = %s, want {}", raw)
	}
	var back TargetSelector
	if err := json.Unmarshal([]byte(`{"nodes":["n1"],"groups":["g1"],"all":false,"exclude":["n2"]}`), &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, TargetSelector{Nodes: []string{"n1"}, Groups: []string{"g1"}, Exclude: []string{"n2"}}) {
		t.Fatalf("decoded selector = %+v", back)
	}
}

// A definition, a save and a view carry the spec flat beside their own
// fields, so a console reads one object rather than a nested spec.
func TestCheckDefinitionFlattensItsSpec(t *testing.T) {
	at := time.Date(2026, 10, 24, 8, 0, 0, 0, time.UTC)
	def := CheckDefinition{
		ID: "chk_abc",
		CheckDefinitionSpec: CheckDefinitionSpec{
			Name: "edge web", Type: MonitorTypeHTTP, Sources: TargetSelector{Nodes: []string{"n1"}},
			Addresses: []string{"https://example.com/health"}, IntervalSec: 60, TimeoutSec: 5, Enabled: true,
		},
		Headers:        []MonitorHeader{{Name: "X-Key", Secret: true, Set: true}},
		SecretsOrigins: []string{"https://example.com:443"},
		Version:        3, CreatedAt: at, UpdatedAt: at,
	}
	raw, err := json.Marshal(CheckDefinitionView{CheckDefinition: def, Summary: CheckDefinitionSummary{Monitors: 1, Paths: 1}})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"id", "name", "type", "sources", "targets", "addresses", "interval_sec", "timeout_sec", "enabled", "headers", "secrets_origins", "version", "created_at", "updated_at", "summary"} {
		if _, ok := doc[key]; !ok {
			t.Fatalf("view lacks top-level %q: %s", key, raw)
		}
	}
	if _, nested := doc["CheckDefinitionSpec"]; nested {
		t.Fatalf("spec nested instead of flattened: %s", raw)
	}
	if _, ok := doc["monitors"]; ok {
		t.Fatalf("a list row carries no monitors: %s", raw)
	}

	var save CheckDefinitionSave
	body := `{"id":"chk_abc","version":3,"name":"edge web","type":"http","sources":{"nodes":["n1"]},"targets":{},` +
		`"addresses":["https://example.com/health"],"interval_sec":60,"timeout_sec":5,"enabled":true,` +
		`"headers":[{"name":"X-Key","op":"keep"}]}`
	if err := json.Unmarshal([]byte(body), &save); err != nil {
		t.Fatal(err)
	}
	if save.ID != "chk_abc" || save.Version != 3 || save.Name != "edge web" || save.Type != MonitorTypeHTTP ||
		!reflect.DeepEqual(save.Sources.Nodes, []string{"n1"}) || len(save.Headers) != 1 || save.Headers[0].Op != MonitorHeaderKeep {
		t.Fatalf("decoded save = %+v", save)
	}
}

// A save's headers are edit operations, never stored headers: an editor that
// echoes the secret-less read sends names and ops, not empty values.
func TestCheckDefinitionSaveHeadersAreEdits(t *testing.T) {
	field, ok := reflect.TypeFor[CheckDefinitionSave]().FieldByName("Headers")
	if !ok {
		t.Fatal("CheckDefinitionSave has no Headers")
	}
	if field.Type != reflect.TypeFor[[]MonitorHeaderEdit]() {
		t.Fatalf("CheckDefinitionSave.Headers is %s, want []MonitorHeaderEdit", field.Type)
	}
}

// The budget pause is its own reason, apart from an operator's pause.
func TestPacketBudgetReasonIsDistinct(t *testing.T) {
	if PathReasonPacketBudget == PathReasonSourcePaused || !strings.Contains(PathReasonPacketBudget, "budget") {
		t.Fatalf("PathReasonPacketBudget = %q", PathReasonPacketBudget)
	}
}
