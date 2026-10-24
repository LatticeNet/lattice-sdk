package model

import (
	"encoding/json"
	"reflect"
	"testing"
)

// A stored policy from before selectors carries only scope_group_id. It must
// keep reading as the one-group selector, so nothing stored needs migrating.
func TestGroupNetPolicyScopeGroupIDReadsAsOneGroupSelector(t *testing.T) {
	var stored GroupNetPolicy
	if err := json.Unmarshal([]byte(`{"id":"gnp_1","scope_group_id":"grp_web","rules":[],"enabled":true,"priority":10}`), &stored); err != nil {
		t.Fatal(err)
	}
	if stored.Scope != nil {
		t.Fatalf("an old document must decode without a scope, got %+v", stored.Scope)
	}
	got := stored.TargetScope()
	want := TargetSelector{Groups: []string{"grp_web"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("TargetScope() = %+v, want %+v", got, want)
	}
}

func TestGroupNetPolicyScopeWinsOverAlias(t *testing.T) {
	p := GroupNetPolicy{
		ScopeGroupID: "grp_web",
		Scope:        &TargetSelector{Nodes: []string{"node-a", "node-b"}, Exclude: []string{"node-c"}},
	}
	got := p.TargetScope()
	if !reflect.DeepEqual(got.Nodes, []string{"node-a", "node-b"}) || len(got.Groups) != 0 || !reflect.DeepEqual(got.Exclude, []string{"node-c"}) {
		t.Fatalf("TargetScope() = %+v, want the stored scope", got)
	}
	// The returned selector is a copy: changing it leaves the policy alone.
	got.Nodes[0] = "changed"
	if p.Scope.Nodes[0] != "node-a" {
		t.Fatal("TargetScope must not alias the stored slices")
	}
	if empty := (GroupNetPolicy{}).TargetScope(); !reflect.DeepEqual(empty, TargetSelector{}) {
		t.Fatalf("a policy with neither field targets nothing, got %+v", empty)
	}
}

func TestTargetSelectorJSONShape(t *testing.T) {
	raw, err := json.Marshal(TargetSelector{Nodes: []string{"node-a"}, Groups: []string{"asia"}, Exclude: []string{"node-b"}})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"nodes":["node-a"],"groups":["asia"],"exclude":["node-b"]}` {
		t.Fatalf("unexpected selector JSON %s", raw)
	}
	raw, _ = json.Marshal(TargetSelector{All: true})
	if string(raw) != `{"all":true}` {
		t.Fatalf("unexpected whole-fleet JSON %s", raw)
	}
}
