package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestBeaconWireShapes pins the JSON names D12 documents for the agent
// config, the agent's facts and the plan document.
func TestBeaconWireShapes(t *testing.T) {
	cfg := AgentConfig{Beacon: &AgentBeaconConfig{
		SourceID: 4,
		Keys:     []BeaconPathKey{{TargetNode: "node_b", Epoch: 2, Key: make([]byte, 32)}},
		Responder: &BeaconResponderConfig{
			Bind: "10.0.0.5", Port: 45001, Limits: DefaultBeaconLimits(),
			Table: []BeaconTableKey{{SourceID: 4, Epoch: 2, Key: make([]byte, 32), Retired: true}},
		},
	}}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"beacon":{"source_id":4,"keys":[{"target_node":"node_b","epoch":2,"key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}]`,
		`"responder":{"bind":"10.0.0.5","port":45001,"limits":{"source_rate_per_second":20,"min_interval_sec":10,"packets_per_second_max":2}`,
		`"table":[{"source_id":4,"epoch":2,"key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","retired":true}]`,
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("agent config %s lacks %s", raw, want)
		}
	}
	if raw, _ := json.Marshal(AgentConfig{}); strings.Contains(string(raw), "beacon") {
		t.Fatalf("an agent config without a beacon carries the key: %s", raw)
	}
	facts, _ := json.Marshal(BeaconFacts{Responder: true, Refusal: PathReasonRefusedByNode, State: BeaconAgentRefused})
	if string(facts) != `{"responder":true,"refusal":"refused_by_node","state":"refused"}` {
		t.Fatalf("facts = %s", facts)
	}
	if raw, _ := json.Marshal(Node{}); strings.Contains(string(raw), `"beacon"`) {
		t.Fatalf("a node without beacon facts carries the key: %s", raw)
	}
	view, _ := json.Marshal(BeaconView{NodeID: "n", State: BeaconStateOff})
	if strings.Contains(string(view), "key") {
		t.Fatalf("the beacon view names a key: %s", view)
	}
}

// TestBeaconReplanShape pins the replan a console files in one click: off
// the view until it is needed, and when present a plan request the plan
// route takes as it is.
func TestBeaconReplanShape(t *testing.T) {
	if raw, _ := json.Marshal(BeaconView{NodeID: "n", State: BeaconStateListening}); strings.Contains(string(raw), "replan") {
		t.Fatalf("a view that needs no plan carries the key: %s", raw)
	}
	replan := BeaconReplan{
		NodeID: "node_t", Name: "target", Reason: PathReasonFirewallPending,
		Added: []string{"node_d"}, Removed: []string{},
		Request: BeaconPlanRequest{NodeID: "node_t", Action: BeaconActionChange},
	}
	raw, err := json.Marshal(BeaconView{NodeID: "node_t", Replan: &replan})
	if err != nil {
		t.Fatal(err)
	}
	want := `"replan":{"node_id":"node_t","name":"target","reason":"firewall_pending","added":["node_d"],"removed":[],"request":{"node_id":"node_t","action":"change"}}`
	if !strings.Contains(string(raw), want) {
		t.Fatalf("view = %s, want it to carry %s", raw, want)
	}
	raw, err = json.Marshal(PathMatrix{Window: PathWindowHour, BeaconReplans: []BeaconReplan{}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"beacon_replans":[]`) {
		t.Fatalf("matrix = %s", raw)
	}
}
