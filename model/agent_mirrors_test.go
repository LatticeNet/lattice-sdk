package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// A plan request carries an entry the server has not stamped yet, and a
// fetch without a chunk failure says nothing about chunks.
func TestAgentMirrorWireShape(t *testing.T) {
	raw, err := json.Marshal(AgentMirrorPlanRequest{Action: AgentMirrorActionCreate, Mirror: AgentMirror{
		ID: "r2", BaseURL: "https://dl.example.org", Global: true, Priority: 10, Enabled: true,
	}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"action":"create","mirror":{"id":"r2","base_url":"https://dl.example.org","global":true,"priority":10,"enabled":true}}`
	if string(raw) != want {
		t.Fatalf("plan request encoded as %s, want %s", raw, want)
	}

	raw, err = json.Marshal(AgentUpdateFetchAttempt{Source: 1, Kind: AgentFetchKindMirrorPrefix + "r2", ExitCode: 0, Bytes: 262144})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "bad_chunks") {
		t.Fatalf("a fetch without chunk failures must not carry bad_chunks: %s", raw)
	}
	raw, err = json.Marshal(AgentUpdateFetchAttempt{Source: 1, Kind: "m.r2", ExitCode: 0, Bytes: 0, BadChunks: 1})
	if err != nil {
		t.Fatal(err)
	}
	var back AgentUpdateFetchAttempt
	if err := json.Unmarshal(raw, &back); err != nil || back.BadChunks != 1 || back.Kind != "m.r2" {
		t.Fatalf("a chunk failure did not round trip: %s %+v %v", raw, back, err)
	}

	raw, err = json.Marshal(AgentUpdateSource{Kind: AgentSourceKindControlPlane, URL: "https://cp.example.org/x", Reason: "held"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"kind":"control-plane","url":"https://cp.example.org/x","reason":"held"}`; string(raw) != want {
		t.Fatalf("source encoded as %s, want %s", raw, want)
	}
}
