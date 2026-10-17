package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// The agent tells a server that serves prefetch from an older one by the
// agent_update block alone, so the block must be on the wire whenever the
// server sets it, keep included and empty as [], and absent otherwise.
func TestAgentConfigCarriesTheUpdateBlockOnlyWhenSet(t *testing.T) {
	raw, err := json.Marshal(AgentConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "agent_update") {
		t.Fatalf("an older server's config must not carry agent_update: %s", raw)
	}
	var old AgentConfig
	if err := json.Unmarshal(raw, &old); err != nil || old.AgentUpdate != nil {
		t.Fatalf("a config without the block must decode to nil: %+v %v", old.AgentUpdate, err)
	}

	raw, err = json.Marshal(AgentConfig{AgentUpdate: &AgentUpdateConfig{Keep: []string{}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"agent_update":{"keep":[]}`) {
		t.Fatalf("a block with nothing to fetch must still say so: %s", raw)
	}
	var empty AgentConfig
	if err := json.Unmarshal(raw, &empty); err != nil || empty.AgentUpdate == nil || empty.AgentUpdate.Prefetch != nil {
		t.Fatalf("decoded %+v %v", empty.AgentUpdate, err)
	}
}

// The prefetch target and the report round-trip with the field names both
// sides use, and the target carries no URL.
func TestAgentPrefetchWireNames(t *testing.T) {
	digest := strings.Repeat("a", 64)
	target := AgentUpdatePrefetch{
		ApprovalID: "approval_1", Version: "0.3.10-alpha.7", OS: "linux", Arch: "amd64",
		SHA256: digest, CompressedSHA256: strings.Repeat("b", 64), Size: 5552813, BinarySize: 14037154,
		InstallPath: "/opt/lattice/node-agent/lattice-agent",
	}
	raw, err := json.Marshal(AgentConfig{AgentUpdate: &AgentUpdateConfig{Prefetch: &target, Keep: []string{digest}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{`"approval_id"`, `"version"`, `"os"`, `"arch"`, `"sha256"`, `"compressed_sha256"`, `"size"`, `"binary_size"`, `"install_path"`, `"keep"`} {
		if !strings.Contains(string(raw), name) {
			t.Fatalf("%s missing from %s", name, raw)
		}
	}
	if strings.Contains(string(raw), "http") || strings.Contains(string(raw), "url") {
		t.Fatalf("the target must carry no URL: %s", raw)
	}
	var back AgentConfig
	if err := json.Unmarshal(raw, &back); err != nil || back.AgentUpdate == nil || back.AgentUpdate.Prefetch == nil || *back.AgentUpdate.Prefetch != target {
		t.Fatalf("round trip %+v %v", back.AgentUpdate, err)
	}

	raw, err = json.Marshal(AgentUpdatePrefetch{ApprovalID: "approval_1", SHA256: digest, Size: 1, BinarySize: 1})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "compressed_sha256") {
		t.Fatalf("an uncompressed target must not carry compressed_sha256: %s", raw)
	}

	facts := AgentPrefetchFacts{ApprovalID: "approval_1", SHA256: digest, Bytes: 4096, Size: 5552813, State: AgentPrefetchFetching}
	raw, err = json.Marshal(facts)
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"approval_id":"approval_1","sha256":"` + digest + `","bytes":4096,"size":5552813,"state":"fetching"}`; string(raw) != want {
		t.Fatalf("report encoded as %s, want %s", raw, want)
	}
	for _, state := range []string{AgentPrefetchFetching, AgentPrefetchComplete, AgentPrefetchWaiting, AgentPrefetchRefused} {
		if state == "" || strings.ToLower(state) != state {
			t.Fatalf("state %q", state)
		}
	}
}
