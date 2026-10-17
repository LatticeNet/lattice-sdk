package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A policy whose node never reported a fetch, was never planned or never
// confirmed an update carries none of those on the wire, and a fetch record
// without a time must not reach a consumer as year 0001.
func TestAgentUpdatePolicyOmitsWhatNeverHappened(t *testing.T) {
	raw, err := json.Marshal(AgentUpdatePolicy{NodeID: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"last_fetch", "last_planned_at", "last_applied_at"} {
		if strings.Contains(string(raw), `"`+field+`"`) {
			t.Fatalf("absent %s reached the wire: %s", field, raw)
		}
	}

	raw, err = json.Marshal(AgentUpdateFetch{ApprovalID: "approval_1", Stage: AgentFetchStagePrepare, ExitCode: 1})
	if err != nil {
		t.Fatal(err)
	}
	// A failure in prepare made no fetch and has no time, and its exit
	// status has to be on the wire.
	if want := `{"approval_id":"approval_1","exit_code":1,"stage":"prepare"}`; string(raw) != want {
		t.Fatalf("prepare failure encoded as %s, want %s", raw, want)
	}

	at := time.Date(2026, 10, 17, 9, 30, 0, 0, time.UTC)
	raw, err = json.Marshal(AgentUpdatePolicy{NodeID: "n1", LastPlannedAt: at, LastAppliedAt: at})
	if err != nil {
		t.Fatal(err)
	}
	var back AgentUpdatePolicy
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !back.LastPlannedAt.Equal(at) || !back.LastAppliedAt.Equal(at) {
		t.Fatalf("planned and applied times did not round trip: %s", raw)
	}
}

// Every value the console reads survives the round trip, including the ones
// whose zero carries meaning: exit status 0, zero bytes, zero seconds, and
// the difference between zero seconds and no clock.
func TestAgentUpdateFetchRoundTrips(t *testing.T) {
	zero, took := int64(0), int64(41)
	at := time.Date(2026, 10, 17, 9, 30, 0, 0, time.UTC)
	want := AgentUpdateFetch{
		ApprovalID:    "approval_1",
		TargetVersion: "0.3.10-alpha.6",
		At:            at,
		Fetches: []AgentUpdateFetchAttempt{
			{Source: 1, Kind: AgentFetchKindControlPlaneGzip, ExitCode: 28, Bytes: 1_048_576, Seconds: &took},
			{Source: 2, Kind: AgentFetchKindUpstream, ExitCode: 7, Bytes: 0, Seconds: &zero},
			{SecondPass: true, Kind: AgentFetchKindControlPlaneGzip, ExitCode: 0, Bytes: 4_504_237},
		},
		ExitCode: 0,
		Stage:    AgentFetchStageDone,
	}
	raw, err := json.Marshal(AgentUpdatePolicy{NodeID: "n1", LastFetch: &want})
	if err != nil {
		t.Fatal(err)
	}
	for _, needle := range []string{`"exit_code":0`, `"bytes":0`, `"seconds":0`, `"second_pass":true`, `"kind":"cp.gz"`} {
		if !strings.Contains(string(raw), needle) {
			t.Fatalf("%s missing from %s", needle, raw)
		}
	}
	var back AgentUpdatePolicy
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	got := back.LastFetch
	if got == nil || got.ApprovalID != want.ApprovalID || got.TargetVersion != want.TargetVersion || !got.At.Equal(at) ||
		got.ExitCode != 0 || got.Stage != AgentFetchStageDone || len(got.Fetches) != 3 {
		t.Fatalf("fetch did not round trip: %+v", got)
	}
	if s := got.Fetches[0].Seconds; s == nil || *s != 41 {
		t.Fatalf("seconds lost: %v", s)
	}
	if s := got.Fetches[1].Seconds; s == nil || *s != 0 {
		t.Fatalf("zero seconds lost: %v", s)
	}
	if got.Fetches[2].Seconds != nil || !got.Fetches[2].SecondPass || got.Fetches[2].Source != 0 {
		t.Fatalf("second-pass fetch without a clock did not round trip: %+v", got.Fetches[2])
	}
}
