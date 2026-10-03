package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The wire shape is the one node-agent 0.3.10-alpha.1 already sends as
// "loop_health" (cmd/lattice-agent/keepalive.go loopHealthPayload). This body
// is copied from that shape, so a renamed tag here fails before a server
// silently stops reading a field every beat carries.
func TestAgentHealthDecodesTheAgentPayload(t *testing.T) {
	body := `{
		"started_at": "2026-10-03T01:00:00Z",
		"cycle_started_at": "2026-10-03T01:09:50Z",
		"cycle_completed_at": "2026-10-03T01:09:52Z",
		"cycle_duration_ms": 2100,
		"step": "inventory",
		"step_since": "2026-10-03T01:10:00Z",
		"linechain_blocked": "journal 3 unreadable",
		"linechain_blocked_since": "2026-10-03T01:02:00Z",
		"steps": {
			"config": {"last_ok_at": "2026-10-03T01:09:50Z"},
			"usage": {"last_error_at": "2026-10-03T01:09:51Z", "last_error": "post /api/agent/usage: 502", "consecutive_errors": 4}
		},
		"task_busy_since": "2026-10-03T01:08:00Z",
		"monitor_results_queued": 12,
		"monitor_results_dropped": 7,
		"watchdog": true
	}`
	var h AgentHealth
	if err := json.Unmarshal([]byte(body), &h); err != nil {
		t.Fatal(err)
	}
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	switch {
	case !h.StartedAt.Equal(at("2026-10-03T01:00:00Z")),
		!h.CycleCompletedAt.Equal(at("2026-10-03T01:09:52Z")),
		h.CycleDurationMs != 2100,
		h.Step != AgentStepInventory,
		!h.StepSince.Equal(at("2026-10-03T01:10:00Z")),
		h.LinechainBlocked != "journal 3 unreadable",
		!h.LinechainBlockedSince.Equal(at("2026-10-03T01:02:00Z")),
		!h.TaskBusySince.Equal(at("2026-10-03T01:08:00Z")),
		h.MonitorResultsQueued != 12,
		h.MonitorResultsDropped != 7,
		!h.Watchdog:
		t.Fatalf("payload decoded wrong: %+v", h)
	}
	usage := h.Steps[AgentStepUsage]
	if usage.ConsecutiveErrors != 4 || usage.LastError != "post /api/agent/usage: 502" || !usage.LastOKAt.IsZero() {
		t.Fatalf("usage step decoded wrong: %+v", usage)
	}
	if !h.Steps[AgentStepConfig].LastOKAt.Equal(at("2026-10-03T01:09:50Z")) {
		t.Fatalf("config step decoded wrong: %+v", h.Steps[AgentStepConfig])
	}
}

// A fresh agent has run no cycle and no step yet. The zero instants must stay
// off the wire, so a console never renders year 0001 as "last cycle".
func TestAgentHealthLeavesUnsetInstantsOffTheWire(t *testing.T) {
	raw, err := json.Marshal(AgentHealth{StartedAt: time.Date(2026, 10, 3, 1, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"cycle_started_at", "cycle_completed_at", "step_since", "linechain_blocked_since", "task_busy_since", "steps", "monitor_results_dropped"} {
		if strings.Contains(string(raw), field) {
			t.Fatalf("zero %s reached the wire: %s", field, raw)
		}
	}
	raw, err = json.Marshal(AgentLoopStep{})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "{}" {
		t.Fatalf("an empty step should encode as {}, got %s", raw)
	}
}
