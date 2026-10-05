package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func traceTestTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// A policy stored before the raw switch existed has no "raw" key. Raw lines
// then follow records, which is what every server up to alpha-0.2.2a117 did.
func TestRawLinesEnabledFollowsRecordsWhenUnset(t *testing.T) {
	if !(TracePolicy{Enabled: true}).RawLinesEnabled() {
		t.Fatal("records on with Raw unset must ship raw lines")
	}
	if (TracePolicy{Enabled: false}).RawLinesEnabled() {
		t.Fatal("records off with Raw unset must not ship raw lines")
	}
}

// Raw lines are a sub-switch of records: the agent's raw path is fed by the
// lines the records floor keeps, so raw on with records off ships nothing.
func TestRawLinesEnabledNeedsRecordsOn(t *testing.T) {
	cases := []struct {
		records, raw, want bool
	}{
		{records: true, raw: true, want: true},
		{records: true, raw: false, want: false},
		{records: false, raw: true, want: false},
		{records: false, raw: false, want: false},
	}
	for _, c := range cases {
		p := TracePolicy{Enabled: c.records, Raw: &RawLinePolicy{Enabled: c.raw}}
		if got := p.RawLinesEnabled(); got != c.want {
			t.Fatalf("records=%v raw=%v: RawLinesEnabled = %v, want %v", c.records, c.raw, got, c.want)
		}
	}
}

// The golden string is what alpha-0.2.2a117 and every agent before this
// field marshal for the same policy. A nil Raw must not change one byte.
const tracePolicyBeforeRaw = `{"node_id":"legend-sg","enabled":true,"level":"debug","budget_lines_per_sec":500,` +
	`"clash_api_addr":"127.0.0.1:9090","secret_path":"/etc/sing-box/config.json",` +
	`"updated_at":"2026-10-05T09:59:50Z","last_core_generation":3,"last_core_started_at":"2026-10-05T08:00:00Z"}`

func tracePolicyFixture(t *testing.T) TracePolicy {
	return TracePolicy{
		NodeID:             "legend-sg",
		Enabled:            true,
		Level:              TraceLevelDebug,
		BudgetLinesPerSec:  500,
		ClashAPIAddr:       "127.0.0.1:9090",
		SecretPath:         "/etc/sing-box/config.json",
		UpdatedAt:          traceTestTime(t, "2026-10-05T09:59:50Z"),
		LastCoreGeneration: 3,
		LastCoreStartedAt:  traceTestTime(t, "2026-10-05T08:00:00Z"),
	}
}

func TestTracePolicyWithoutRawEncodesAsBefore(t *testing.T) {
	raw, err := json.Marshal(tracePolicyFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != tracePolicyBeforeRaw {
		t.Fatalf("nil Raw changed the policy bytes:\n got %s\nwant %s", raw, tracePolicyBeforeRaw)
	}
}

// A set switch, including an explicit off, survives a store round trip as a
// set switch. Decoding it back to nil would turn "raw off" into "raw follows
// records", which is on.
func TestTracePolicyRawRoundTrips(t *testing.T) {
	p := tracePolicyFixture(t)
	p.Raw = &RawLinePolicy{Enabled: false}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Replace(tracePolicyBeforeRaw, `,"updated_at"`, `,"raw":{"enabled":false},"updated_at"`, 1)
	if string(raw) != want {
		t.Fatalf("policy with raw off:\n got %s\nwant %s", raw, want)
	}
	var back TracePolicy
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Raw == nil || back.Raw.Enabled {
		t.Fatalf("explicit raw off decoded as %+v", back.Raw)
	}
	if back.RawLinesEnabled() {
		t.Fatal("explicit raw off with records on must not ship raw lines")
	}
}

// JSON written before the new keys existed decodes to exactly what it meant.
func TestOlderTraceJSONDecodesUnchanged(t *testing.T) {
	var p TracePolicy
	if err := json.Unmarshal([]byte(tracePolicyBeforeRaw), &p); err != nil {
		t.Fatal(err)
	}
	if p.Raw != nil {
		t.Fatalf("a policy without a raw key decoded with Raw %+v", p.Raw)
	}
	if want := tracePolicyFixture(t); p != want {
		t.Fatalf("old policy decoded as\n %+v\nwant %+v", p, want)
	}
	if !p.RawLinesEnabled() {
		t.Fatal("old policy with records on must keep shipping raw lines")
	}

	var b TraceBatch
	old := `{"node_id":"legend-sg","dropped":42,"unparsed":2,"captured_at":"2026-10-05T10:00:01Z"}`
	if err := json.Unmarshal([]byte(old), &b); err != nil {
		t.Fatal(err)
	}
	if b.ShedConnections != 0 || b.Dropped != 42 || b.Unparsed != 2 || b.NodeID != "legend-sg" ||
		!b.CapturedAt.Equal(traceTestTime(t, "2026-10-05T10:00:01Z")) {
		t.Fatalf("old batch decoded wrong: %+v", b)
	}
}

func TestCollectorStatusWireNames(t *testing.T) {
	s := CollectorStatus{
		State:             CollectorReady,
		Since:             traceTestTime(t, "2026-10-05T09:59:51Z"),
		Level:             TraceLevelDebug,
		ClashAPIAddr:      "127.0.0.1:9090",
		AddrSource:        ClashAddrFromConfig,
		Detail:            "logs stream reconnected",
		RawLines:          true,
		LinesPerSec:       41.3,
		BudgetLinesPerSec: 5000,
		ShedConnections:   40,
		Unparsed:          2,
		CountersSince:     traceTestTime(t, "2026-10-05T08:00:00Z"),
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"state":"ready","since":"2026-10-05T09:59:51Z","level":"debug","clash_api_addr":"127.0.0.1:9090",` +
		`"addr_source":"config","detail":"logs stream reconnected","raw_lines":true,"lines_per_sec":41.3,` +
		`"budget_lines_per_sec":5000,"shed_connections":40,"unparsed":2,"counters_since":"2026-10-05T08:00:00Z"}`
	if string(raw) != want {
		t.Fatalf("collector status wire shape:\n got %s\nwant %s", raw, want)
	}
	var back CollectorStatus
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back != s {
		t.Fatalf("round trip:\n got %+v\nwant %+v", back, s)
	}

	// The not-ready status the plan fixes for the metrics beat (I2). Zero
	// counters and an empty address stay off the wire.
	notReady := CollectorStatus{
		State:             CollectorNoClashAPI,
		Since:             traceTestTime(t, "2026-10-05T09:59:51Z"),
		Detail:            "no experimental.clash_api in /etc/sing-box/config.json",
		BudgetLinesPerSec: 5000,
		CountersSince:     traceTestTime(t, "2026-10-05T08:00:00Z"),
	}
	raw, err = json.Marshal(notReady)
	if err != nil {
		t.Fatal(err)
	}
	want = `{"state":"no_clash_api","since":"2026-10-05T09:59:51Z",` +
		`"detail":"no experimental.clash_api in /etc/sing-box/config.json",` +
		`"budget_lines_per_sec":5000,"counters_since":"2026-10-05T08:00:00Z"}`
	if string(raw) != want {
		t.Fatalf("not-ready status wire shape:\n got %s\nwant %s", raw, want)
	}
	raw, err = json.Marshal(CollectorStatus{State: CollectorOff})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != `{"state":"off"}` {
		t.Fatalf("zero status leaked fields: %s", raw)
	}
}

func TestAgentMayNotSendAgentTooOld(t *testing.T) {
	for _, s := range []CollectorState{CollectorOff, CollectorReady, CollectorNoClashAPI, CollectorSecretUnreadable, CollectorStreamFailing} {
		if !ValidAgentCollectorState(s) {
			t.Fatalf("%q is an agent state and was refused", s)
		}
	}
	for _, s := range []CollectorState{CollectorAgentTooOld, "", "waiting", "READY"} {
		if ValidAgentCollectorState(s) {
			t.Fatalf("%q was accepted from an agent", s)
		}
	}
}

func TestBoundCollectorDetail(t *testing.T) {
	if got := BoundCollectorDetail("get /logs: 401 Unauthorized"); got != "get /logs: 401 Unauthorized" {
		t.Fatalf("short detail changed: %q", got)
	}
	if got := BoundCollectorDetail("dial tcp 127.0.0.1:9090:\r\nconnection refused\nretry\r"); got != "dial tcp 127.0.0.1:9090: connection refused retry " {
		t.Fatalf("line breaks survived: %q", got)
	}
	long := strings.Repeat("a", 300)
	if got := BoundCollectorDetail(long); got != long[:CollectorDetailMaxBytes] {
		t.Fatalf("ascii cut to %d bytes, want %d", len(got), CollectorDetailMaxBytes)
	}
	// A three-byte rune straddles the limit: bytes 255, 256 and 257.
	straddle := strings.Repeat("a", CollectorDetailMaxBytes-1) + "网" + "tail"
	got := BoundCollectorDetail(straddle)
	if len(got) > CollectorDetailMaxBytes || !utf8.ValidString(got) {
		t.Fatalf("cut split a rune or overran: %d bytes, valid=%v", len(got), utf8.ValidString(got))
	}
	if got != strings.Repeat("a", CollectorDetailMaxBytes-1) {
		t.Fatalf("cut kept part of the straddling rune: %q", got[len(got)-4:])
	}
}

// ShedConnections is a subset of Dropped on the wire (I3), and a batch that
// carries only it is a real report, not the zero batch.
func TestShedConnectionsRoundTripAndBareCheck(t *testing.T) {
	b := TraceBatch{
		NodeID:          "legend-sg",
		Dropped:         42,
		ShedConnections: 40,
		CapturedAt:      traceTestTime(t, "2026-10-05T10:00:01Z"),
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"node_id":"legend-sg","dropped":42,"shed_connections":40,"captured_at":"2026-10-05T10:00:01Z"}`
	if string(raw) != want {
		t.Fatalf("batch wire shape:\n got %s\nwant %s", raw, want)
	}
	var back TraceBatch
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.ShedConnections != 40 || back.Dropped != 42 {
		t.Fatalf("round trip lost counters: %+v", back)
	}

	if !(TraceBatch{}).SourceLooksBare() {
		t.Fatal("the zero batch must look bare")
	}
	if (TraceBatch{ShedConnections: 1}).SourceLooksBare() {
		t.Fatal("a batch carrying only shed connections looked bare")
	}
}

func TestEvidenceSettingsWireNames(t *testing.T) {
	// Today's values, as a server that has stored nothing returns them (I7).
	s := EvidenceSettings{
		TraceDBMaxBytes:    2 << 30,
		RecordTTLSeconds:   14 * 86400,
		LineTTLSeconds:     7 * 86400,
		Rollup5mTTLSeconds: 90 * 86400,
		RawSourceMaxBytes:  64 << 20,
	}
	raw, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"trace_db_max_bytes":2147483648,"record_ttl_seconds":1209600,"line_ttl_seconds":604800,` +
		`"rollup_5m_ttl_seconds":7776000,"raw_source_max_bytes":67108864,"version":0}`
	if string(raw) != want {
		t.Fatalf("default settings wire shape:\n got %s\nwant %s", raw, want)
	}

	s.Version = 3
	s.UpdatedAt = traceTestTime(t, "2026-10-05T11:00:00Z")
	s.UpdatedBy = "admin"
	raw, err = json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	want = `{"trace_db_max_bytes":2147483648,"record_ttl_seconds":1209600,"line_ttl_seconds":604800,` +
		`"rollup_5m_ttl_seconds":7776000,"raw_source_max_bytes":67108864,"version":3,` +
		`"updated_at":"2026-10-05T11:00:00Z","updated_by":"admin"}`
	if string(raw) != want {
		t.Fatalf("saved settings wire shape:\n got %s\nwant %s", raw, want)
	}
	var back EvidenceSettings
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back != s {
		t.Fatalf("round trip:\n got %+v\nwant %+v", back, s)
	}
}
