package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// zeroTimeOmitted names, per type, every time.Time member whose zero value
// means "never" or "not set" and must therefore be absent from the wire.
// omitempty never omits a time.Time (a struct is never empty), so each of
// these used to ship "0001-01-01T00:00:00Z", which a console reads as a real
// date. A path with a dot names a member of a nested object.
var zeroTimeOmitted = []struct {
	name  string
	value any
	keys  []string
}{
	{"Token", Token{}, []string{"revoked_at"}},
	{"Node", Node{}, []string{
		"token_last_used_at", "last_seen", "online_since", "disabled_at",
		"metrics.collected_at", "host_facts.boot_time", "host_facts.reported_at",
		"agent_debug.updated_at", "trace.updated_at",
	}},
	{"Node with launch, ip and geo", Node{AgentLaunch: &AgentLaunchConfig{}, IPConfig: &NodeIPConfig{}, Geo: &NodeGeo{}}, []string{
		"agent_launch.updated_at", "ip_config.updated_at", "geo.updated_at",
	}},
	{"MachineProfile", MachineProfile{}, []string{"purchased_at", "next_renewal"}},
	{"DNSDeployment", DNSDeployment{}, []string{"cert_not_after", "last_applied_at", "last_published_at"}},
	{"GeoRouting", GeoRouting{}, []string{"last_applied_at", "last_delegated_at"}},
	{"NetPolicy", NetPolicy{}, []string{"last_applied_at"}},
	{"NodeGuardBinding", NodeGuardBinding{}, []string{"last_applied_at"}},
	{"WGExternalPeer", WGExternalPeer{}, []string{"last_issued_at"}},
	{"ProxyUser", ProxyUser{}, []string{"expires_at", "last_seen_at"}},
	{"ProxyNodeProfile", ProxyNodeProfile{}, []string{
		"last_apply_at", "usage_collector_checked_at", "usage_collector_last_ok_at", "usage_collector_last_error_at",
	}},
	{"ProxyUsageSnapshot", ProxyUsageSnapshot{}, []string{"collector_checked_at"}},
	{"SingBoxRuntime", SingBoxRuntime{}, []string{"started_at", "probed_at"}},
	{"Task", Task{TargetLeases: map[string]TaskLease{"node_1": {LeaseID: "lease_1"}}}, []string{
		"started_at", "finished_at", "target_leases.node_1.started_at",
	}},
	{"TerminalSession", TerminalSession{}, []string{"opened_at", "closed_at", "last_seen"}},
	{"StorageAccessToken", StorageAccessToken{}, []string{"revoked_at", "last_used_at"}},
	{"PluginInstallation", PluginInstallation{}, []string{"verified_at", "installed_at", "activated_at", "disabled_at"}},
	{"DDNSProfile", DDNSProfile{}, []string{"last_run_at"}},
}

func lookupJSONPath(t *testing.T, doc map[string]any, path string) (any, bool) {
	t.Helper()
	parts := strings.Split(path, ".")
	var cur any = doc
	for _, part := range parts {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = obj[part]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func TestZeroTimesAreAbsentFromTheWire(t *testing.T) {
	for _, tc := range zeroTimeOmitted {
		raw, err := json.Marshal(tc.value)
		if err != nil {
			t.Fatalf("%s: marshal: %v", tc.name, err)
		}
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: unmarshal: %v", tc.name, err)
		}
		for _, key := range tc.keys {
			if v, ok := lookupJSONPath(t, doc, key); ok {
				t.Errorf("%s: zero %s is on the wire as %v", tc.name, key, v)
			}
		}
	}
}

// A never-reported node and an unfinished task are the two shapes the
// console renders most; neither may carry year 1 anywhere, including the
// nested metrics, host facts and debug policy every node embeds.
func TestNeverReportedNodeAndUnfinishedTaskCarryNoYearOne(t *testing.T) {
	created := time.Date(2026, 10, 17, 9, 30, 0, 0, time.UTC)
	for name, value := range map[string]any{
		"node": Node{ID: "node_1", Name: "fresh", CreatedAt: created},
		"task": Task{ID: "task_1", Status: "pending", Targets: []string{"node_1"}, CreatedAt: created,
			TargetLeases: map[string]TaskLease{"node_1": {LeaseID: "lease_1"}}},
	} {
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if strings.Contains(string(raw), "0001-01-01") {
			t.Errorf("%s carries year 1: %s", name, raw)
		}
	}
}

// A set time still travels and reads back exactly, and both an absent key and
// the 0001 string an older server sends decode to the zero time, so a reader
// built on these types needs no special case for either.
func TestOmittedTimesRoundTrip(t *testing.T) {
	at := time.Date(2026, 10, 17, 9, 30, 0, 123456789, time.UTC)
	raw, err := json.Marshal(Task{ID: "task_1", StartedAt: at, FinishedAt: at.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	var back Task
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !back.StartedAt.Equal(at) || !back.FinishedAt.Equal(at.Add(time.Minute)) {
		t.Fatalf("round trip = %v / %v, want %v / %v", back.StartedAt, back.FinishedAt, at, at.Add(time.Minute))
	}
	for _, body := range []string{
		`{"id":"node_1"}`,
		`{"id":"node_1","last_seen":"0001-01-01T00:00:00Z","metrics":{"collected_at":"0001-01-01T00:00:00Z"}}`,
	} {
		var node Node
		if err := json.Unmarshal([]byte(body), &node); err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if !node.LastSeen.IsZero() || !node.Metrics.CollectedAt.IsZero() {
			t.Fatalf("%s: last_seen %v, collected_at %v, want zero", body, node.LastSeen, node.Metrics.CollectedAt)
		}
	}
}
