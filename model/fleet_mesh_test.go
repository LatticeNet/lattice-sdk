package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// Design 32 R1: the fields the migration adds are additive on the wire, so
// a reader that predates them decodes the same object.
func TestMigrationFieldsAreAdditive(t *testing.T) {
	raw, err := json.Marshal(Monitor{ID: "mon_lat_a", ManagedBy: MonitorManagedLatency})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "check_definition_id") {
		t.Fatalf("an unowned monitor carries the definition key: %s", raw)
	}
	raw, err = json.Marshal(Monitor{ID: "mon_lat_a", ManagedBy: MonitorManagedLatency, CheckDefinitionID: CheckFleetMeshID})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"managed_by":"latency","check_definition_id":"chk_fleet_mesh"`) {
		t.Fatalf("an adopted monitor = %s", raw)
	}
	raw, err = json.Marshal(LatencyProbeConfig{Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "migrated") {
		t.Fatalf("an unmigrated path set = %s", raw)
	}
	raw, err = json.Marshal(CheckDefinition{ID: "chk_a", CheckDefinitionSpec: CheckDefinitionSpec{Type: CheckMethodAuto, ExcludedPairs: []LatencyPair{{Source: "a", Target: "b"}}}, Adopted: []CheckAdoption{{Method: "tcp", TargetNode: "b", MonitorID: "mon_lat_b"}}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"type":"auto"`, `"excluded_pairs":[{"source":"a","target":"b"}]`, `"adopted":[{"method":"tcp","target_node":"b","monitor_id":"mon_lat_b"}]`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("definition = %s, want %s", raw, want)
		}
	}
}

// Design 32 R2: configuration facts are not paths; health is.
func TestPathMeasurement(t *testing.T) {
	for reason, want := range map[string]string{
		PathReasonNotProbeable: PathSkipped, PathReasonAgentTooOld: PathSkipped, PathReasonICMPNotPermitted: PathSkipped,
		PathReasonPacketBudget: PathSkipped, PathReasonBeaconSourcePending: PathSkipped, PathReasonBeaconNotEnabled: PathSkipped,
		PathReasonFirewallPending: PathSkipped, PathReasonRefusedByNode: PathSkipped,
		PathReasonSourcePaused: PathPaused,
		PathReasonNoData:       PathMeasured, PathReasonAgentOffline: PathMeasured, PathReasonICMPFiltered: PathMeasured,
		PathReasonDestinationRefused: PathMeasured, PathReasonBeaconNotListening: PathMeasured,
	} {
		if got := PathMeasurement(PathStateUnknown, reason); got != want {
			t.Fatalf("unknown %s = %q, want %q", reason, got, want)
		}
	}
	if got := PathMeasurement(PathStateDown, PathReasonNotProbeable); got != PathMeasured {
		t.Fatalf("a down path = %q", got)
	}
}
