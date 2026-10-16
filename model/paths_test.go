package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// What was not measured is an explicit null, so a console tells a gap from
// a zero without guessing at absent keys.
func TestPathShapesWriteNullsForWhatWasNotMeasured(t *testing.T) {
	at := time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)
	raw, err := json.Marshal(PathBucket{T: at, Expected: 5})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"t":"2026-10-16T08:00:00Z","n":0,"expected":5,"fail":0,"min_ms":null,"p50_ms":null,"p95_ms":null,"max_ms":null,"jitter_ms":null,"loss":null}`
	if string(raw) != want {
		t.Fatalf("bucket = %s\nwant %s", raw, want)
	}
	raw, err = json.Marshal(PathCell{Source: "a", State: PathStateUnknown, Reason: PathReasonNoData})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"prev":null`, `"last_at":null`, `"p50_ms":null`, `"loss":null`, `"target_node":""`, `"reason":"no_data"`} {
		if !strings.Contains(string(raw), field) {
			t.Fatalf("cell %s lacks %s", raw, field)
		}
	}
}

// The new monitor fields stay off the wire until they are set, so agents and
// older consoles see the monitor they always saw.
func TestMonitorEditFieldsOmittedUntilSet(t *testing.T) {
	raw, err := json.Marshal(Monitor{ID: "mon_x", Type: MonitorTypeTCP})
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"paused_node_ids", "alert", "version"} {
		if strings.Contains(string(raw), field) {
			t.Fatalf("%s present on a monitor that never set it: %s", field, raw)
		}
	}
	var upd MonitorUpdate
	if err := json.Unmarshal([]byte(`{"id":"mon_x","version":3,"paused_node_ids":[],"name":null}`), &upd); err != nil {
		t.Fatal(err)
	}
	if upd.PausedNodeIDs == nil || len(*upd.PausedNodeIDs) != 0 || upd.Name != nil || upd.NodeIDs != nil {
		t.Fatalf("update = %+v: an empty list must read as set, null and absent as unchanged", upd)
	}
}
