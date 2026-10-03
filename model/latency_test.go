package model

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// An unknown window has to read as unknown on the wire: a zero p50 would be
// drawn as the fastest pair in the fleet, and a zero loss as a clean path.
func TestLatencyStatsOmitsWhatWasNotMeasured(t *testing.T) {
	raw, err := json.Marshal(LatencyStats{Expected: 60})
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	for _, absent := range []string{"p50_ms", "p95_ms", "loss"} {
		if strings.Contains(got, absent) {
			t.Fatalf("%s present in an unmeasured window: %s", absent, got)
		}
	}
	p50, loss := 0.0, 0.0
	raw, err = json.Marshal(LatencyStats{Samples: 3, Expected: 60, P50Ms: &p50, Loss: &loss})
	if err != nil {
		t.Fatal(err)
	}
	if got := string(raw); !strings.Contains(got, `"p50_ms":0`) || !strings.Contains(got, `"loss":0`) {
		t.Fatalf("a measured zero must stay on the wire: %s", got)
	}
}

// A bucket carries its stats beside its instant, not under a nested key.
func TestLatencyBucketFlattensItsStats(t *testing.T) {
	at := time.Date(2026, 10, 3, 1, 5, 0, 0, time.UTC)
	raw, err := json.Marshal(LatencyBucket{At: at, LatencyStats: LatencyStats{Samples: 5, Failures: 1, Expected: 5}})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"at":"2026-10-03T01:05:00Z","samples":5,"failures":1,"expected":5}`
	if string(raw) != want {
		t.Fatalf("bucket JSON = %s, want %s", raw, want)
	}
}

// An operator's monitor carries no managed_by, so an older reader sees the
// same record it always did.
func TestMonitorManagedByIsOmittedWhenEmpty(t *testing.T) {
	raw, err := json.Marshal(Monitor{ID: "mon_1", Type: MonitorTypeTCP})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "managed_by") {
		t.Fatalf("managed_by present on an operator monitor: %s", raw)
	}
	raw, err = json.Marshal(Monitor{ID: "mon_lat_x", Type: MonitorTypeTCP, ManagedBy: MonitorManagedLatency})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"managed_by":"latency"`) {
		t.Fatalf("managed_by missing on a generated monitor: %s", raw)
	}
}
