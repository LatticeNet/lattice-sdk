package model

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"
)

// Every bound is inclusive, a value just past one is refused naming its
// field, and NaN, infinities and negatives are refused whatever the field.
func TestValidateDegradedRule(t *testing.T) {
	if err := ValidateDegradedRule(nil); err != nil {
		t.Fatalf("nil rule: %v", err)
	}
	if err := ValidateDegradedRule(&MonitorDegradedRule{}); err != nil {
		t.Fatalf("zero rule: %v", err)
	}
	type field struct {
		name   string
		set    func(*MonitorDegradedRule, float64)
		lo, hi float64
		step   float64
	}
	fields := []field{
		{"loss_percent", func(r *MonitorDegradedRule, v float64) { r.LossPercent = v }, 0.5, 50, 0.1},
		{"loss_factor", func(r *MonitorDegradedRule, v float64) { r.LossFactor = v }, 1.2, 10, 0.1},
		{"latency_factor", func(r *MonitorDegradedRule, v float64) { r.LatencyFactor = v }, 1.2, 10, 0.1},
		{"latency_margin_ms", func(r *MonitorDegradedRule, v float64) { r.LatencyMarginMs = v }, 5, 1000, 1},
	}
	for _, f := range fields {
		for _, tc := range []struct {
			v  float64
			ok bool
		}{
			{f.lo, true},
			{f.hi, true},
			{f.lo - f.step, false},
			{f.hi + f.step, false},
			{(f.lo + f.hi) / 2, true},
			{-1, false},
			{math.NaN(), false},
			{math.Inf(1), false},
			{math.Inf(-1), false},
		} {
			var r MonitorDegradedRule
			f.set(&r, tc.v)
			err := ValidateDegradedRule(&r)
			if (err == nil) != tc.ok {
				t.Errorf("%s = %v: err %v, want ok %v", f.name, tc.v, err, tc.ok)
			}
			if err != nil && !strings.Contains(err.Error(), "degraded."+f.name) {
				t.Errorf("%s = %v: %q does not name the field", f.name, tc.v, err)
			}
		}
	}
}

// The stored form rounds to one place (the margin to a whole millisecond),
// writes a default as zero and is nil when every field is the default.
func TestCanonicalDegradedRule(t *testing.T) {
	if CanonicalDegradedRule(nil) != nil {
		t.Fatal("nil must stay nil")
	}
	if got := CanonicalDegradedRule(&MonitorDegradedRule{}); got != nil {
		t.Fatalf("an empty rule stores %+v, want nil", got)
	}
	defaults := &MonitorDegradedRule{LossPercent: 2, LossFactor: 2, LatencyFactor: 2, LatencyMarginMs: 30}
	if got := CanonicalDegradedRule(defaults); got != nil {
		t.Fatalf("an editor echoing the defaults stores %+v, want nil", got)
	}
	got := CanonicalDegradedRule(&MonitorDegradedRule{LossPercent: 3.14, LossFactor: 2.04, LatencyFactor: 1.26, LatencyMarginMs: 44.6})
	want := MonitorDegradedRule{LossPercent: 3.1, LossFactor: 0, LatencyFactor: 1.3, LatencyMarginMs: 45}
	if got == nil || *got != want {
		t.Fatalf("canonical = %+v, want %+v (2.04 rounds to the default 2 and is stored as zero)", got, want)
	}
	in := MonitorDegradedRule{LossPercent: 5}
	if out := CanonicalDegradedRule(&in); out == &in || out.LossPercent != 5 {
		t.Fatalf("canonical must copy, got %p for %p", out, &in)
	}
}

func TestDegradedRuleEffective(t *testing.T) {
	var nilRule *MonitorDegradedRule
	want := MonitorDegradedRule{LossPercent: 2, LossFactor: 2, LatencyFactor: 2, LatencyMarginMs: 30}
	if got := nilRule.Effective(); got != want {
		t.Fatalf("nil effective = %+v", got)
	}
	got := (&MonitorDegradedRule{LatencyMarginMs: 50}).Effective()
	want.LatencyMarginMs = 50
	if got != want {
		t.Fatalf("effective = %+v, want %+v", got, want)
	}
}

// The triggers take the larger arm: a fast path's margin, a slow path's
// factor, and the loss floor when the baseline lost nothing.
func TestDegradedTriggers(t *testing.T) {
	def := MonitorDegradedRule{}
	for _, tc := range []struct {
		base, want float64
	}{
		{20, 50},   // 2 x 20 = 40 < 20 + 30
		{100, 200}, // 2 x 100 = 200 > 100 + 30
		{30, 60},   // both arms agree
		{0, 30},
	} {
		if got := DegradedLatencyTrigger(def, tc.base); got != tc.want {
			t.Errorf("latency trigger for base %v = %v, want %v", tc.base, got, tc.want)
		}
	}
	for _, tc := range []struct {
		base, want float64
	}{
		{0, 0.02},     // the floor
		{0.004, 0.02}, // 2 x 0.4% is under the floor
		{0.05, 0.1},   // 2 x 5%
	} {
		if got := DegradedLossTrigger(def, tc.base); math.Abs(got-tc.want) > 1e-12 {
			t.Errorf("loss trigger for base %v = %v, want %v", tc.base, got, tc.want)
		}
	}
	custom := MonitorDegradedRule{LossPercent: 5, LossFactor: 3, LatencyFactor: 1.5, LatencyMarginMs: 100}
	if got := DegradedLatencyTrigger(custom, 100); got != 200 {
		t.Errorf("custom latency trigger = %v, want 200 (100 + 100 over 1.5 x 100)", got)
	}
	if got := DegradedLossTrigger(custom, 0.03); math.Abs(got-0.09) > 1e-12 {
		t.Errorf("custom loss trigger = %v, want 0.09", got)
	}
}

func TestEffectiveMonitorAlert(t *testing.T) {
	for _, tc := range []struct {
		alert     string
		generated bool
		want      string
	}{
		{"", false, MonitorAlertDown},
		{"", true, MonitorAlertOff},
		{"bogus", false, MonitorAlertDown},
		{"bogus", true, MonitorAlertOff},
		{MonitorAlertOff, false, MonitorAlertOff},
		{MonitorAlertOff, true, MonitorAlertOff},
		{MonitorAlertDown, false, MonitorAlertDown},
		{MonitorAlertDown, true, MonitorAlertDown},
		{MonitorAlertDownAndDegraded, false, MonitorAlertDownAndDegraded},
		{MonitorAlertDownAndDegraded, true, MonitorAlertDownAndDegraded},
	} {
		if got := EffectiveMonitorAlert(tc.alert, tc.generated); got != tc.want {
			t.Errorf("EffectiveMonitorAlert(%q, %v) = %q, want %q", tc.alert, tc.generated, got, tc.want)
		}
	}
}

// A check and a path set without the M3 fields encode exactly as they did,
// and decode back to the same value.
func TestM3FieldsLeaveStoredShapesAlone(t *testing.T) {
	at := time.Date(2026, 10, 16, 8, 0, 0, 0, time.UTC)
	mon := Monitor{ID: "mon_x", Name: "x", Type: MonitorTypeTCP, Target: "203.0.113.1:443", IntervalSec: 30, TimeoutSec: 5,
		NodeIDs: []string{"n1"}, Enabled: true, Alert: MonitorAlertDown, AlertAfter: 3, Version: 2, CreatedAt: at, UpdatedAt: at}
	raw, err := json.Marshal(mon)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"id":"mon_x","name":"x","type":"tcp","target":"203.0.113.1:443","interval_sec":30,"timeout_sec":5,"assign_all":false,"node_ids":["n1"],"enabled":true,"alert":"down","alert_after":3,"version":2,"created_at":"2026-10-16T08:00:00Z","updated_at":"2026-10-16T08:00:00Z"}`
	if string(raw) != want {
		t.Fatalf("monitor = %s\nwant %s", raw, want)
	}
	var back Monitor
	if err := json.Unmarshal(raw, &back); err != nil || back.Degraded != nil {
		t.Fatalf("decoded %+v, %v", back, err)
	}
	cfg := LatencyProbeConfig{Enabled: true, IntervalSec: 60, TimeoutSec: 5, Sources: []string{"n1"}, AutoTargets: true, Version: 4}
	raw, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want = `{"enabled":true,"interval_sec":60,"timeout_sec":5,"sources":["n1"],"auto_targets":true,"version":4}`
	if string(raw) != want {
		t.Fatalf("path set = %s\nwant %s", raw, want)
	}
	// Set, they round trip.
	mon.Alert = MonitorAlertDownAndDegraded
	mon.Degraded = &MonitorDegradedRule{LatencyMarginMs: 50}
	cfg.Alert, cfg.AlertAfter, cfg.Degraded = MonitorAlertDown, 4, &MonitorDegradedRule{LossPercent: 5}
	for name, v := range map[string]any{"monitor": mon, "config": cfg} {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		for _, field := range []string{`"degraded":{`, `"alert":"`} {
			if !strings.Contains(string(raw), field) {
				t.Errorf("%s lacks %s: %s", name, field, raw)
			}
		}
	}
	raw, _ = json.Marshal(cfg)
	var cfgBack LatencyProbeConfig
	if err := json.Unmarshal(raw, &cfgBack); err != nil || cfgBack.AlertAfter != 4 || cfgBack.Degraded == nil || cfgBack.Degraded.LossPercent != 5 {
		t.Fatalf("path set back = %+v, %v", cfgBack, err)
	}
}

// An edit tells absent (keep) from an empty object (reset to the defaults).
func TestMonitorUpdateDegradedAbsentNullAndEmpty(t *testing.T) {
	for body, wantSet := range map[string]bool{
		`{"id":"m","version":1}`:                                 false,
		`{"id":"m","version":1,"degraded":null}`:                 false,
		`{"id":"m","version":1,"degraded":{}}`:                   true,
		`{"id":"m","version":1,"degraded":{"loss_percent":3.5}}`: true,
	} {
		var upd MonitorUpdate
		if err := json.Unmarshal([]byte(body), &upd); err != nil {
			t.Fatal(err)
		}
		if (upd.Degraded != nil) != wantSet {
			t.Errorf("%s: degraded set = %v, want %v", body, upd.Degraded != nil, wantSet)
		}
	}
}

// The two read fields an M3 server always sends are present as null when
// there is nothing to say; the cell's degradation and the previous series
// stay off the wire until set.
func TestM3ReadFieldsShape(t *testing.T) {
	raw, err := json.Marshal(PathMatrix{Window: PathWindowHour})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"degraded_at":null`) {
		t.Fatalf("matrix lacks degraded_at: %s", raw)
	}
	raw, err = json.Marshal(PathSeries{Window: PathWindowHour})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"baseline":null`) || strings.Contains(string(raw), `"previous"`) {
		t.Fatalf("series = %s", raw)
	}
	raw, err = json.Marshal(PathCell{State: PathStateUp})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), `"degraded"`) {
		t.Fatalf("an up cell carries degraded: %s", raw)
	}
	since := time.Date(2026, 10, 16, 14, 2, 0, 0, time.UTC)
	cell := PathCell{State: PathStateDegraded, Reason: PathReasonDegradedLoss, Degraded: &PathDegradation{
		Since: since, EvaluatedAt: since.Add(time.Minute),
		Loss: &PathLossEvidence{Value: 0.042, Baseline: 0.004, Trigger: 0.02, Sent: 290, Lost: 12},
	}}
	raw, err = json.Marshal(cell)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"state":"degraded"`, `"reason":"degraded_loss"`, `"since":"2026-10-16T14:02:00Z"`, `"loss":{"value":0.042,"baseline":0.004,"trigger":0.02,"sent":290,"lost":12}`} {
		if !strings.Contains(string(raw), field) {
			t.Errorf("degraded cell lacks %s: %s", field, raw)
		}
	}
	if strings.Contains(string(raw), "clearing_since") || strings.Contains(string(raw), `"latency":{`) {
		t.Errorf("degraded cell carries an unset part: %s", raw)
	}
	b := PathBaseline{Hours: 14, Rule: (&MonitorDegradedRule{}).Effective()}
	raw, err = json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"ready":false`, `"p50_ms":null`, `"trigger_p50_ms":null`, `"trigger_loss":null`, `"rule":{"loss_percent":2,"loss_factor":2,"latency_factor":2,"latency_margin_ms":30}`} {
		if !strings.Contains(string(raw), field) {
			t.Errorf("baseline lacks %s: %s", field, raw)
		}
	}
	v := 64.0
	raw, err = json.Marshal(PathPreviousSeries{OffsetSeconds: 3600, StepSeconds: 60, P50Ms: []*float64{nil, &v}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"p50_ms":[null,64]`) {
		t.Fatalf("previous = %s", raw)
	}
}
