package model

import (
	"fmt"
	"math"
	"time"
)

// Monitoring paths (lattice docs design 29).
//
// A path is one source probing one target with one method: a (monitor,
// source node) pair, which is how the control plane already keys results,
// rows and rollups. Generated latency checks contribute one path per
// (source, target node); an operator's check contributes one path per
// assigned source, and a tls check one path whose source is the control
// plane (an empty node id).
//
// History has three tiers: raw results (MonitorRawRowsPerPath per path),
// five-minute rollups kept MonitorSettings.FineRetentionDays, and one-hour
// rollups kept MonitorCoarseRetentionDays.

// Path windows, shared by the matrix and the series reads.
const (
	PathWindowHour      = "1h"
	PathWindowSixHours  = "6h"
	PathWindowDay       = "24h"
	PathWindowThreeDays = "3d"
	PathWindowWeek      = "7d"
	PathWindowTwoWeeks  = "14d"
)

// Path states (PathCell.State).
const (
	PathStateUp   = "up"
	PathStateDown = "down"
	// PathStateDegraded: the path answers, but its loss or its median
	// latency is well above its own last week (design 29 D13). The control
	// plane judges it on a schedule; PathCell.Reason names the arms that
	// held and PathCell.Degraded carries the evidence.
	PathStateDegraded = "degraded"
	// PathStateUnknown: no current result when one was expected. It is
	// never drawn as up; PathCell.Reason says why when the control plane
	// knows.
	PathStateUnknown = "unknown"
)

// Why a path reads unknown (PathCell.Reason).
const (
	// PathReasonAgentOffline: the source node is not reporting.
	PathReasonAgentOffline = "agent_offline"
	// PathReasonSourcePaused: the path is paused, by the check's paused
	// sources, a disabled check, a disabled pair of the latency
	// configuration or that configuration switched off.
	PathReasonSourcePaused = "source_paused"
	// PathReasonNotProbeable: the target node serves nothing the method
	// may dial (for tcp, no public TCP line).
	PathReasonNotProbeable = "not_probeable"
	// PathReasonNoData: a result was expected and none is current.
	PathReasonNoData = "no_data"
	// PathReasonAgentTooOld: the source's agent does not run the check's
	// kind (Node.ProbeMethods), so the control plane does not hand it the
	// check. An agent handed a kind it does not know reports this reason
	// instead of a failure.
	PathReasonAgentTooOld = "agent_too_old"
	// PathReasonICMPNotPermitted: the source's kernel refuses unprivileged
	// echo sockets to the agent's group (net.ipv4.ping_group_range).
	// Reported by the agent in Node.ProbeRefusals and on results.
	PathReasonICMPNotPermitted = "icmp_not_permitted"
	// PathReasonICMPFiltered: every echo of every recent run was lost on a
	// path that has never had an echo back, so the target or a provider
	// likely filters ICMP. Judged by the control plane; once a path has
	// succeeded, all-loss runs read down instead.
	PathReasonICMPFiltered = "icmp_filtered"
	// PathReasonDestinationRefused: the agent refused to dial the address
	// the target resolved to (MonitorDestinationRefused), or a check with
	// secret headers asked for a request its rules forbid.
	PathReasonDestinationRefused = "destination_refused"
	// PathReasonPacketBudget: the control plane paused a check
	// definition's path because its source would send the target address
	// more than MonitorPacketsPerSecondMax packets a second across its
	// checks (design 32 D1). It resumes once the budget has room.
	PathReasonPacketBudget = "packet_budget"
)

// Whether a path is measured (design 32 R2). A check skips a pair when the
// method has nothing to dial on the target, the source cannot run the method
// or its host refuses it, a beacon or firewall approval is pending, or the
// pair is over the packet budget; a pair is paused when its check or its
// source is paused or its target left the set. Those are facts about
// configuration, not the health of a path: a console leaves them out of
// its default graph, list and counts and shows them on request. Every other
// state, unknown included, is a measured path.
const (
	PathMeasured = ""
	PathSkipped  = "skipped"
	PathPaused   = "paused"
)

// PathMeasurement is whether a path in state for reason is measured,
// skipped or paused (PathMeasured, PathSkipped, PathPaused).
func PathMeasurement(state, reason string) string {
	if state != PathStateUnknown {
		return PathMeasured
	}
	switch reason {
	case PathReasonNotProbeable, PathReasonAgentTooOld, PathReasonICMPNotPermitted, PathReasonPacketBudget,
		PathReasonBeaconNotEnabled, PathReasonFirewallPending, PathReasonBeaconSourcePending, PathReasonRefusedByNode:
		return PathSkipped
	case PathReasonSourcePaused:
		return PathPaused
	}
	return PathMeasured
}

// Monitor history retention.
const (
	MonitorFineRetentionDefaultDays = 7
	MonitorFineRetentionMinDays     = 3
	MonitorFineRetentionMaxDays     = 14
	MonitorCoarseRetentionDays      = 35
	MonitorRawRowsPerPath           = 1440
)

// MonitorSettings is the operator's monitor history setting, and the body
// of POST /api/monitors/settings/update. A save names the version it was
// read at; a stale one is refused.
type MonitorSettings struct {
	// FineRetentionDays is how long five-minute rollups are kept,
	// MonitorFineRetentionMinDays to MonitorFineRetentionMaxDays.
	FineRetentionDays int       `json:"fine_retention_days"`
	Version           int64     `json:"version"`
	UpdatedAt         time.Time `json:"updated_at,omitzero"`
	UpdatedBy         string    `json:"updated_by,omitempty"`
}

// MonitorSettingsView answers GET /api/monitors/settings: the setting in
// force (the default until one is saved, at version zero), the fixed
// tiers, and the history's size. MeasuredBytes is what the monitor history
// occupies now, read from the store's page statistics; ProjectedBytes is
// what it will occupy once every current path has filled every tier at the
// setting shown. The store's file reuses freed pages but never shrinks, so
// lowering the retention frees space for reuse, not disk.
type MonitorSettingsView struct {
	Version             int64     `json:"version"`
	FineRetentionDays   int       `json:"fine_retention_days"`
	FineMinDays         int       `json:"fine_min_days"`
	FineMaxDays         int       `json:"fine_max_days"`
	CoarseRetentionDays int       `json:"coarse_retention_days"`
	RawRowsPerPath      int       `json:"raw_rows_per_path"`
	Paths               int       `json:"paths"`
	MeasuredBytes       int64     `json:"measured_bytes"`
	ProjectedBytes      int64     `json:"projected_bytes"`
	UpdatedAt           time.Time `json:"updated_at,omitzero"`
	UpdatedBy           string    `json:"updated_by,omitempty"`
}

// PathSeries is one path over one window (GET /api/monitors/series). A pair
// with a target node is asked for as source and target_node, plus check to
// choose which check's series when several measure the pair (a definition
// id, or a single check's monitor id); without check the first check on the
// pair answers, measured checks before paused ones, then by name. Check
// names the check that answered. Every
// step is present: a bucket with N zero and Expected above zero is a gap,
// which reads as unknown, never interpolated. A window holds as many steps as
// fit in its span (one hour at a one-minute step is 60), the last of them
// the step in progress at To; From is the first step's start.
type PathSeries struct {
	Check       string    `json:"check,omitempty"`
	Window      string    `json:"window"`
	StepSeconds int       `json:"step_seconds"`
	From        time.Time `json:"from"`
	To          time.Time `json:"to"`
	// MethodChanges is the method in force from the first bucket with
	// data, then every bucket where it changed. A path series addressed by
	// (source, target node) joins every generated check for that pair, so
	// one line can cross a method switch.
	MethodChanges []PathMethodChange `json:"method_changes"`
	Buckets       []PathBucket       `json:"buckets"`
	// Baseline is the degraded rule's guide for the pair the path is
	// judged on now (design 29 D13). It is always on the wire from a
	// server that judges degraded, null for a tls check or a generated
	// path with no current check, so a console tells the two servers
	// apart by the key.
	Baseline *PathBaseline `json:"baseline"`
	// Previous is the same path one window earlier, present only when the
	// request asked for it (compare=previous).
	Previous *PathPreviousSeries `json:"previous,omitempty"`
}

// PathMethodChange marks where a path's method begins.
type PathMethodChange struct {
	T      time.Time `json:"t"`
	Method string    `json:"method"`
}

// PathBucket is one step of a series. N counts runs and Fail the failed
// ones; Expected is how many runs the interval produces over the step. The
// step in progress (the last, which ends after the series' To) expects the
// runs certainly due over the part that has passed, and never fewer than it
// has heard: a run may land before its share of the interval has passed, and
// one that did was expected. The latency figures come from the
// successful runs and are null when none succeeded; percentiles are read
// off a histogram whose bins are about 9 percent wide. JitterMs is the mean
// absolute difference between consecutive successful runs; Loss is Fail
// over N, null when N is zero.
//
// Sent and Lost count probes: every echo of a multi-packet run (icmp) and
// one per run of a single-probe kind (tcp, http), from design 29 M2a on.
// Where Sent is above zero Loss is Lost over Sent; buckets written before
// M2a carry zero and Loss stays Fail over N. A multi-packet run counts once
// in N and in the latency figures, with its median RTT.
type PathBucket struct {
	T        time.Time `json:"t"`
	N        int       `json:"n"`
	Expected int       `json:"expected"`
	Fail     int       `json:"fail"`
	MinMs    *float64  `json:"min_ms"`
	P50Ms    *float64  `json:"p50_ms"`
	P95Ms    *float64  `json:"p95_ms"`
	MaxMs    *float64  `json:"max_ms"`
	JitterMs *float64  `json:"jitter_ms"`
	Loss     *float64  `json:"loss"`
	Sent     int       `json:"sent,omitempty"`
	Lost     int       `json:"lost,omitempty"`
}

// PathMatrix answers GET /api/monitors/paths: every path the caller may
// read (both its source and its target node), with its state now and its
// figures over the window. ObservedAt is when the states were judged. The
// window figures cover the whole buckets of the window's tier (one minute
// for 1h, five minutes for 6h and 24h, one hour from 3d up) that fit in its
// span and end where the bucket in progress begins; they are cached until
// that bucket closes.
//
// DegradedAt is when the degraded evaluator last ran, null before its first
// run after a start. A server that judges degraded always sends the key, so
// a console shows the degraded state only when it is present.
//
// BeaconReplans are the nodes the caller may read whose beacon needs a
// change plan before its sources match what uses it, always present and
// empty when none does.
type PathMatrix struct {
	Window        string         `json:"window"`
	ObservedAt    time.Time      `json:"observed_at"`
	DegradedAt    *time.Time     `json:"degraded_at"`
	Sources       []PathSource   `json:"sources"`
	Targets       []PathTarget   `json:"targets"`
	Paths         []PathCell     `json:"paths"`
	BeaconReplans []BeaconReplan `json:"beacon_replans"`
}

// PathSource is a node some path runs from. The control plane, the source
// of tls checks, appears with an empty node id.
type PathSource struct {
	NodeID string `json:"node_id"`
	Name   string `json:"name"`
	Region string `json:"region"`
}

// PathTarget is a node some path reaches. Region is a LatencyRegion*
// value and Country the node's ISO country code.
type PathTarget struct {
	NodeID  string `json:"node_id"`
	Name    string `json:"name"`
	Region  string `json:"region"`
	Country string `json:"country"`
}

// PathCell is one path. TargetNode is the node a generated check reaches,
// or the node an operator check's address resolves to, else empty; Target
// is what the method dials. MonitorID is empty for a generated path whose
// check does not exist (a target that was never probeable). Reason is set
// only when State is unknown or degraded
// (a PathReasonDegraded* code). Samples and Expected count runs over the
// window's whole buckets (PathMatrix), as PathBucket's N and Expected do, so
// a path that ran every interval reads Samples equal to Expected. Prev is
// the same figures one
// window earlier, null when that window heard nothing; LastAt is the newest
// run's stamp, null when there is none. Degraded is present only while
// State is degraded.
//
// A path is a (source, target) pair whichever check measures it (design 32
// R1): a console keys every pair with a target node as source~target node
// and an external target as source~@monitor id, and lists every check on a
// pair. CheckDefinitionID names the definition a cell's monitor was expanded
// from, empty for a single check. Managed is deprecated: it marks the cells
// of the definitions migrated from the path set, is sent for one release,
// and is then removed; key by the pair instead.
type PathCell struct {
	Source     string `json:"source"`
	TargetNode string `json:"target_node"`
	Target     string `json:"target"`
	MonitorID  string `json:"monitor_id"`
	// Deprecated: key by the pair (design 32 R1).
	Managed           bool             `json:"managed"`
	CheckDefinitionID string           `json:"check_definition_id,omitempty"`
	Method            string           `json:"method"`
	State             string           `json:"state"`
	Reason            string           `json:"reason"`
	P50Ms             *float64         `json:"p50_ms"`
	P95Ms             *float64         `json:"p95_ms"`
	JitterMs          *float64         `json:"jitter_ms"`
	Loss              *float64         `json:"loss"`
	Samples           int              `json:"samples"`
	Expected          int              `json:"expected"`
	Prev              *PathPrev        `json:"prev"`
	LastAt            *time.Time       `json:"last_at"`
	Degraded          *PathDegradation `json:"degraded,omitempty"`
}

// PathPrev is a path's figures over the window before the one asked for.
type PathPrev struct {
	P50Ms *float64 `json:"p50_ms"`
	Loss  *float64 `json:"loss"`
}

// The degraded rule (design 29 D13).
//
// The control plane judges every path whose check kind is tcp, http, icmp or
// beacon once a minute, never on a console read. A path is judged only once
// its baseline, the one-hour buckets whose start lies in [H - 7 days, H)
// where H is the current hour, holds PathBaselineMinHours buckets with a
// countable run. The condition is either arm:
//
//   - loss: at least PathDegradedMinProbes probes in the last hour, and their
//     loss strictly above DegradedLossTrigger of the baseline loss;
//   - latency: at least PathDegradedMinLatencyRuns successful runs in the last
//     15 minutes, and their median strictly above DegradedLatencyTrigger of
//     the baseline median.
//
// A path enters degraded on PathDegradedEnterAfter consecutive evaluations
// that find the condition and leaves once it has been absent for
// PathDegradedLeaveAfter. A probe is counted as MonitorRollup counts it:
// every echo or request of a multi-packet run, one per run otherwise.
const (
	PathDegradedEvery          = time.Minute
	PathBaselineSpan           = 7 * 24 * time.Hour
	PathBaselineMinHours       = 24
	PathDegradedLossWindow     = time.Hour
	PathDegradedMinProbes      = 30
	PathDegradedLatencyWindow  = 15 * time.Minute
	PathDegradedMinLatencyRuns = 5
	PathDegradedEnterAfter     = 2
	PathDegradedLeaveAfter     = 10 * time.Minute
)

// Why a path reads degraded (PathCell.Reason): the arms that held at the last
// evaluation that found the condition. They carry a prefix so one reason
// table serves the unknown and the degraded states.
const (
	PathReasonDegradedLoss        = "degraded_loss"
	PathReasonDegradedLatency     = "degraded_latency"
	PathReasonDegradedLossLatency = "degraded_loss_latency"
)

// The degraded rule's thresholds: defaults and bounds of each
// MonitorDegradedRule field.
const (
	MonitorDegradedLossPercentDefault     = 2.0
	MonitorDegradedLossPercentMin         = 0.5
	MonitorDegradedLossPercentMax         = 50.0
	MonitorDegradedLossFactorDefault      = 2.0
	MonitorDegradedLossFactorMin          = 1.2
	MonitorDegradedLossFactorMax          = 10.0
	MonitorDegradedLatencyFactorDefault   = 2.0
	MonitorDegradedLatencyFactorMin       = 1.2
	MonitorDegradedLatencyFactorMax       = 10.0
	MonitorDegradedLatencyMarginMsDefault = 30.0
	MonitorDegradedLatencyMarginMsMin     = 5.0
	MonitorDegradedLatencyMarginMsMax     = 1000.0
)

// MonitorDegradedRule is a check's degraded thresholds (Monitor.Degraded, and
// LatencyProbeConfig.Degraded for the path set's generated checks). A zero
// field reads as its default, and so does a nil rule. The control plane
// stores the canonical form (CanonicalDegradedRule).
type MonitorDegradedRule struct {
	// LossPercent is the loss floor in percent: the loss arm needs more
	// than this whatever the baseline.
	LossPercent float64 `json:"loss_percent,omitempty"`
	// LossFactor is how many times the baseline loss the loss arm needs.
	LossFactor float64 `json:"loss_factor,omitempty"`
	// LatencyFactor is how many times the baseline median the latency arm
	// needs.
	LatencyFactor float64 `json:"latency_factor,omitempty"`
	// LatencyMarginMs is how many milliseconds above the baseline median
	// the latency arm needs.
	LatencyMarginMs float64 `json:"latency_margin_ms,omitempty"`
}

// degradedRuleField is one threshold: its JSON name, default, bounds and the
// number of decimal places the canonical form keeps.
type degradedRuleField struct {
	name        string
	def, lo, hi float64
	decimals    int
	get         func(*MonitorDegradedRule) *float64
	unit        string
}

var degradedRuleFields = []degradedRuleField{
	{"loss_percent", MonitorDegradedLossPercentDefault, MonitorDegradedLossPercentMin, MonitorDegradedLossPercentMax, 1,
		func(r *MonitorDegradedRule) *float64 { return &r.LossPercent }, " percent"},
	{"loss_factor", MonitorDegradedLossFactorDefault, MonitorDegradedLossFactorMin, MonitorDegradedLossFactorMax, 1,
		func(r *MonitorDegradedRule) *float64 { return &r.LossFactor }, ""},
	{"latency_factor", MonitorDegradedLatencyFactorDefault, MonitorDegradedLatencyFactorMin, MonitorDegradedLatencyFactorMax, 1,
		func(r *MonitorDegradedRule) *float64 { return &r.LatencyFactor }, ""},
	{"latency_margin_ms", MonitorDegradedLatencyMarginMsDefault, MonitorDegradedLatencyMarginMsMin, MonitorDegradedLatencyMarginMsMax, 0,
		func(r *MonitorDegradedRule) *float64 { return &r.LatencyMarginMs }, " ms"},
}

// ValidateDegradedRule refuses a rule with a field that is NaN, infinite,
// negative or, when set, outside its bounds, naming the field. Zero is not
// a value but the default, and a nil rule is all defaults.
func ValidateDegradedRule(r *MonitorDegradedRule) error {
	if r == nil {
		return nil
	}
	for _, f := range degradedRuleFields {
		v := *f.get(r)
		switch {
		case math.IsNaN(v) || math.IsInf(v, 0):
			return fmt.Errorf("degraded.%s must be a number", f.name)
		case v < 0:
			return fmt.Errorf("degraded.%s cannot be negative", f.name)
		case v != 0 && (v < f.lo || v > f.hi):
			return fmt.Errorf("degraded.%s must be %s to %s%s", f.name, formatDegradedBound(f.lo), formatDegradedBound(f.hi), f.unit)
		}
	}
	return nil
}

func formatDegradedBound(v float64) string {
	return fmt.Sprintf("%g", v)
}

// CanonicalDegradedRule is the form the control plane stores: every value
// rounded to one decimal place (the margin to a whole millisecond), a field
// equal to its default written as zero, and nil when every field is the
// default, so an editor that echoes the defaults stores nothing. Validate
// first; a rounded value never leaves its bounds, which sit on the same
// places.
func CanonicalDegradedRule(r *MonitorDegradedRule) *MonitorDegradedRule {
	if r == nil {
		return nil
	}
	out := *r
	empty := true
	for _, f := range degradedRuleFields {
		p := f.get(&out)
		scale := math.Pow(10, float64(f.decimals))
		v := math.Round(*p*scale) / scale
		if v == f.def {
			v = 0
		}
		*p = v
		if v != 0 {
			empty = false
		}
	}
	if empty {
		return nil
	}
	return &out
}

// Effective is the rule with every unset field at its default. A nil rule is
// every default.
func (r *MonitorDegradedRule) Effective() MonitorDegradedRule {
	var out MonitorDegradedRule
	if r != nil {
		out = *r
	}
	for _, f := range degradedRuleFields {
		if p := f.get(&out); *p == 0 {
			*p = f.def
		}
	}
	return out
}

// DegradedLossTrigger is the loss share (0 to 1) the loss arm must exceed:
// the larger of the floor, LossPercent / 100, and LossFactor times the
// baseline loss. Unset fields read as their defaults.
func DegradedLossTrigger(rule MonitorDegradedRule, baseLoss float64) float64 {
	e := rule.Effective()
	return math.Max(e.LossPercent/100, e.LossFactor*baseLoss)
}

// DegradedLatencyTrigger is the median in milliseconds the latency arm must
// exceed: the larger of LatencyFactor times the baseline median and the
// baseline median plus LatencyMarginMs. Unset fields read as their defaults.
func DegradedLatencyTrigger(rule MonitorDegradedRule, baseP50 float64) float64 {
	e := rule.Effective()
	return math.Max(e.LatencyFactor*baseP50, baseP50+e.LatencyMarginMs)
}

// PathDegradation is why a path reads degraded (PathCell.Degraded). Since is
// the first of the evaluations that entered it, EvaluatedAt the last one that
// found the condition, which the evidence is from. ClearingSince is set once
// the condition is absent; the path leaves PathDegradedLeaveAfter later
// unless it returns. Loss is present when the loss arm held, Latency when the
// latency arm did.
type PathDegradation struct {
	Since         time.Time            `json:"since"`
	EvaluatedAt   time.Time            `json:"evaluated_at"`
	ClearingSince *time.Time           `json:"clearing_since,omitempty"`
	Loss          *PathLossEvidence    `json:"loss,omitempty"`
	Latency       *PathLatencyEvidence `json:"latency,omitempty"`
}

// PathLossEvidence is the loss arm at an evaluation: the loss over the last
// hour (Value), the baseline loss and the trigger it exceeded, as shares from
// 0 to 1, with the probes sent and lost in that hour.
type PathLossEvidence struct {
	Value    float64 `json:"value"`
	Baseline float64 `json:"baseline"`
	Trigger  float64 `json:"trigger"`
	Sent     int     `json:"sent"`
	Lost     int     `json:"lost"`
}

// PathLatencyEvidence is the latency arm at an evaluation: the median of the
// last 15 minutes over Runs successful runs, the baseline median and the
// trigger it exceeded.
type PathLatencyEvidence struct {
	P50Ms      float64 `json:"p50_ms"`
	Runs       int     `json:"runs"`
	BaselineMs float64 `json:"baseline_ms"`
	TriggerMs  float64 `json:"trigger_ms"`
}

// PathBaseline is the degraded rule's guide for one pair (PathSeries.Baseline):
// the baseline window [From, To), the one-hour buckets in it with a run
// (Hours), whether that is enough to judge (Ready, at least
// PathBaselineMinHours), the baseline median and loss (null without data),
// the triggers (null until Ready, and the latency trigger also while P50Ms is
// null) and the thresholds in force with every default filled in.
type PathBaseline struct {
	From         time.Time           `json:"from"`
	To           time.Time           `json:"to"`
	Hours        int                 `json:"hours"`
	Ready        bool                `json:"ready"`
	P50Ms        *float64            `json:"p50_ms"`
	Loss         *float64            `json:"loss"`
	TriggerP50Ms *float64            `json:"trigger_p50_ms"`
	TriggerLoss  *float64            `json:"trigger_loss"`
	Rule         MonitorDegradedRule `json:"rule"`
}

// PathPreviousSeries is a path's median one window earlier, aligned with the
// series it was asked with: P50Ms has one entry per PathSeries.Buckets entry,
// entry i covering [t_i - OffsetSeconds, t_i - OffsetSeconds + step), null
// where that step had no successful run. StepSeconds is the resolution it was
// read at; when that is coarser than the series' step (the earlier window
// lies beyond the finer tier's retention), one bucket gives its value to
// every step it covers.
type PathPreviousSeries struct {
	From          time.Time  `json:"from"`
	To            time.Time  `json:"to"`
	OffsetSeconds int        `json:"offset_seconds"`
	StepSeconds   int        `json:"step_seconds"`
	P50Ms         []*float64 `json:"p50_ms"`
}
