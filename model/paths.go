package model

import "time"

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
)

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

// PathSeries is one path over one window (GET /api/monitors/series). Every
// step is present: a bucket with N zero and Expected above zero is a gap,
// which reads as unknown, never interpolated.
type PathSeries struct {
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
}

// PathMethodChange marks where a path's method begins.
type PathMethodChange struct {
	T      time.Time `json:"t"`
	Method string    `json:"method"`
}

// PathBucket is one step of a series. N counts runs and Fail the failed
// ones; Expected is how many runs the interval would have produced over
// the part of the step that has passed. The latency figures come from the
// successful runs and are null when none succeeded; percentiles are read
// off a histogram whose bins are about 9 percent wide. JitterMs is the mean
// absolute difference between consecutive successful runs; Loss is Fail
// over N, null when N is zero.
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
}

// PathMatrix answers GET /api/monitors/paths: every path the caller may
// read (both its source and its target node), with its state now and its
// figures over the window. ObservedAt is when the states were judged; the
// window figures are cached until the window's next bucket closes.
type PathMatrix struct {
	Window     string       `json:"window"`
	ObservedAt time.Time    `json:"observed_at"`
	Sources    []PathSource `json:"sources"`
	Targets    []PathTarget `json:"targets"`
	Paths      []PathCell   `json:"paths"`
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
// check does not exist (a target that was never probeable). Managed marks
// generated checks. Reason is set only when State is unknown. Samples and
// Expected count runs over the window, as PathBucket's N and Expected do.
// Prev is the same figures one window earlier, null when that window heard
// nothing; LastAt is the newest run's stamp, null when there is none.
type PathCell struct {
	Source     string     `json:"source"`
	TargetNode string     `json:"target_node"`
	Target     string     `json:"target"`
	MonitorID  string     `json:"monitor_id"`
	Managed    bool       `json:"managed"`
	Method     string     `json:"method"`
	State      string     `json:"state"`
	Reason     string     `json:"reason"`
	P50Ms      *float64   `json:"p50_ms"`
	P95Ms      *float64   `json:"p95_ms"`
	JitterMs   *float64   `json:"jitter_ms"`
	Loss       *float64   `json:"loss"`
	Samples    int        `json:"samples"`
	Expected   int        `json:"expected"`
	Prev       *PathPrev  `json:"prev"`
	LastAt     *time.Time `json:"last_at"`
}

// PathPrev is a path's figures over the window before the one asked for.
type PathPrev struct {
	P50Ms *float64 `json:"p50_ms"`
	Loss  *float64 `json:"loss"`
}
