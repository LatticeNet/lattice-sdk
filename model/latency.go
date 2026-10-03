package model

import "time"

// Latency and reachability probes between nodes.
//
// The operator keeps one LatencyProbeConfig. The control plane turns it into
// tcp monitors, one per target node, each assigned to the sources that probe
// that target, and marks them with ManagedBy MonitorManagedLatency. Agents run
// them through the ordinary monitor assignment and report through the
// ordinary result routes, so a probe needs no agent feature beyond tcp
// monitors. A (monitor, node) result pair is therefore a (target, source)
// pair here.
//
// The probe is a TCP connect to a line port the target already serves to the
// public, never SSH and never a knock-gated port, and its latency is the
// handshake round trip as the source saw it. The control plane owns the rule
// that picks the port (lattice-server internal/server/latency_probes.go).

// MonitorManagedLatency is Monitor.ManagedBy on a monitor generated from the
// latency probe configuration.
const MonitorManagedLatency = "latency"

// Bounds and defaults of a latency probe configuration.
const (
	LatencyProbeDefaultIntervalSec = 60
	LatencyProbeDefaultTimeoutSec  = 5
	LatencyProbeMinIntervalSec     = 10
	LatencyProbeMaxIntervalSec     = 3600
	LatencyProbeMaxTimeoutSec      = 30
)

// LatencyProbeConfig is the operator's plan for latency probes. A save must
// name existing nodes. A node deleted after the save stays in the stored
// lists and is ignored (the plan reports it in SourceNotes when it was a
// source); enrolment always mints a new node id, so a stale id can never come
// to mean another machine.
type LatencyProbeConfig struct {
	// Enabled switches every generated probe on or off at once. Off keeps
	// the generated monitors, paused, with their history.
	Enabled     bool `json:"enabled"`
	IntervalSec int  `json:"interval_sec"`
	TimeoutSec  int  `json:"timeout_sec"`
	// Sources are the nodes that run the probes.
	Sources []string `json:"sources"`
	// AutoTargets probes every node whose region is outside mainland China
	// (LatencyRegionOutside).
	AutoTargets bool `json:"auto_targets"`
	// IncludeTargets are probed whatever their region.
	IncludeTargets []string `json:"include_targets,omitempty"`
	// ExcludeTargets are never probed, even when AutoTargets covers them.
	ExcludeTargets []string `json:"exclude_targets,omitempty"`
	// DisabledPairs switches single source to target pairs off.
	DisabledPairs []LatencyPair `json:"disabled_pairs,omitempty"`
	// Version counts saves. A save must name the version it was made from,
	// so two operators editing at once cannot overwrite each other.
	Version   int64     `json:"version"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
	UpdatedBy string    `json:"updated_by,omitempty"`
}

// LatencyPair names one source to target pair by node id.
type LatencyPair struct {
	Source string `json:"source"`
	Target string `json:"target"`
}

// Where a node sits for the default target rule. A node's region is its
// Geo.Country: CN is mainland China, and HK, MO and TW are outside it. A node
// with no country is unknown and is never a default target.
const (
	LatencyRegionOutside  = "outside_mainland"
	LatencyRegionMainland = "mainland"
	LatencyRegionUnknown  = "unknown"
)

// What the plan does with a node as a target.
const (
	// LatencyTargetProbed: probed by at least one source now.
	LatencyTargetProbed = "probed"
	// LatencyTargetNotProbeable: meant to be probed, but the node serves no
	// port the rule may dial; EndpointNote says why.
	LatencyTargetNotProbeable = "not_probeable"
	// LatencyTargetPaused: its monitor and history are kept, nothing probes
	// it now; TargetReason says why.
	LatencyTargetPaused = "paused"
	// LatencyTargetNone: not a target.
	LatencyTargetNone = "none"
)

// Why a node is or is not a target (LatencyProbeNode.TargetReason).
//
// A target (probed, not_probeable or paused) carries why it was chosen
// (auto, included) or, when paused, why nothing probes it (config_off,
// pairs_off, no_source). A node that is not a target carries why not
// (excluded, mainland, region_unknown, auto_off, node_disabled); its
// MonitorID stays set while the monitor and its history are kept.
const (
	LatencyReasonAuto          = "auto"
	LatencyReasonIncluded      = "included"
	LatencyReasonExcluded      = "excluded"
	LatencyReasonMainland      = "mainland"
	LatencyReasonRegionUnknown = "region_unknown"
	LatencyReasonAutoOff       = "auto_off"
	LatencyReasonNodeDisabled  = "node_disabled"
	LatencyReasonConfigOff     = "config_off"
	LatencyReasonPairsOff      = "pairs_off"
	LatencyReasonNoSource      = "no_source"
)

// What the port rule found on a target (LatencyProbeNode.EndpointNote).
const (
	// LatencyEndpointLastKnown: the node's line inventory is not current
	// (an offline node stops reporting it), so the probe keeps the address
	// it had. A node that went dark is exactly what the probe must keep
	// measuring.
	LatencyEndpointLastKnown = "last_known"
	// LatencyEndpointNoAddress: no public IPv4 address, provider edge or
	// published host to dial.
	LatencyEndpointNoAddress = "no_public_address"
	// LatencyEndpointUDPOnly: every line is UDP (hysteria2, tuic, QUIC
	// transport), which a TCP connect cannot measure.
	LatencyEndpointUDPOnly = "udp_only"
	// LatencyEndpointNoLine: no proxy line the rule may dial: none at all,
	// only loopback listeners, or only ports that are SSH or knock-gated.
	LatencyEndpointNoLine = "no_tcp_line"
	// LatencyEndpointNoInventory: the node has not reported its lines since
	// the control plane started and no earlier probe address is kept, so
	// nothing is known to dial yet.
	LatencyEndpointNoInventory = "no_inventory"
)

// Why a configured source cannot probe (LatencyProbePlan.SourceNotes).
const (
	LatencySourceUnknownNode = "unknown_node"
	LatencySourceDisabled    = "node_disabled"
)

// LatencyProbePlan is the configuration and what the control plane made of
// it against the fleet as it is now.
type LatencyProbePlan struct {
	Config LatencyProbeConfig `json:"config"`
	// Stored is false while no operator has saved a configuration and the
	// defaults are in force.
	Stored bool `json:"stored"`
	// DefaultSourceName is the node name the defaults take as the source,
	// so the console can say which node it looked for.
	DefaultSourceName string                  `json:"default_source_name"`
	Nodes             []LatencyProbeNode      `json:"nodes"`
	Pairs             []LatencyProbePairState `json:"pairs"`
	// SourceNotes lists configured source ids that cannot probe, with why
	// (LatencySource*). A source id that names no node appears only here.
	SourceNotes map[string]string `json:"source_notes,omitempty"`
}

// LatencyProbeNode is one node as the plan sees it.
type LatencyProbeNode struct {
	NodeID  string `json:"node_id"`
	Name    string `json:"name"`
	Country string `json:"country,omitempty"`
	Region  string `json:"region"`
	Source  bool   `json:"source"`
	// Target is a LatencyTarget* state and TargetReason a LatencyReason*.
	Target       string `json:"target"`
	TargetReason string `json:"target_reason,omitempty"`
	// Endpoint is host:port as the sources dial it, with the line it came
	// from. EndpointNote is a LatencyEndpoint* code: why there is no
	// endpoint, or that it is the last known one.
	Endpoint     string `json:"endpoint,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	LineName     string `json:"line_name,omitempty"`
	EndpointNote string `json:"endpoint_note,omitempty"`
	MonitorID    string `json:"monitor_id,omitempty"`
}

// LatencyProbePairState is one source to target pair of the plan.
type LatencyProbePairState struct {
	Source string `json:"source"`
	Target string `json:"target"`
	// Enabled is the operator's switch for the pair; Active is whether the
	// source runs the probe now, which also needs the configuration on, a
	// probeable target and a source that can run it.
	Enabled   bool   `json:"enabled"`
	Active    bool   `json:"active"`
	MonitorID string `json:"monitor_id,omitempty"`
}

// Rollup windows.
const (
	LatencyWindowHour = "1h"
	LatencyWindowDay  = "24h"
	LatencyWindowWeek = "7d"
)

// LatencyStats summarizes one pair over one window or one bucket.
//
// Percentiles come from the probes that succeeded and are estimates read off
// a histogram whose bins are about 9 percent wide, so a value is within about
// 4.5 percent of the exact one. They are absent when no probe succeeded. Loss
// is the failure share of the probes the control plane heard, absent when it
// heard none. Expected is how many probes the interval would have produced,
// so the part of the window without results (Expected minus Samples) is
// unknown, never counted as up or as down.
type LatencyStats struct {
	Samples  int      `json:"samples"`
	Failures int      `json:"failures"`
	Expected int      `json:"expected"`
	P50Ms    *float64 `json:"p50_ms,omitempty"`
	P95Ms    *float64 `json:"p95_ms,omitempty"`
	Loss     *float64 `json:"loss,omitempty"`
}

// LatencyPairRollup is one pair's stats over the 1 h, 24 h and 7 d windows,
// keyed by window name, and its newest result.
type LatencyPairRollup struct {
	Source    string                  `json:"source"`
	Target    string                  `json:"target"`
	MonitorID string                  `json:"monitor_id"`
	Windows   map[string]LatencyStats `json:"windows"`
	Latest    *MonitorResult          `json:"latest,omitempty"`
}

// LatencyRollups answers the rollup read: every pair of the plan that has a
// generated monitor (probing now or paused with its history) and whose two
// nodes the caller may read.
type LatencyRollups struct {
	GeneratedAt time.Time           `json:"generated_at"`
	IntervalSec int                 `json:"interval_sec"`
	Pairs       []LatencyPairRollup `json:"pairs"`
}

// LatencyBucket is one step of a pair's series.
type LatencyBucket struct {
	At time.Time `json:"at"`
	LatencyStats
}

// LatencySeries is one pair over one window, every bucket present: a bucket
// with no samples is a gap, which reads as unknown.
type LatencySeries struct {
	Source    string          `json:"source"`
	Target    string          `json:"target"`
	MonitorID string          `json:"monitor_id"`
	Window    string          `json:"window"`
	BucketSec int             `json:"bucket_sec"`
	From      time.Time       `json:"from"`
	To        time.Time       `json:"to"`
	Buckets   []LatencyBucket `json:"buckets"`
}
