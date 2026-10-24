package model

import "time"

// Check definitions (lattice docs design 32 D1).
//
// A check definition is the one thing an operator creates: a method, a
// source set, a target set, a schedule, expectations and alerting. A path is
// one (source, target) pair a definition measures; it is derived, never
// authored. The control plane expands a definition into ordinary monitors,
// one per (target, method), each assigned to the definition's sources and
// marked with ManagedBy "check:<definition id>". Agents run them through the
// ordinary monitor assignment, so a definition needs no agent feature beyond
// the methods it uses.
//
// An expanded monitor's id is "mon_" plus the definition id plus a short
// stable hash of the method and the normalized target, so removing one
// target never hands another its history and a method change starts new
// series. Ids are opaque: read the definition from the monitor's
// check_definition_id and the target from its fields, never from the id.
//
// A target that leaves the set keeps its monitor, paused, with its history.
// History goes only when the operator deletes the definition or forgets its
// paused targets, both of which name the monitors and their runs first, or
// when the target node is removed from the fleet.
//
// The path set (LatencyProbeConfig) is listed beside the definitions as the
// built-in check named Fleet mesh, with its own editor and its own ids.

// CheckDefinitionIDPrefix starts every definition id.
const CheckDefinitionIDPrefix = "chk_"

// Bounds of a check definition.
const (
	CheckDefinitionNameMax = 120
	// CheckDefinitionNodesMax bounds each node list a selector names.
	CheckDefinitionNodesMax = 512
	// CheckDefinitionGroupsMax bounds the groups a selector names.
	CheckDefinitionGroupsMax = 64
	// CheckDefinitionAddressesMax bounds the external targets.
	CheckDefinitionAddressesMax = 64
	// CheckDefinitionPairsMax bounds the paths one definition measures:
	// its resolved sources times its targets.
	CheckDefinitionPairsMax = 4096
)

// CheckDefinitionSpec is what an operator writes: everything but the
// identity, the request headers and the bookkeeping.
//
// Type is the method, a MonitorType* value: tcp, icmp, beacon, http or tls.
// Sources selects the nodes that run it; a tls check runs on the control
// plane and takes no sources. Targets selects target nodes for tcp, icmp and
// beacon. Addresses are external targets, each its own target: absolute
// URLs for http, host:port for tcp and tls, IPv4 addresses for icmp. A tcp
// or icmp definition may name both; beacon takes nodes only, http and tls
// addresses only.
//
// The remaining fields mean what they mean on a Monitor and are copied onto
// every expanded monitor; an edit to any of them rewrites every expanded
// monitor in one write. Enabled false pauses every monitor of the
// definition and creates none.
type CheckDefinitionSpec struct {
	Name          string               `json:"name"`
	Type          string               `json:"type"`
	Sources       TargetSelector       `json:"sources"`
	Targets       TargetSelector       `json:"targets"`
	Addresses     []string             `json:"addresses,omitempty"`
	IntervalSec   int                  `json:"interval_sec"`
	TimeoutSec    int                  `json:"timeout_sec"`
	Packets       int                  `json:"packets,omitempty"`
	ThresholdDays int                  `json:"threshold_days,omitempty"`
	ExpectStatus  string               `json:"expect_status,omitempty"`
	Alert         string               `json:"alert,omitempty"`
	AlertAfter    int                  `json:"alert_after,omitempty"`
	Degraded      *MonitorDegradedRule `json:"degraded,omitempty"`
	Enabled       bool                 `json:"enabled"`
}

// CheckDefinition is a stored definition.
//
// Headers are an http definition's request headers. Every read carries a
// secret header's Name with Secret and Set and no Value, as on a Monitor. A
// definition with a secret header names its sources as explicit nodes
// only, because a group or whole-fleet source would send the secret to any
// node that joins. SecretsOrigins are the origins (MonitorOrigin) the
// secrets were saved for; an edit that adds an address with another origin
// must set every secret header again.
type CheckDefinition struct {
	ID string `json:"id"`
	CheckDefinitionSpec
	Headers        []MonitorHeader `json:"headers,omitempty"`
	SecretsOrigins []string        `json:"secrets_origins,omitempty"`
	// Version counts saves. An edit names the version it was read at, so
	// two operators editing one definition cannot overwrite each other.
	Version   int64     `json:"version"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by,omitempty"`
}

// CheckDefinitionSave is the body of a create (POST
// /api/monitors/definitions, no id), an edit (POST
// /api/monitors/definitions/update, with the id and the version it was read
// at) and a dry run of either (POST /api/monitors/definitions/preview). The
// spec replaces the stored one whole. Headers are operations applied in
// order to the stored headers, as on MonitorUpdate, so an edit that echoes
// the secret-less read neither wipes nor leaks a secret; a create's are all
// MonitorHeaderSet.
type CheckDefinitionSave struct {
	ID      string `json:"id,omitempty"`
	Version int64  `json:"version,omitempty"`
	CheckDefinitionSpec
	Headers []MonitorHeaderEdit `json:"headers,omitempty"`
}

// CheckDefinitionDelete is the body of POST /api/monitors/definitions/delete.
// MonitorIDs are the expanded monitors the operator confirmed deleting with
// their history; the delete is refused when they are not exactly the
// definition's monitors now, so a confirmation always matches what goes.
type CheckDefinitionDelete struct {
	ID         string   `json:"id"`
	Version    int64    `json:"version"`
	MonitorIDs []string `json:"monitor_ids"`
}

// CheckDefinitionForget is the body of POST /api/monitors/definitions/forget:
// delete, with their history, the named monitors whose targets left the
// definition's set. Each must be one of the definition's paused targets.
type CheckDefinitionForget struct {
	ID         string   `json:"id"`
	MonitorIDs []string `json:"monitor_ids"`
}

// CheckDefinitionView is a definition as the API reads it: secret header
// values removed, with what it expands to now.
type CheckDefinitionView struct {
	CheckDefinition
	Summary CheckDefinitionSummary `json:"summary"`
	// Monitors are the expanded monitors, present on a read of one
	// definition (GET /api/monitors/definitions?id=) and after a save.
	Monitors []CheckDefinitionMonitor `json:"monitors,omitempty"`
}

// CheckDefinitionSummary counts what a definition holds now. Paths are the
// (monitor, source) pairs of its monitors whose targets are in the set;
// PausedTargets are its monitors whose targets left the set, kept with
// PausedRuns stored runs between them.
type CheckDefinitionSummary struct {
	Monitors      int `json:"monitors"`
	Paths         int `json:"paths"`
	PausedTargets int `json:"paused_targets"`
	PausedRuns    int `json:"paused_runs"`
}

// CheckDefinitionMonitor is one expanded monitor. InSet says whether its
// target is in the definition's target set now; one that is not is a paused
// target. Runs is how many results it stores, over every source.
type CheckDefinitionMonitor struct {
	MonitorID  string   `json:"monitor_id"`
	Method     string   `json:"method"`
	Target     string   `json:"target"`
	TargetNode string   `json:"target_node,omitempty"`
	InSet      bool     `json:"in_set"`
	Enabled    bool     `json:"enabled"`
	Sources    []string `json:"sources"`
	Runs       int      `json:"runs"`
}

// CheckFleetMesh is the path set listed as the built-in check named Fleet
// mesh. It keeps its own editor (GET and PUT /api/monitors/latency); these
// are its counts against the fleet now.
type CheckFleetMesh struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	// Stored is false while the defaults are in force.
	Stored  bool   `json:"stored"`
	Version int64  `json:"version"`
	Method  string `json:"method"`
	Sources int    `json:"sources"`
	// Targets are the nodes probed now, Paths the pairs that run, and
	// PausedTargets the targets whose checks are kept paused.
	Targets       int `json:"targets"`
	Paths         int `json:"paths"`
	PausedTargets int `json:"paused_targets"`
}

// CheckFleetMeshName is the name the path set is listed under.
const CheckFleetMeshName = "Fleet mesh"

// CheckDefinitionList answers GET /api/monitors/definitions: every
// definition the caller may read, by name, and Fleet mesh.
type CheckDefinitionList struct {
	Definitions []CheckDefinitionView `json:"definitions"`
	FleetMesh   CheckFleetMesh        `json:"fleet_mesh"`
}

// CheckDefinitionPreview answers a dry run: exactly what a save of the
// same body would write and measure, judged against the fleet now.
//
// Sources are the nodes that would run the check (none for tls, whose one
// source is the control plane, an empty id in Pairs). Targets lists every
// target in the set with its monitor. Pairs are the paths; a pair with a
// Reason would read unknown for that reason (a PathReason* code, including
// PathReasonPacketBudget for a pair the budget pauses and
// PathReasonSourcePaused when the definition is disabled), and Measured
// counts the pairs without one. Notes says why a node a selector names
// explicitly is left out (LatencySourceUnknownNode,
// LatencySourceDisabled).
type CheckDefinitionPreview struct {
	Sources  []string             `json:"sources"`
	Targets  []CheckPreviewTarget `json:"targets"`
	Pairs    []CheckPreviewPair   `json:"pairs"`
	Paths    int                  `json:"paths"`
	Measured int                  `json:"measured"`
	Writes   CheckPreviewWrites   `json:"writes"`
	Notes    map[string]string    `json:"notes,omitempty"`
}

// CheckPreviewTarget is one target of a dry run. Target is what the method
// dials now, empty when nothing can be dialled; Reason then says why
// (PathReasonNotProbeable, or PathReasonBeaconNotEnabled for a beacon
// target), and Note gives the detail (a LatencyEndpoint* code).
type CheckPreviewTarget struct {
	MonitorID  string `json:"monitor_id"`
	Target     string `json:"target"`
	TargetNode string `json:"target_node,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Note       string `json:"note,omitempty"`
}

// CheckPreviewPair is one path of a dry run.
type CheckPreviewPair struct {
	Source    string `json:"source"`
	MonitorID string `json:"monitor_id"`
	Reason    string `json:"reason,omitempty"`
}

// CheckPreviewWrites are the monitor ids a save would write: created,
// rewritten, paused because their targets left the set (kept with their
// history), and deleted because their target nodes left the fleet.
type CheckPreviewWrites struct {
	Created []string `json:"created"`
	Updated []string `json:"updated"`
	Paused  []string `json:"paused"`
	Deleted []string `json:"deleted"`
}
