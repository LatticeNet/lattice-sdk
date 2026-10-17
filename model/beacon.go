package model

import "time"

// The measurement beacon of design 29 D3 (M2b; the wire contract is D12).
//
// A beacon is an authenticated UDP responder inside a node's agent, off until
// an approved node.beacon plan turns it on. The control plane holds one
// 32-byte key per target node and derives a path key per (source, target,
// epoch) from it (package beacon of this module, DerivePathKey). Path keys
// reach agents only through the authenticated config pull
// (AgentConfig.Beacon), and agents hold them in memory only.

// Approval columns of a node.beacon plan.
const (
	// BeaconApprovalPlugin is Approval.Plugin of a node.beacon plan.
	BeaconApprovalPlugin = "beacon"
	// BeaconPlanKind is Approval.Action and BeaconPlan.Kind.
	BeaconPlanKind = "node.beacon"
)

// Actions of a node.beacon plan (BeaconPlanRequest.Action).
const (
	BeaconActionEnable  = "enable"
	BeaconActionDisable = "disable"
	// BeaconActionChange changes the port, bind address or endpoint of an
	// enabled beacon, or re-plans its source set and NetGuard allow set.
	BeaconActionChange = "change"
)

// MonitorManagedBeacon is Monitor.ManagedBy on a beacon's reachability
// check, generated when a node.beacon plan that enables or changes a beacon
// is applied. Its id is "mon_beaconr_<target node id>".
const MonitorManagedBeacon = "beacon"

// LatencyMethodBeacon probes a target through its beacon
// (LatencyProbeConfig.Method and SourceMethods). Its generated checks are
// "mon_latb_<target node id>".
const LatencyMethodBeacon = MonitorTypeBeacon

// Generated check id prefixes, followed by the target node id.
const (
	LatencyMonitorPrefixTCP    = "mon_lat_"
	LatencyMonitorPrefixICMP   = "mon_lati_"
	LatencyMonitorPrefixBeacon = "mon_latb_"
	BeaconReachMonitorPrefix   = "mon_beaconr_"
)

// Epoch timing the control plane keeps (D12). A rotation from epoch N-1 to
// N first adds N to the target's table beside N-1. Sources switch to N
// BeaconSourceSwitchDelay after the target first pulls a table holding N,
// so the target holds a key before any source uses it. N-1 stays accepted
// for BeaconEpochOverlap after that pull (many pull cycles, at least two),
// then stays BeaconRetiredGrace as retired, answering only
// beacon.StatusUnknownEpoch, and is then removed. A table holds at most two
// epochs per source, so a rotation during another one's overlap drops the
// oldest at once.
const (
	BeaconSourceSwitchDelay = 20 * time.Second
	BeaconEpochOverlap      = 2 * time.Minute
	BeaconRetiredGrace      = 10 * time.Minute
)

// BeaconLimits are the limits a node.beacon plan fixes, and its hash covers.
// The agent enforces SourceRatePerSecond after authentication; the control
// plane enforces MinIntervalSec and PacketsPerSecondMax on every beacon check
// it saves or generates, per (source, target).
type BeaconLimits struct {
	SourceRatePerSecond int `json:"source_rate_per_second"`
	MinIntervalSec      int `json:"min_interval_sec"`
	PacketsPerSecondMax int `json:"packets_per_second_max"`
}

// DefaultBeaconLimits are the limits of beacon v1: 20 requests per second
// per source id (beacon.SourceRatePerSecond), a 10 s interval floor and 2
// packets per second per (source, target), the same budget icmp has.
func DefaultBeaconLimits() BeaconLimits {
	return BeaconLimits{
		SourceRatePerSecond: 20,
		MinIntervalSec:      LatencyProbeMinIntervalSec,
		PacketsPerSecondMax: MonitorPacketsPerSecondMax,
	}
}

// BeaconSettings is what a node.beacon plan sets.
type BeaconSettings struct {
	Enabled bool `json:"enabled"`
	// Port is the UDP port the agent listens on: assigned at random in
	// beacon.PortRandomMin to beacon.PortRandomMax unless the operator
	// chose one, beacon.PortOverrideMin to 65535.
	Port int `json:"port,omitempty"`
	// Bind is the IPv4 address the agent binds, never the wildcard: the
	// node's primary interface address by default (its private address on
	// a NAT node), so WireGuard and other interfaces stay closed.
	Bind string `json:"bind,omitempty"`
	// Endpoint is the advertised address:port sources send to, an IPv4
	// literal: the node's public IPv4 and Port by default, the mapped
	// public address and port on a NAT node. Host names are refused.
	Endpoint string       `json:"endpoint,omitempty"`
	Limits   BeaconLimits `json:"limits"`
}

// BeaconPlanRequest is the body of POST /api/nodes/beacon/plan. For enable,
// a zero Port takes the node's assigned random port, an empty Bind the
// node's primary interface address and an empty Endpoint its public IPv4
// with the port. For change, a zero or empty field keeps the current value.
// Disable takes none of them.
type BeaconPlanRequest struct {
	NodeID   string `json:"node_id"`
	Action   string `json:"action"`
	Port     int    `json:"port,omitempty"`
	Bind     string `json:"bind,omitempty"`
	Endpoint string `json:"endpoint,omitempty"`
}

// BeaconPlan is the document a node.beacon approval carries as its Plan, as
// indented JSON. Approving it means approving these bytes (the approval's
// plan_sha256), so its hash covers the port, the bind address, the endpoint,
// the source set, the limits and, when NetGuard manages the node, the whole
// ruleset that will be applied. The control plane re-renders the plan from
// live state when it is decided and refuses the approval as stale when the
// bytes differ.
type BeaconPlan struct {
	Kind     string          `json:"kind"`
	NodeID   string          `json:"node_id"`
	NodeName string          `json:"node_name"`
	Action   string          `json:"action"`
	Beacon   BeaconSettings  `json:"beacon"`
	Previous *BeaconSettings `json:"previous,omitempty"`
	// Sources is the approved source set: the nodes that will hold a path
	// key for this target and, under NetGuard, may reach the port. Sorted
	// by node id. Empty on disable.
	Sources []BeaconPlanSource `json:"sources"`
	// Exposure is BeaconExposureNetGuard when the plan carries companion
	// rules, else BeaconExposureInternet: the port is open to everyone and
	// protected only by the beacon's own properties.
	Exposure string              `json:"exposure"`
	NetGuard *BeaconNetGuardPlan `json:"netguard,omitempty"`
	// BaseVersion is the beacon state's version the plan was made from.
	BaseVersion int64 `json:"base_version"`
}

// BeaconPlanSource is one source of the approved set.
type BeaconPlanSource struct {
	NodeID   string `json:"node_id"`
	Name     string `json:"name"`
	SourceID uint32 `json:"source_id"`
	// Allow is the /32s the companion rule admits for this source: its
	// pinned addresses (public and WireGuard IPv4) and, when it differs,
	// the egress address the control plane sees it connect from. Empty
	// without NetGuard.
	Allow []string `json:"allow,omitempty"`
}

// Exposure of a beacon port.
const (
	BeaconExposureNetGuard = "netguard"
	BeaconExposureInternet = "internet"
)

// BeaconNetGuardPlan is the companion rule set a node.beacon plan carries
// when NetGuard manages the node: UDP Port accepted from exactly Allow, and
// marked notrack in both directions (destination port on the way in,
// source port on the way out), so spoofed datagrams cannot fill the
// connection-tracking table the node's other traffic needs. Ruleset is the
// node's whole lattice_guard ruleset with the companion rules in place;
// approving the plan applies it as a NetGuard apply does.
type BeaconNetGuardPlan struct {
	Port           int      `json:"port"`
	Allow          []string `json:"allow"`
	Notrack        bool     `json:"notrack"`
	BindingVersion int64    `json:"binding_version"`
	RulesetSHA256  string   `json:"ruleset_sha256"`
	Ruleset        string   `json:"ruleset"`
}

// BeaconFinding is one lint result of a plan. A finding with severity
// BeaconFindingBlock refuses the plan; a warning is shown and kept.
type BeaconFinding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"`
	Message  string `json:"message"`
}

// Finding severities.
const (
	BeaconFindingBlock = "block"
	BeaconFindingWarn  = "warn"
)

// Finding codes.
const (
	// BeaconLintPortSingBox: a sing-box inbound listens on the port.
	BeaconLintPortSingBox = "port_singbox_inbound"
	// BeaconLintPortSSH: sshd listens on the port.
	BeaconLintPortSSH = "port_sshd"
	// BeaconLintPortKnock: the port is in the node's knock sequence.
	BeaconLintPortKnock = "port_knock"
	// BeaconLintPortWireGuard: WireGuard listens on the port.
	BeaconLintPortWireGuard = "port_wireguard"
	// BeaconLintBindWireGuard: the bind address is the node's WireGuard
	// address.
	BeaconLintBindWireGuard = "bind_wireguard"
	// BeaconLintBindNotLocal: the bind address is neither the node's
	// primary interface address nor its public IPv4 (warn: the agent
	// reports a bind failure if the address is not on the host).
	BeaconLintBindNotLocal = "bind_not_local"
	// BeaconLintEndpointMapped: the endpoint differs from the node's public
	// IPv4 and port (warn: a NAT mapping the operator vouches for).
	BeaconLintEndpointMapped = "endpoint_mapped"
	// BeaconLintNoSources: no source uses the beacon yet (warn).
	BeaconLintNoSources = "no_sources"
	// BeaconLintOpenToInternet: NetGuard does not manage the node (warn).
	BeaconLintOpenToInternet = "open_to_internet"
)

// BeaconPlanResponse answers POST /api/nodes/beacon/plan.
type BeaconPlanResponse struct {
	Approval Approval        `json:"approval"`
	Plan     BeaconPlan      `json:"plan"`
	Findings []BeaconFinding `json:"findings"`
}

// BeaconRotateRequest is the body of POST /api/nodes/beacon/rotate, an
// audited action that moves the node's key to a new epoch.
type BeaconRotateRequest struct {
	NodeID string `json:"node_id"`
}

// BeaconRotateResponse answers a rotation.
type BeaconRotateResponse struct {
	NodeID string `json:"node_id"`
	Epoch  uint32 `json:"epoch"`
}

// States of a node's beacon (BeaconView.State).
const (
	// BeaconStateOff: no applied plan enables it.
	BeaconStateOff = "off"
	// BeaconStatePending: enabled by an applied plan; the agent has not yet
	// reported listening on the planned address and port.
	BeaconStatePending = "pending"
	// BeaconStateListening: the agent reports listening on the planned
	// address and port.
	BeaconStateListening = "listening"
	// BeaconStateRefusedByNode: the agent runs with -no-beacon.
	BeaconStateRefusedByNode = "refused_by_node"
	// BeaconStateNotListening: enabled, but the agent reports a bind
	// failure, an open circuit breaker or no socket.
	BeaconStateNotListening = "not_listening"
	// BeaconStateAgentTooOld: the agent does not report a responder.
	BeaconStateAgentTooOld = "agent_too_old"
)

// Reachability verdicts of the check one source runs after a plan applies
// (BeaconReachability.State).
const (
	BeaconReachPending      = "pending"
	BeaconReachReachable    = "reachable"
	BeaconReachFiltered     = "filtered"
	BeaconReachNotListening = "not_listening"
	// BeaconReachNoSource: no online source runs the beacon client.
	BeaconReachNoSource = "no_source"
)

// BeaconReachability is the result of the reachability check: reachable
// when a reply came back, not listening when the source's connected socket
// read ECONNREFUSED, filtered when every request was lost.
type BeaconReachability struct {
	State     string    `json:"state,omitempty"`
	Source    string    `json:"source,omitempty"`
	MonitorID string    `json:"monitor_id,omitempty"`
	CheckedAt time.Time `json:"checked_at,omitzero"`
}

// BeaconView answers GET /api/nodes/beacon?node_id=. It never carries a
// key.
type BeaconView struct {
	NodeID string `json:"node_id"`
	State  string `json:"state"`
	// Reason is a PathReason* code when State is not listening or off.
	Reason string `json:"reason,omitempty"`
	// Applied is what the last applied plan set; nil before any.
	Applied           *BeaconSettings `json:"applied,omitempty"`
	AppliedApprovalID string          `json:"applied_approval_id,omitempty"`
	AppliedAt         time.Time       `json:"applied_at,omitzero"`
	// Epoch is the key epoch sources are moving to or using now.
	Epoch     uint32    `json:"epoch,omitempty"`
	RotatedAt time.Time `json:"rotated_at,omitzero"`
	// LastAuthAt is the last authenticated request the agent saw.
	LastAuthAt   time.Time          `json:"last_auth_at,omitzero"`
	Agent        *BeaconFacts       `json:"agent,omitempty"`
	Reachability BeaconReachability `json:"reachability"`
	Exposure     string             `json:"exposure,omitempty"`
	// FirewallPending is true when NetGuard manages the node and the
	// current source set differs from the approved one: a change plan must
	// be applied before an added source can reach the port.
	FirewallPending bool               `json:"firewall_pending,omitempty"`
	Sources         []BeaconSourceView `json:"sources"`
	// PendingApprovalID is an open node.beacon approval for this node.
	PendingApprovalID string `json:"pending_approval_id,omitempty"`
	// SuggestedPort is the random port an enable without a port takes.
	SuggestedPort int   `json:"suggested_port,omitempty"`
	Version       int64 `json:"version"`
}

// BeaconSourceView is one source of a beacon: approved by the applied plan,
// using the beacon now (the path set or an operator check), or both.
type BeaconSourceView struct {
	NodeID   string `json:"node_id"`
	Name     string `json:"name"`
	SourceID uint32 `json:"source_id"`
	Approved bool   `json:"approved"`
	Current  bool   `json:"current"`
	// Reason is firewall_pending or beacon_source_pending for a current
	// source the applied plan did not approve.
	Reason string `json:"reason,omitempty"`
}

// AgentBeaconConfig is AgentConfig.Beacon. An agent that does not know the
// field ignores it. A successful pull without Responder means the agent
// closes any responder socket; one without Keys means it holds no path keys.
type AgentBeaconConfig struct {
	// SourceID is this node's beacon source id, put in every request it
	// sends. The control plane assigns it once, above zero, and never
	// reuses it.
	SourceID uint32 `json:"source_id,omitempty"`
	// Keys are this node's path keys as a source, one per target it may
	// probe by beacon: the key for the epoch to send with now.
	Keys []BeaconPathKey `json:"keys,omitempty"`
	// Responder is this node's responder; present only while an applied
	// plan enables it and the agent reports a responder without refusal.
	Responder *BeaconResponderConfig `json:"responder,omitempty"`
}

// BeaconPathKey is a source's key for one target. Key is 32 bytes, base64 in
// JSON.
type BeaconPathKey struct {
	TargetNode string `json:"target_node"`
	Epoch      uint32 `json:"epoch"`
	Key        []byte `json:"key"`
}

// BeaconResponderConfig is the responder an applied plan set: bind exactly
// Bind:Port over UDP, enforce Limits, and answer only requests signed with a
// key of Table.
type BeaconResponderConfig struct {
	Bind   string           `json:"bind"`
	Port   int              `json:"port"`
	Limits BeaconLimits     `json:"limits"`
	Table  []BeaconTableKey `json:"table"`
}

// BeaconTableKey is one entry of a target's table (beacon.TableEntry). Key is
// 32 bytes, base64 in JSON.
type BeaconTableKey struct {
	SourceID uint32 `json:"source_id"`
	Epoch    uint32 `json:"epoch"`
	Key      []byte `json:"key"`
	Retired  bool   `json:"retired,omitempty"`
}

// BeaconFacts is what an agent reports about its responder, as the top-level
// key "beacon" of every hello and heartbeat body, beside probe_methods. The
// beacon client is reported as "beacon" in probe_methods; it sends only, so
// -no-beacon does not touch it. The control plane stores the last report as
// Node.Beacon.
type BeaconFacts struct {
	// Responder: the agent implements the responder.
	Responder bool `json:"responder"`
	// Refusal is PathReasonRefusedByNode when the agent runs with
	// -no-beacon; it then never binds, whatever its configuration says.
	Refusal string `json:"refusal,omitempty"`
	// State is a BeaconAgent* value.
	State string `json:"state,omitempty"`
	// Bind and Port are what the socket is bound to, or tried to bind.
	Bind string `json:"bind,omitempty"`
	Port int    `json:"port,omitempty"`
	// Epoch is the newest epoch in the table the agent applied, and
	// Sources how many source ids that table holds.
	Epoch   uint32 `json:"epoch,omitempty"`
	Sources int    `json:"sources,omitempty"`
	// LastAuthAt is when a request's tag last verified.
	LastAuthAt time.Time `json:"last_auth_at,omitzero"`
	// Error is the bind or socket error, at most 200 bytes.
	Error string `json:"error,omitempty"`
}

// Agent responder states (BeaconFacts.State).
const (
	BeaconAgentOff         = "off"
	BeaconAgentListening   = "listening"
	BeaconAgentBindFailed  = "bind_failed"
	BeaconAgentCircuitOpen = "circuit_open"
	BeaconAgentRefused     = "refused"
)

// Beacon reasons, for PathCell.Reason, pair states and MonitorResult.Reason.
const (
	// PathReasonBeaconNotEnabled: the target has no applied, enabled
	// beacon.
	PathReasonBeaconNotEnabled = "beacon_not_enabled"
	// PathReasonFirewallPending: NetGuard manages the target and the source
	// is not in the allow set of the applied plan; a change plan must be
	// applied first.
	PathReasonFirewallPending = "firewall_pending"
	// PathReasonBeaconSourcePending: the same on a target NetGuard does not
	// manage: the source is not in the applied plan's source set, so the
	// target holds no key for it.
	PathReasonBeaconSourcePending = "beacon_source_pending"
	// PathReasonRefusedByNode: the target's agent runs with -no-beacon.
	PathReasonRefusedByNode = "refused_by_node"
	// PathReasonBeaconNotListening: the target reports no socket (bind
	// failure, circuit breaker), or the source's connected socket read
	// ECONNREFUSED (reported on results).
	PathReasonBeaconNotListening = "beacon_not_listening"
	// PathReasonBeaconFiltered: every request of every recent run was lost
	// on a path that has never had a reply. Judged by the control plane, as
	// icmp_filtered is; once a path has succeeded, all-loss reads down.
	PathReasonBeaconFiltered = "beacon_filtered"
	// PathReasonBeaconStale: the responder answered beacon.StatusStale: the
	// source's clock is more than a minute from the target's.
	PathReasonBeaconStale = "beacon_stale"
	// PathReasonBeaconUnknownEpoch: the responder answered
	// beacon.StatusUnknownEpoch: the source sent with a retired key.
	PathReasonBeaconUnknownEpoch = "beacon_unknown_epoch"
	// PathReasonBeaconRateLimited: the responder answered
	// beacon.StatusRateLimited.
	PathReasonBeaconRateLimited = "beacon_rate_limited"
	// PathReasonBeaconNoKey: the source holds no path key for the target
	// (its configuration has not caught up). Reported on results.
	PathReasonBeaconNoKey = "beacon_no_key"
)
