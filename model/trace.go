package model

import "time"

// sing-box trace: the shared contract between agent, server, and dashboard.
//
// Design: Lattice/SINGBOX-TRACE-DESIGN.md. Two facts from the V1/V2 rig on a
// real v1.13.14 binary shape most of what follows, and both are counterintuitive
// enough to restate here:
//
//   - sing-box emits to Clash API subscribers WITHOUT applying log.level
//     (log/observable.go: subscriber.Emit sits outside the level guard). So the
//     effective verbosity is the agent's subscription, changed without touching
//     the node's config and without restarting the core. Restarting is what
//     drops every live connection, so this is the whole point.
//   - a connection shorter than the /connections sampling interval is never
//     sampled, so its byte counts are UNKNOWN, not zero. BytesKnown carries
//     that distinction; nothing may render a zero it did not measure.

// TraceLevel is the verbosity of a sing-box log subscription. It is NOT the
// node's log.level (which stays at whatever the config says and governs only
// what lands on disk).
type TraceLevel string

const (
	// TraceLevelInfo carries connection accept, authenticated user, outbound,
	// and close. It is enough to assemble a ConnRecord and is the always-on
	// default.
	TraceLevelInfo TraceLevel = "info"
	// TraceLevelDebug adds rule matches, sniffing results, and DNS.
	TraceLevelDebug TraceLevel = "debug"
	// TraceLevelTrace adds the cancel-path close lines.
	TraceLevelTrace TraceLevel = "trace"
)

// ValidTraceLevel reports whether l is one of the three known levels. Callers
// fail closed on false rather than defaulting, because silently collecting at
// the wrong verbosity is both a cost and a privacy surprise.
func ValidTraceLevel(l TraceLevel) bool {
	switch l {
	case TraceLevelInfo, TraceLevelDebug, TraceLevelTrace:
		return true
	}
	return false
}

// TraceLevelAtLeast reports whether have is at least as verbose as want.
func TraceLevelAtLeast(have, want TraceLevel) bool {
	return traceLevelRank(have) >= traceLevelRank(want)
}

func traceLevelRank(l TraceLevel) int {
	switch l {
	case TraceLevelDebug:
		return 1
	case TraceLevelTrace:
		return 2
	default:
		return 0
	}
}

// TracePolicy is the per-node collection policy: the always-on floor. It is an
// agent behaviour setting, not a node config change, so it is audited but does
// not go through the approval chain.
type TracePolicy struct {
	NodeID  string `json:"node_id"`
	Enabled bool   `json:"enabled"`
	// Level is the floor for this node. The agent subscribes at the max of this
	// and every running session's level.
	Level TraceLevel `json:"level"`
	// BudgetLinesPerSec caps ingest for this node. Over budget the agent drops
	// oldest and counts; the count is reported and displayed, never hidden.
	BudgetLinesPerSec int `json:"budget_lines_per_sec"`
	// ClashAPIAddr is the loopback address of the node's sing-box Clash API,
	// e.g. "127.0.0.1:9090". Never a routable address.
	ClashAPIAddr string `json:"clash_api_addr,omitempty"`
	// SecretPath is where the agent reads the Clash API secret on the node. The
	// secret itself never travels to the server and is never stored here.
	SecretPath string    `json:"secret_path,omitempty"`
	UpdatedAt  time.Time `json:"updated_at,omitzero"`

	// LastCoreGeneration and LastCoreStartedAt are the newest sing-box process
	// instance this node reported. A change is a restart, and recording it here
	// means a restart on an idle node is still visible even though it swept no
	// connections.
	LastCoreGeneration uint64    `json:"last_core_generation,omitempty"`
	LastCoreStartedAt  time.Time `json:"last_core_started_at,omitzero"`
}

// TraceFilter selects what a session captures. Empty fields mean "no constraint
// on this dimension"; a filter with every field empty matches the whole node,
// which is legal but is what the budget exists to survive.
type TraceFilter struct {
	UserIDs   []string `json:"user_ids,omitempty"`
	LineUUIDs []string `json:"line_uuids,omitempty"`
	NodeIDs   []string `json:"node_ids,omitempty"`
	// DstPatterns are case-insensitive substrings matched against the
	// destination host. Not globs: a substring is what an operator types.
	DstPatterns []string `json:"dst_patterns,omitempty"`
}

// IsEmpty reports whether the filter constrains nothing.
func (f TraceFilter) IsEmpty() bool {
	return len(f.UserIDs) == 0 && len(f.LineUUIDs) == 0 && len(f.NodeIDs) == 0 && len(f.DstPatterns) == 0
}

// Trace session states.
const (
	TraceSessionRunning = "running"
	TraceSessionExpired = "expired"
	TraceSessionStopped = "stopped"
)

// TraceSession is a time-boxed capture. The TTL is enforced on the agent as
// well as the server, so a session still ends if the control plane goes away
// mid-capture. That is deliberate: an unbounded trace left running on a node is
// a privacy and disk problem nobody would notice.
type TraceSession struct {
	ID     string      `json:"id"`
	Name   string      `json:"name"`
	Filter TraceFilter `json:"filter"`
	Level  TraceLevel  `json:"level"`

	StartedAt time.Time `json:"started_at"`
	ExpiresAt time.Time `json:"expires_at"`
	EndedAt   time.Time `json:"ended_at,omitzero"`
	State     string    `json:"state"`

	StartedBy     string `json:"started_by"`
	CorrelationID string `json:"correlation_id,omitempty"`

	// Counters, reported back for display. Dropped is as load-bearing as Lines:
	// a capture that silently lost lines reads as a quiet network.
	Lines   uint64 `json:"lines"`
	Records uint64 `json:"records"`
	Dropped uint64 `json:"dropped"`
}

// Active reports whether the session should still be capturing at t.
func (s TraceSession) Active(t time.Time) bool {
	return s.State == TraceSessionRunning && t.Before(s.ExpiresAt)
}

// TraceAgentConfig is what an agent polls: its node policy plus the sessions
// whose filters touch this node, already expanded by the server into predicates
// this node can evaluate locally.
type TraceAgentConfig struct {
	Policy   TracePolicy         `json:"policy"`
	Sessions []TraceAgentSession `json:"sessions,omitempty"`
	// ServerTime lets the agent bound clock skew when enforcing TTLs.
	ServerTime time.Time `json:"server_time,omitzero"`
	// RawSourceID is the virtual log source that receives the node's ordinary
	// sing-box lines, the ones no capture session asked for. They go to the
	// existing bounded log store rather than the trace store, so the Logs view
	// keeps working and there is parser evidence to look at after the fact
	// instead of only assembled records. Empty means the server does not want
	// raw lines from this node.
	RawSourceID string `json:"raw_source_id,omitempty"`
}

// TraceAgentSession is one session as the agent sees it: the server has already
// turned user ids into the u_<hex> names this node actually renders, and line
// uuids into inbound tags.
type TraceAgentSession struct {
	ID        string     `json:"id"`
	Level     TraceLevel `json:"level"`
	ExpiresAt time.Time  `json:"expires_at"`
	// UserNames are sing-box inbound user names (u_<16hex>, or a legacy label).
	UserNames []string `json:"user_names,omitempty"`
	// InboundTags are sing-box inbound tags on THIS node.
	InboundTags []string `json:"inbound_tags,omitempty"`
	DstPatterns []string `json:"dst_patterns,omitempty"`
}

// MatchesAll reports whether this session captures everything on the node.
func (s TraceAgentSession) MatchesAll() bool {
	return len(s.UserNames) == 0 && len(s.InboundTags) == 0 && len(s.DstPatterns) == 0
}

// How a connection ended. Derived from the last line sing-box emitted for it;
// see SINGBOX-TRACE-DESIGN.md section 4.6 for the mapping.
const (
	CloseEOF             = "eof"              // upload/download finished
	CloseCanceled        = "canceled"         // closed, no error (trace level)
	CloseReset           = "reset"            // connection reset by peer
	CloseTimeout         = "timeout"          // i/o timeout
	CloseDialFailed      = "dial_failed"      // open connection to ... using outbound/...
	CloseAuthFailed      = "auth_failed"      // process connection from ... (no user is known)
	CloseHandshakeFailed = "handshake_failed" // TLS handshake / upload handshake
	CloseUDPIdle         = "udp_idle"         // packet upload closed, no error
	CloseCoreRestart     = "core_restart"     // core generation changed under an open connection
	// CloseUnknown is an honest gap: the stream ended, or the id never produced
	// a terminal line. It must never be rendered as a clean close.
	CloseUnknown = "unknown"
)

// How confidently a user was attributed to a connection.
const (
	UserKindManaged    = "managed"    // u_<16hex>, reversible to a Lattice user
	UserKindLegacy     = "legacy"     // a free-text operator label on a legacy ProxyUser
	UserKindDiscovered = "discovered" // a third-party adopted node's named user
	UserKindUnnamed    = "unnamed"    // sing-box logged an index, not a name
	// UserKindUnobserved means the identity was never delivered for this
	// connection, which is different from sing-box declining to name a user.
	//
	// The case that matters is multiplexing: a VLESS mux transport
	// authenticates the user on the OUTER connection, and sing-box then mints a
	// fresh log id for every inner stream. The inner streams begin at routing
	// or outbound, so no user-bearing line ever carries their id, and the Clash
	// API does not serialise the user either. The evidence does not exist under
	// that id, so calling it unnamed would blame sing-box for something it was
	// never asked. It also covers a collector that started mid-connection.
	UserKindUnobserved = "unobserved"
	UserKindUnresolved = "unresolved" // a name that no lookup could place, yet
)

// How a hop path was joined across machines.
const (
	HopConfidenceExact     = "exact"     // identity carried through the chain (carry_identity)
	HopConfidenceInferred  = "inferred"  // one candidate matched dst + window + declared edge
	HopConfidenceAmbiguous = "ambiguous" // several candidates matched; Candidates lists them
	HopConfidenceNone      = "none"      // no downstream record matched
)

// ConnRecord is one sing-box connection as assembled on the node. It is the
// central object of the whole feature: the row an operator filters, sorts, and
// opens.
type ConnRecord struct {
	// Identity of where it happened.
	NodeID      string `json:"node_id"`
	LineUUID    string `json:"line_uuid,omitempty"`
	LineHashID  string `json:"line_hash_id,omitempty"`
	InboundTag  string `json:"inbound_tag,omitempty"`
	InboundType string `json:"inbound_type,omitempty"`

	// Identity of who. UserName is what sing-box logged; UserID is the Lattice
	// user it was reversed to, empty unless UserKind is managed.
	UserName string `json:"user_name,omitempty"`
	UserID   string `json:"user_id,omitempty"`
	UserKind string `json:"user_kind,omitempty"`

	// The connection itself. LogID is sing-box's per-connection id: uint32 from
	// rand, unique enough within a process-lifetime window but NOT globally, so
	// it is a join key only together with NodeID and CoreGeneration.
	LogID   uint32 `json:"log_id"`
	Network string `json:"network,omitempty"` // tcp | udp
	SrcIP   string `json:"src_ip,omitempty"`
	SrcPort int    `json:"src_port,omitempty"`
	DstHost string `json:"dst_host,omitempty"` // as logged: hostname or ip
	DstIP   string `json:"dst_ip,omitempty"`   // resolved, when DNS lines were seen
	DstPort int    `json:"dst_port,omitempty"`

	// What the router decided.
	SniffedProtocol string `json:"sniffed_protocol,omitempty"`
	SniffedDomain   string `json:"sniffed_domain,omitempty"`
	RuleIndex       int    `json:"rule_index,omitempty"`
	RuleText        string `json:"rule_text,omitempty"`
	OutboundTag     string `json:"outbound_tag,omitempty"`
	OutboundType    string `json:"outbound_type,omitempty"`
	ChainEdgeUUID   string `json:"chain_edge_uuid,omitempty"`

	// Lifecycle.
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at,omitzero"`
	// DurationMS comes from sing-box's own elapsed counter on the final line,
	// which is more trustworthy than subtracting two agent-side timestamps.
	DurationMS int64 `json:"duration_ms,omitempty"`
	// Open marks a periodic snapshot of a still-running connection. Snapshots
	// replace each other; only the final record has Open false.
	Open bool `json:"open,omitempty"`

	// Bytes, and whether they were ever actually measured. A short connection
	// dies between /connections samples and is never counted: BytesKnown false
	// means "we did not see", not "zero".
	Upload     int64 `json:"upload,omitempty"`
	Download   int64 `json:"download,omitempty"`
	BytesKnown bool  `json:"bytes_known,omitempty"`

	// How it ended, and whether it looked stuck. StalledAt is set when a
	// connection older than the stall floor went quiet in both directions;
	// cleared if it resumes. sing-box says nothing about a stalled TCP stream,
	// so this heuristic is the only signal there is.
	CloseReason string    `json:"close_reason,omitempty"`
	CloseError  string    `json:"close_error,omitempty"`
	StalledAt   time.Time `json:"stalled_at,omitzero"`

	// CoreGeneration changes when sing-box restarts. Records from a previous
	// generation that never closed are swept to CloseCoreRestart, and the count
	// is the blast radius of that restart.
	CoreGeneration uint64 `json:"core_generation,omitempty"`

	// SessionIDs are the trace sessions that captured this connection.
	SessionIDs []string `json:"session_ids,omitempty"`
	// HopPathID groups records stitched across machines.
	HopPathID string `json:"hop_path_id,omitempty"`
}

// TraceLine is one raw sing-box log line kept because a session asked for it.
// Unlabelled lines do not come here; they stay in the existing logstore.
type TraceLine struct {
	SessionID string    `json:"session_id"`
	NodeID    string    `json:"node_id"`
	Seq       uint64    `json:"seq"`
	At        time.Time `json:"at"`
	Level     string    `json:"level"`
	LogID     uint32    `json:"log_id,omitempty"`
	Tag       string    `json:"tag,omitempty"`
	Message   string    `json:"message"`
	// Raw is the payload exactly as sing-box sent it, kept so a parser bug can
	// never destroy the evidence it failed to read.
	Raw string `json:"raw,omitempty"`
}

// TraceBatch is the agent to server envelope.
type TraceBatch struct {
	NodeID  string       `json:"node_id"`
	Records []ConnRecord `json:"records,omitempty"`
	Lines   []TraceLine  `json:"lines,omitempty"`
	// CoreGeneration and CoreStartedAt let the server detect a restart even if
	// it missed the records that the restart swept.
	CoreGeneration uint64    `json:"core_generation,omitempty"`
	CoreStartedAt  time.Time `json:"core_started_at,omitzero"`
	// Dropped counts what the agent discarded under budget since the last batch.
	Dropped uint64 `json:"dropped,omitempty"`
	// Unparsed counts lines the parser could not read. A rising number means
	// sing-box changed its format, which is the failure mode most likely to be
	// mistaken for "nothing is happening".
	Unparsed   uint64    `json:"unparsed,omitempty"`
	CapturedAt time.Time `json:"captured_at"`
}

// SourceLooksBare reports whether this value is the zero batch. The agent sends
// {node_id, batch}; a client that posts a bare TraceBatch instead still
// authenticates, because TraceBatch has its own NodeID, and then decodes into
// an empty Batch that the server would accept with 200 OK and zero records.
// Nothing would ever surface that. A batch that legitimately carries only
// counters still sets CapturedAt, so this stays false for it.
func (b TraceBatch) SourceLooksBare() bool {
	return len(b.Records) == 0 && len(b.Lines) == 0 &&
		b.CapturedAt.IsZero() && b.NodeID == "" &&
		b.Dropped == 0 && b.Unparsed == 0 && b.CoreGeneration == 0
}

// TraceMarkerKind classifies the events drawn on the trace timeline. Each comes
// from a signal Lattice already records; none is new instrumentation.
const (
	MarkerCoreRestart = "core_restart" // sing-box restarted; Count is connections swept
	MarkerConfigApply = "config_apply" // an approved apply landed on the node
	MarkerSubFetch    = "sub_fetch"    // a subscription URL was fetched by a user
	MarkerSession     = "session"      // a trace session started or ended
)

// TraceMarker is one event on the timeline.
type TraceMarker struct {
	Kind   string    `json:"kind"`
	At     time.Time `json:"at"`
	NodeID string    `json:"node_id,omitempty"`
	UserID string    `json:"user_id,omitempty"`
	Title  string    `json:"title"`
	Detail string    `json:"detail,omitempty"`
	// Count is the blast radius where one applies: connections closed by a
	// restart, nodes touched by an apply.
	Count         int    `json:"count,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
}

// HopPath is a connection stitched across machines.
type HopPath struct {
	ID         string `json:"id"`
	Confidence string `json:"confidence"`
	// RecordKeys are (node_id, core_generation, log_id) triples in hop order.
	RecordKeys []ConnRecordKey `json:"record_keys"`
	// Candidates is populated only when Confidence is ambiguous, so the operator
	// sees what the stitcher could not choose between rather than a guess.
	Candidates []ConnRecordKey `json:"candidates,omitempty"`
}

// ConnRecordKey identifies one ConnRecord.
//
// StartedAt is part of the identity, not decoration. sing-box's log id is
// rand.Uint32, so one core generation on one node can reuse it; the assembler
// deliberately splits those into two connections and the store's primary key
// keeps both. A key without StartedAt collapses them again wherever it is used,
// so a lookup returns whichever the query happened to order first and a hop
// view can walk into the wrong connection entirely.
type ConnRecordKey struct {
	NodeID         string    `json:"node_id"`
	CoreGeneration uint64    `json:"core_generation"`
	LogID          uint32    `json:"log_id"`
	StartedAt      time.Time `json:"started_at,omitzero"`
}

// KeyOf builds the full identity of a record.
func KeyOf(r ConnRecord) ConnRecordKey {
	return ConnRecordKey{
		NodeID:         r.NodeID,
		CoreGeneration: r.CoreGeneration,
		LogID:          r.LogID,
		StartedAt:      r.StartedAt,
	}
}
