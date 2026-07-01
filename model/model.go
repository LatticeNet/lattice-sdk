package model

import "time"

const (
	TaskQueued   = "queued"
	TaskLeased   = "leased"
	TaskFinished = "finished"
	TaskFailed   = "failed"
	// TaskCancelled is an operator-cancelled task. Only a queued task can be
	// cancelled (a leased task is already running on the agent and cannot be
	// reliably stopped from the server); it is then never leased.
	TaskCancelled = "cancelled"

	TerminalPending = "pending"
	TerminalOpen    = "open"
	TerminalClosed  = "closed"
	TerminalFailed  = "failed"

	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalRejected = "rejected"
	ApprovalApplied  = "applied"

	PluginStatusVerified  = "verified"
	PluginStatusInstalled = "installed"
	PluginStatusActive    = "active"
	PluginStatusDisabled  = "disabled"
)

type User struct {
	ID                 string   `json:"id"`
	Username           string   `json:"username"`
	PasswordHash       string   `json:"password_hash"`
	Scopes             []string `json:"scopes"`
	TOTPEnabled        bool     `json:"totp_enabled"`
	TOTPSecret         string   `json:"totp_secret,omitempty"`
	RecoveryCodeHashes []string `json:"recovery_code_hashes,omitempty"`
	// LastTOTPStep is the highest RFC-6238 counter accepted for this user. A
	// successful verification must present a strictly greater step, which makes
	// each code single-use and prevents replay within the validity window.
	LastTOTPStep uint64 `json:"last_totp_step,omitempty"`
	// SecurityEpoch is bumped on password change, 2FA disable, or admin revoke.
	// Sessions carry the epoch at which they were minted; a session whose epoch
	// is older than the user's current epoch is rejected, so privilege-reducing
	// events invalidate all existing sessions.
	SecurityEpoch uint64    `json:"security_epoch,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type Token struct {
	ID              string    `json:"id"`
	Name            string    `json:"name"`
	TokenHash       string    `json:"token_hash"`
	ActorID         string    `json:"actor_id"`
	Scopes          []string  `json:"scopes"`
	ServerAllowlist []string  `json:"server_allowlist"`
	RevokedAt       time.Time `json:"revoked_at,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

type Node struct {
	ID                 string   `json:"id"`
	Name               string   `json:"name"`
	Comment            string   `json:"comment,omitempty"`
	TokenHash          string   `json:"token_hash"`
	Tags               []string `json:"tags"`
	Role               string   `json:"role"`
	WireGuardIP        string   `json:"wireguard_ip"`
	WireGuardPublicKey string   `json:"wireguard_public_key,omitempty"`
	WireGuardEndpoint  string   `json:"wireguard_endpoint,omitempty"`
	WireGuardPort      int      `json:"wireguard_port,omitempty"`
	PublicIP           string   `json:"public_ip"`
	PublicIPv6         string   `json:"public_ipv6,omitempty"`
	// InternalIP / InternalIPv6 are the node's LAN/primary-interface addresses,
	// reported by the agent. Informational (not geocoded); private ranges allowed.
	InternalIP   string           `json:"internal_ip,omitempty"`
	InternalIPv6 string           `json:"internal_ipv6,omitempty"`
	AgentVersion string           `json:"agent_version"`
	Online       bool             `json:"online"`
	Disabled     bool             `json:"disabled,omitempty"`
	LastSeen     time.Time        `json:"last_seen"`
	Metrics      Metrics          `json:"metrics"`
	HostFacts    HostFacts        `json:"host_facts"`
	Geo          *NodeGeo         `json:"geo,omitempty"`
	AgentDebug   AgentDebugPolicy `json:"agent_debug"`
	// AgentLaunch is the last operator-authored installer/startup profile used
	// to generate an enrollment or reconfigure command. It is advisory desired
	// state, not proof of the currently running process flags.
	AgentLaunch *AgentLaunchConfig `json:"agent_launch,omitempty"`
	// TerminalTransport is the operator-owned per-node terminal transport: "poll"
	// (default) or "stream". Empty is treated as the deployment default. It is the
	// rollout lever for promoting the streaming terminal one node at a time; the
	// agent reads it from its polled AgentConfig and applies it to new sessions.
	TerminalTransport string `json:"terminal_transport,omitempty"`
	// IPConfig is the operator-owned, per-node override for how the agent
	// discovers its public IPs (mirrors the agent's -ip-mode/-ip-resolvers
	// flags). nil means "no override" — the agent keeps its startup flags. It is
	// pushed down through the polled AgentConfig.
	IPConfig *NodeIPConfig `json:"ip_config,omitempty"`
	// GroupIDs is the node's resolved group memberships. It is a server-computed,
	// read-only convenience field (the union of every group whose explicit
	// Members or display Selector resolves this node); it is never authored by a
	// client and is not persisted as node intent. Tags/Role remain the underlying
	// facts that selectors read.
	GroupIDs  []string  `json:"group_ids,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// AgentDebugPolicy is the operator-owned diagnostic mode for a node-agent. When
// Enabled is true the agent emits verbose non-secret diagnostics locally on the
// node. Collect controls whether those diagnostics are also shipped back to the
// server log store. Server-managed debug collection defaults to true when
// enabled, but operators may keep local node debug output without central
// collection by setting Collect=false.
type AgentDebugPolicy struct {
	Enabled   bool      `json:"enabled"`
	Collect   bool      `json:"collect"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// AgentDebugConfig is the runtime policy an agent polls from the server. It is
// intentionally small and non-secret so older agents can ignore it safely.
type AgentDebugConfig struct {
	Enabled       bool `json:"enabled"`
	Collect       bool `json:"collect"`
	MaxLineBytes  int  `json:"max_line_bytes,omitempty"`
	MaxBatchLines int  `json:"max_batch_lines,omitempty"`
}

// AgentLaunchConfig mirrors lattice-agent startup flags/env vars used by the
// dashboard's enroll/reconfigure command generator. Runtime overrides that
// already-running agents poll remain in AgentConfig instead.
type AgentLaunchConfig struct {
	AllowExec             bool      `json:"allow_exec"`
	AllowRootExec         bool      `json:"allow_root_exec"`
	NoExec                bool      `json:"no_exec"`
	AllowTerminal         bool      `json:"allow_terminal"`
	TerminalTransport     string    `json:"terminal_transport,omitempty"`
	SSHAlerts             bool      `json:"ssh_alerts"`
	SingBoxDiscover       bool      `json:"singbox_discover"`
	SingBoxBin            string    `json:"singbox_bin,omitempty"`
	ProxyUsageFile        string    `json:"proxy_usage_file,omitempty"`
	ProxyUsageURL         string    `json:"proxy_usage_url,omitempty"`
	ProxyUsageXrayAPI     string    `json:"proxy_usage_xray_api,omitempty"`
	ProxyUsageXrayBin     string    `json:"proxy_usage_xray_bin,omitempty"`
	ProxyUsageXrayPattern string    `json:"proxy_usage_xray_pattern,omitempty"`
	UpdatedAt             time.Time `json:"updated_at,omitempty"`
}

type AgentConfig struct {
	Debug AgentDebugConfig `json:"debug"`
	// TerminalTransport is the server's per-node override for the agent terminal
	// transport: "poll" or "stream". Empty means "no override" — the agent keeps
	// its startup -terminal-transport / LATTICE_TERMINAL_TRANSPORT value. This is
	// the rollout lever for promoting streaming per node without a redeploy; it
	// affects only sessions opened after the change, never in-flight ones.
	TerminalTransport string `json:"terminal_transport,omitempty"`
	// IPConfig is the server's per-node override for public-IP discovery. nil
	// means "no override" — the agent keeps its startup -ip-mode/-ip-resolvers
	// flags. Old agents that do not know this field ignore it safely.
	IPConfig *NodeIPConfig `json:"ip_config,omitempty"`
}

const (
	NodeIPModeAuto     = "auto"     // static override if set, else resolver probe
	NodeIPModeStatic   = "static"   // use the operator-provided static IPs only
	NodeIPModeResolver = "resolver" // always probe the resolvers, ignore static
	NodeIPModeScript   = "script"   // run an operator-provided script on the agent
)

// NodeIPConfig is the operator-owned, per-node override for how the agent
// determines its public IPs. It mirrors the agent's -ip-mode / -ip-resolvers /
// -public-ip startup flags so the server can push a change without a redeploy.
// An empty Mode means "no override". Script discovery is high-trust node-local
// code: the server stores Script for the agent only, and read-facing node views
// should redact Script while keeping ScriptSHA256 for operator confirmation.
type NodeIPConfig struct {
	Mode         string    `json:"mode,omitempty"` // "" | auto | static | resolver | script
	StaticIPv4   string    `json:"static_ipv4,omitempty"`
	StaticIPv6   string    `json:"static_ipv6,omitempty"`
	Resolvers    []string  `json:"resolvers,omitempty"` // IP-echo URLs; empty = agent defaults
	Script       string    `json:"script,omitempty"`    // server->agent only; redact from node views
	ScriptSHA256 string    `json:"script_sha256,omitempty"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

// AgentDebugBatch carries locally emitted agent diagnostics to the server log
// store when server-side collection is enabled for the node.
type AgentDebugBatch struct {
	NodeID     string    `json:"node_id"`
	Lines      []string  `json:"lines"`
	CapturedAt time.Time `json:"captured_at"`
}

// AgentUpdatePolicy is a server-owned node-agent update intent. It carries no
// secrets: operators provide a public HTTPS binary URL plus the expected SHA-256
// digest, and the server turns that into a reviewed, plan-hash-bound update
// task. AutoPlan never mutates a node directly; it only creates a pending
// approval when the node reports a different AgentVersion and no equivalent
// pending/approved update is already open.
type AgentUpdatePolicy struct {
	NodeID             string    `json:"node_id"`
	Enabled            bool      `json:"enabled"`
	AutoPlan           bool      `json:"auto_plan"`
	TargetVersion      string    `json:"target_version"`
	BinaryURL          string    `json:"binary_url"`
	SHA256             string    `json:"sha256"`
	InstallPath        string    `json:"install_path"`
	ServiceName        string    `json:"service_name"`
	LastPlannedVersion string    `json:"last_planned_version,omitempty"`
	LastPlannedAt      time.Time `json:"last_planned_at,omitempty"`
	LastAppliedVersion string    `json:"last_applied_version,omitempty"`
	LastAppliedAt      time.Time `json:"last_applied_at,omitempty"`
	LastError          string    `json:"last_error,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

type Metrics struct {
	CPUPercent  float64 `json:"cpu_percent"`
	Load1       float64 `json:"load1"`
	Load5       float64 `json:"load5"`
	Load15      float64 `json:"load15"`
	MemoryUsed  uint64  `json:"memory_used"`
	MemoryTotal uint64  `json:"memory_total"`
	DiskUsed    uint64  `json:"disk_used"`
	DiskTotal   uint64  `json:"disk_total"`
	NetRxBytes  uint64  `json:"net_rx_bytes"`
	NetTxBytes  uint64  `json:"net_tx_bytes"`
	// NetRxSpeed / NetTxSpeed are bytes-per-second rates the agent derives from
	// the delta of the cumulative byte counters between two metrics cycles. The
	// first cycle after agent start (no prior sample) and any counter reset both
	// report 0. Dashboards read these for live bandwidth; the cumulative
	// NetRxBytes/NetTxBytes remain the source of truth.
	NetRxSpeed    float64   `json:"net_rx_speed"`
	NetTxSpeed    float64   `json:"net_tx_speed"`
	UptimeSeconds uint64    `json:"uptime_seconds"`
	CollectedAt   time.Time `json:"collected_at"`
}

// HostFacts are auto-detected, slow-changing machine facts reported by the
// node-agent. They are advisory low-trust telemetry: useful for display,
// inventory and map planning, but never for authorization decisions.
type HostFacts struct {
	Hostname        string    `json:"hostname,omitempty"`
	OS              string    `json:"os,omitempty"`
	Platform        string    `json:"platform,omitempty"`
	PlatformVersion string    `json:"platform_version,omitempty"`
	KernelVersion   string    `json:"kernel_version,omitempty"`
	Arch            string    `json:"arch,omitempty"`
	CPUCores        int       `json:"cpu_cores,omitempty"`
	CPUModel        string    `json:"cpu_model,omitempty"`
	MemoryTotal     uint64    `json:"memory_total,omitempty"`
	SwapTotal       uint64    `json:"swap_total,omitempty"`
	Virtualization  string    `json:"virtualization,omitempty"`
	BootTime        time.Time `json:"boot_time,omitempty"`
	ReportedAt      time.Time `json:"reported_at,omitempty"`
}

const (
	RenewalCycleMonthly    = "monthly"
	RenewalCycleQuarterly  = "quarterly"
	RenewalCycleSemiannual = "semiannual"
	RenewalCycleAnnual     = "annual"
	RenewalCycleCustomDays = "custom_days"
)

// MachineProfile is operator-authored inventory, cost, and renewal metadata for
// a node. It is server-only control-plane state: it must never be sent to an
// agent or used by an agent. ConsoleURL and DetailURL may carry account-specific
// or signed links and are encrypted at rest by lattice-server.
type MachineProfile struct {
	ID     string `json:"id"`
	NodeID string `json:"node_id"`
	Label  string `json:"label,omitempty"`

	Vendor     string `json:"vendor,omitempty"`
	ConsoleURL string `json:"console_url,omitempty"`
	DetailURL  string `json:"detail_url,omitempty"`
	Region     string `json:"region,omitempty"`
	Notes      string `json:"notes,omitempty"`

	PriceCents int64  `json:"price_cents,omitempty"`
	Currency   string `json:"currency,omitempty"`

	RenewalCycle string    `json:"renewal_cycle,omitempty"`
	CycleDays    int       `json:"cycle_days,omitempty"`
	NextRenewal  time.Time `json:"next_renewal,omitempty"`
	AutoRoll     bool      `json:"auto_roll"`

	RemindDaysBefore []int  `json:"remind_days_before,omitempty"`
	RemindersEnabled bool   `json:"reminders_enabled"`
	LastRemindedKey  string `json:"last_reminded_key,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// NFTInputs are the authoritative, server-owned baseline nftables inputs for a
// single node. Other core providers (DNS, per-node ACL, proxy cores) compose
// their required ports/rules into this shape before rendering the one
// lattice_guard table; they must not create competing nft tables.
type NFTInputs struct {
	ID     string `json:"id"`
	NodeID string `json:"node_id"`

	InterfaceName string `json:"interface_name,omitempty"`
	WireGuardCIDR string `json:"wireguard_cidr,omitempty"`

	PublicTCP    []int `json:"public_tcp,omitempty"`
	PublicUDP    []int `json:"public_udp,omitempty"`
	WireGuardTCP []int `json:"wireguard_tcp,omitempty"`
	WireGuardUDP []int `json:"wireguard_udp,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

const (
	DNSEngineCoreDNS = "coredns"

	DNSExposureMesh   = "mesh"
	DNSExposurePublic = "public"

	DNSZoneForward = "forward"
	DNSZoneStatic  = "static"
	DNSZoneBlock   = "block"

	DNSStatusPending  = "pending"
	DNSStatusApplying = "applying"
	DNSStatusRunning  = "running"
	DNSStatusFailed   = "failed"
	DNSStatusDisabled = "disabled"
)

// DNSZone is one served block in a self-hosted resolver configuration. It is
// server-owned intent; the agent only receives the rendered, approved artifact.
type DNSZone struct {
	Suffix    string      `json:"suffix"`
	Mode      string      `json:"mode"`
	Upstreams []string    `json:"upstreams,omitempty"`
	Records   []DNSRecord `json:"records,omitempty"`
}

// DNSRecord is a static authoritative record for a DNSZoneStatic zone.
type DNSRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl,omitempty"`
}

// DNSDeployment is the control-plane intent for a self-hosted DNS service on a
// node. CFAPIToken is a server-side secret and must never appear in read views
// or agent payloads.
type DNSDeployment struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	NodeID string `json:"node_id"`
	Engine string `json:"engine"`

	ListenPort int    `json:"listen_port"`
	EnableUDP  bool   `json:"enable_udp"`
	EnableTCP  bool   `json:"enable_tcp"`
	Exposure   string `json:"exposure"`

	Zones []DNSZone `json:"zones"`

	Hostname      string `json:"hostname,omitempty"`
	PublishIPv4   bool   `json:"publish_ipv4"`
	PublishIPv6   bool   `json:"publish_ipv6"`
	RecordTTL     int    `json:"record_ttl,omitempty"`
	CFAPIToken    string `json:"cf_api_token,omitempty"`
	DDNSProfileID string `json:"ddns_profile_id,omitempty"`

	Status           string    `json:"status"`
	EngineVersion    string    `json:"engine_version,omitempty"`
	LastIPv4         string    `json:"last_ipv4,omitempty"`
	LastIPv6         string    `json:"last_ipv6,omitempty"`
	LastAppliedAt    time.Time `json:"last_applied_at,omitempty"`
	LastError        string    `json:"last_error,omitempty"`
	LastPublishedAt  time.Time `json:"last_published_at,omitempty"`
	LastPublishError string    `json:"last_publish_error,omitempty"`
	Disabled         bool      `json:"disabled,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// GeoRouting answers one apex hostname (e.g. dns.roobli.org) with the nearest
// healthy participating node, served by Lattice's own DNS nodes (Design 06,
// Path B). It carries no secrets: the NS-delegation token is reused from the
// referenced DDNSProfile.
type GeoRouting struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Hostname    string   `json:"hostname"`     // the geo apex, e.g. dns.roobli.org
	NodeIDs     []string `json:"node_ids"`     // participating targets (need NodeGeo + IP)
	DNSNodeIDs  []string `json:"dns_node_ids"` // authoritative DNS nodes (run self-host DNS)
	TTL         int      `json:"ttl,omitempty"`
	Strategy    string   `json:"strategy"`                // "geoip" | "all-healthy"
	GeoIPDBPath string   `json:"geoip_db_path,omitempty"` // GeoLite2 path on the node

	// Parent-zone NS delegation reuses the referenced DDNSProfile's CF token.
	PublishNS     bool   `json:"publish_ns,omitempty"`
	DDNSProfileID string `json:"ddns_profile_id,omitempty"`

	LastRenderedSHA string    `json:"last_rendered_sha,omitempty"`
	Status          string    `json:"status,omitempty"`
	LastAppliedAt   time.Time `json:"last_applied_at,omitempty"`
	LastDelegatedAt time.Time `json:"last_delegated_at,omitempty"`
	LastError       string    `json:"last_error,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

const (
	GeoRoutingStrategyGeoIP      = "geoip"
	GeoRoutingStrategyAllHealthy = "all-healthy"
)

const (
	NetRuleAllow = "allow"
	NetRuleDeny  = "deny"

	NetDirEgress  = "egress"
	NetDirIngress = "ingress"

	NetProtoTCP = "tcp"
	NetProtoUDP = "udp"
	NetProtoAny = "any"

	NetRefNode   = "node"
	NetRefCIDR   = "cidr"
	NetRefDomain = "domain"
	NetRefAny    = "any"
	// NetRefGroup is a group-scoped remote. It is an authoring-layer kind only:
	// the server expands it to one concrete node ref per resolved group member
	// before compilation, so the per-node nft compiler never sees a group ref.
	NetRefGroup = "group"
)

// NetEndpoint describes the non-target side of a policy rule. Node refs are
// resolved by the server at validation/graph/compile time. Domain refs are
// egress-only and compile to named nft sets that the node refreshes through the
// agent's DNS updater; they are not accepted as ingress identity.
type NetEndpoint struct {
	Kind    string `json:"kind"`
	NodeID  string `json:"node_id,omitempty"`
	CIDR    string `json:"cidr,omitempty"`
	Domain  string `json:"domain,omitempty"`
	GroupID string `json:"group_id,omitempty"` // set when Kind == NetRefGroup; resolved to node refs before compile
}

// NetRule is an ordered operator-authored L3/L4 policy rule evaluated on the
// target node. Empty Ports means all ports for the selected protocol.
type NetRule struct {
	ID        string      `json:"id"`
	Comment   string      `json:"comment,omitempty"`
	Action    string      `json:"action"`
	Direction string      `json:"direction"`
	Protocol  string      `json:"protocol"`
	Ports     []int       `json:"ports,omitempty"`
	Remote    NetEndpoint `json:"remote"`
	Disabled  bool        `json:"disabled,omitempty"`
}

// NetPolicy is the per-node network intent document. It is control-plane state
// only: the agent does not receive it directly. A later iteration compiles this
// policy into nft with dead-man rollback.
type NetPolicy struct {
	ID           string    `json:"id"`
	TargetNodeID string    `json:"target_node_id"`
	Rules        []NetRule `json:"rules"`
	Enabled      bool      `json:"enabled"`
	// GroupDerived marks a per-node policy materialized from one or more
	// GroupNetPolicy documents (server-side expansion). Manually-authored
	// per-node policies leave it false. Materialization refuses to overwrite a
	// manual policy, so the two authoring lanes never silently clobber.
	GroupDerived  bool      `json:"group_derived,omitempty"`
	LastPlanSHA   string    `json:"last_plan_sha,omitempty"`
	LastAppliedAt time.Time `json:"last_applied_at,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Group is a first-class fleet organization entity. A node's policy-relevant
// membership is the explicit Members list (the canonical source of truth);
// Selector is a display-only "smart filter" used to suggest/filter on the
// dashboard and to seed groups during migration — it never silently changes a
// firewall. Color is a design-token name (e.g. "sky", "violet"), never a raw
// hex value, so the dashboard stays CSP-safe. Slug is url/nft-safe, unique, and
// treated as immutable once assigned. ParentID gives a single-parent hierarchy
// ("" = root); Order is the operator-controlled sort weight within a parent.
type Group struct {
	ID          string         `json:"id"`   // "grp_<ulid>"
	Name        string         `json:"name"` // unique, display
	Slug        string         `json:"slug"` // url/nft-safe, unique, immutable
	Description string         `json:"description,omitempty"`
	Color       string         `json:"color"`               // design-token name, never raw hex (CSP)
	Icon        string         `json:"icon,omitempty"`      // lucide icon name
	ParentID    string         `json:"parent_id,omitempty"` // single parent; "" = root
	Order       int            `json:"order"`               // sort weight within the parent
	Members     []string       `json:"members"`             // explicit node IDs — the CANONICAL membership
	Selector    *GroupSelector `json:"selector,omitempty"`  // DISPLAY-ONLY smart filter, not a policy input
	// LeaderID is the operator-designated group leader. It must be an explicit
	// Member of the group (validated on upsert); empty means "no leader". This is
	// the real, first-class field that replaces the old role-name heuristic used
	// by the dashboard to mark a node as its group's leader.
	LeaderID  string    `json:"leader_id,omitempty"`
	System    bool      `json:"system,omitempty"` // built-in (e.g. "Ungrouped"); limited edits
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// GroupSelector is a read-only "smart group" used only for dashboard filtering
// and migration seeding. It is NOT a policy input: the compiler never reads it,
// so a spoofed tag can mis-scope display but cannot bypass per-node nft. Each
// field is an OR-set; a node matches the selector when it satisfies any one of
// the populated criteria (tags-any / roles / country / continent).
type GroupSelector struct {
	MatchTagsAny   []string `json:"match_tags_any,omitempty"`
	MatchRoles     []string `json:"match_roles,omitempty"`
	MatchCountry   []string `json:"match_country,omitempty"`   // ISO-3166 alpha-2 codes
	MatchContinent []string `json:"match_continent,omitempty"` // AS/EU/NA/SA/AF/OC/AN
}

// GroupNetPolicy is a group-scoped authoring layer over the unchanged per-node
// NetPolicy engine. The server expands it into one NetPolicy per member of
// ScopeGroupID before compilation; the agent never receives it. Priority breaks
// ties when a node is a member of two or more scoped groups (lower wins).
type GroupNetPolicy struct {
	ID           string         `json:"id"`             // "gnp_<ulid>"
	ScopeGroupID string         `json:"scope_group_id"` // applies to members of this group
	Rules        []GroupNetRule `json:"rules"`
	Enabled      bool           `json:"enabled"`
	Priority     int            `json:"priority"` // lower wins when a node is in 2+ scoped groups
	CreatedAt    time.Time      `json:"created_at"`
	UpdatedAt    time.Time      `json:"updated_at"`
}

// GroupNetRule mirrors NetRule but its Remote may additionally be a group ref
// (Remote.Kind == NetRefGroup with Remote.GroupID set). The server fans a group
// remote out to one node-ref rule per resolved remote member during expansion,
// so the compiled per-node rule set only ever contains node/cidr/domain/any
// remotes.
type GroupNetRule struct {
	ID        string      `json:"id"`
	Comment   string      `json:"comment,omitempty"`
	Action    string      `json:"action"`
	Direction string      `json:"direction"`
	Protocol  string      `json:"protocol"`
	Ports     []int       `json:"ports,omitempty"`
	Remote    NetEndpoint `json:"remote"` // Kind may be NetRefGroup in addition to node|cidr|domain|any
	Disabled  bool        `json:"disabled,omitempty"`
}

const (
	ProxyCoreSingbox = "sing-box"
	ProxyCoreXray    = "xray"

	ProxyProtocolVLESS       = "vless"
	ProxyProtocolVMess       = "vmess"
	ProxyProtocolTrojan      = "trojan"
	ProxyProtocolShadowsocks = "shadowsocks"
	ProxyProtocolHysteria2   = "hysteria2"

	ProxyTransportTCP   = "tcp"
	ProxyTransportWS    = "ws"
	ProxyTransportGRPC  = "grpc"
	ProxyTransportHTTP2 = "http2"
	ProxyTransportQUIC  = "quic"

	ProxySecurityNone    = "none"
	ProxySecurityTLS     = "tls"
	ProxySecurityReality = "reality"

	ProxyUserStatusActive    = "active"
	ProxyUserStatusExpired   = "expired"
	ProxyUserStatusOverQuota = "over_quota"
	ProxyUserStatusDisabled  = "disabled"

	ProxyUsageCollectorStatusOK    = "ok"
	ProxyUsageCollectorStatusError = "error"
)

// ProxyInbound is the central protocol/transport template that the server
// renders into node-local sing-box/xray config. RealityPrivateKey is a
// server-side secret and must never appear in API views or agent payloads.
type ProxyInbound struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Core     string `json:"core"`
	Protocol string `json:"protocol"`
	Listen   string `json:"listen,omitempty"`
	Port     int    `json:"port"`

	Transport string `json:"transport,omitempty"`
	Path      string `json:"path,omitempty"`
	Host      string `json:"host,omitempty"`

	Security    string   `json:"security,omitempty"`
	SNI         string   `json:"sni,omitempty"`
	ALPN        []string `json:"alpn,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`

	CertPath string `json:"cert_path,omitempty"`
	KeyPath  string `json:"key_path,omitempty"`

	RealityPrivateKey string   `json:"reality_private_key,omitempty"`
	RealityPublicKey  string   `json:"reality_public_key,omitempty"`
	RealityShortIDs   []string `json:"reality_short_ids,omitempty"`
	RealityDest       string   `json:"reality_dest,omitempty"`

	SSMethod string `json:"ss_method,omitempty"`

	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ProxyUser is a central subscriber identity. UUID, Password and SubToken are
// bearer credential material; they are encrypted at rest and only surfaced
// through one-time/admin rotation flows, never through list/read views.
type ProxyUser struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`

	UUID     string `json:"uuid,omitempty"`
	Password string `json:"password,omitempty"`
	SubToken string `json:"sub_token,omitempty"`

	InboundIDs        []string  `json:"inbound_ids,omitempty"`
	TrafficLimitBytes int64     `json:"traffic_limit_bytes,omitempty"`
	ExpiresAt         time.Time `json:"expires_at,omitempty"`

	UsedBytes  int64     `json:"used_bytes"`
	LastSeenAt time.Time `json:"last_seen_at,omitempty"`
	Status     string    `json:"status"`

	// Server-managed notification cursors. They prevent repeated quota/expiry
	// alerts after the operator has already been notified for the current limit
	// or expiry date.
	LastQuotaNotifiedKey  string `json:"last_quota_notified_key,omitempty"`
	LastExpiryNotifiedKey string `json:"last_expiry_notified_key,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ProxyNodeProfile binds the central proxy model to a single node. One profile
// exists per node; it is the unit rendered into a reviewed plan/apply task.
type ProxyNodeProfile struct {
	ID         string   `json:"id"`
	NodeID     string   `json:"node_id"`
	Core       string   `json:"core"`
	InboundIDs []string `json:"inbound_ids"`
	Hostname   string   `json:"hostname,omitempty"`
	ListenIP   string   `json:"listen_ip,omitempty"`

	ConfigPath string `json:"config_path,omitempty"`
	StatsAPI   string `json:"stats_api,omitempty"`

	AppliedSHA256 string    `json:"applied_sha256,omitempty"`
	LastApplyAt   time.Time `json:"last_apply_at,omitempty"`
	LastError     string    `json:"last_error,omitempty"`

	// Usage collector health is agent-reported and server persisted for
	// operator visibility. It is not client-editable policy and must not affect
	// the server's monotonic usage accounting.
	UsageCollectorSource      string    `json:"usage_collector_source,omitempty"`
	UsageCollectorStatus      string    `json:"usage_collector_status,omitempty"`
	UsageCollectorCheckedAt   time.Time `json:"usage_collector_checked_at,omitempty"`
	UsageCollectorLastOKAt    time.Time `json:"usage_collector_last_ok_at,omitempty"`
	UsageCollectorLastError   string    `json:"usage_collector_last_error,omitempty"`
	UsageCollectorLastErrorAt time.Time `json:"usage_collector_last_error_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ProxyUsageSnapshot is the last node-reported accounting snapshot. The server
// later diffs successive snapshots to advance ProxyUser.UsedBytes monotonically.
type ProxyUsageSnapshot struct {
	NodeID        string           `json:"node_id"`
	At            time.Time        `json:"at"`
	CoreUptimeSec uint64           `json:"core_uptime_sec"`
	UserBytes     map[string]int64 `json:"user_bytes"`
	// LineUserBytes optionally carries cumulative counters split by stable
	// line_hash_id and proxy user id. It is additive to UserBytes so old
	// collectors remain valid; if a collector sends only line_user_bytes, agents
	// and servers may derive user_bytes by summing per-user line counters.
	LineUserBytes map[string]map[string]int64 `json:"line_user_bytes,omitempty"`

	// Collector fields describe this collection attempt. They let the agent
	// report local collector errors without overwriting the previous accounting
	// baseline on the server.
	CollectorSource    string    `json:"collector_source,omitempty"` // file | http | future core transport
	CollectorStatus    string    `json:"collector_status,omitempty"` // ok | error
	CollectorError     string    `json:"collector_error,omitempty"`
	CollectorCheckedAt time.Time `json:"collector_checked_at,omitempty"`
}

// SingBoxNode is one inbound discovered on a node by reading its on-box sing-box
// management state (the 233boy `sb --json list` output). It is the adoption-model
// view of a proxy that exists on the machine but is NOT (necessarily) managed by
// Lattice's own proxy store — the bridge that lets the dashboard see proxies on
// machines provisioned out-of-band. Secret-free: share_url already encodes the
// connection without exposing additional server-side material.
type SingBoxNode struct {
	Name        string            `json:"name"`
	Protocol    string            `json:"protocol,omitempty"`
	Network     string            `json:"network,omitempty"`
	Address     string            `json:"address,omitempty"`
	Port        string            `json:"port,omitempty"`
	SNI         string            `json:"sni,omitempty"`
	Host        string            `json:"host,omitempty"`
	ListenHost  string            `json:"listen_host,omitempty"`
	OutboundRef string            `json:"outbound_ref,omitempty"`
	UserCount   int               `json:"user_count,omitempty"`
	UserKnown   bool              `json:"user_known,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	PublicKey   string            `json:"public_key,omitempty"`
	ShareURL    string            `json:"share_url,omitempty"`
}

// SingBoxInventory is the latest snapshot of the sing-box nodes discovered on one
// machine. It is reported by the agent (read-only `sb --json list`) and held in
// memory on the server as a live mirror — it is re-reported each interval and is
// not persisted (a restart simply waits for the next report). Status/Error let a
// node report a discovery failure (e.g. sb not installed) without a stale list.
type SingBoxInventory struct {
	NodeID      string        `json:"node_id"`
	At          time.Time     `json:"at"`
	CoreVersion string        `json:"core_version,omitempty"`
	Nodes       []SingBoxNode `json:"nodes"`
	Status      string        `json:"status,omitempty"` // ok | error
	Error       string        `json:"error,omitempty"`
}

// NodeGeo is map metadata for a node. Operator-entered values are authoritative;
// automatic GeoIP values are advisory and should not overwrite operator values
// unless an operator explicitly asks for that replacement.
type NodeGeo struct {
	Country   string    `json:"country,omitempty"`
	Region    string    `json:"region,omitempty"`
	City      string    `json:"city,omitempty"`
	Lat       float64   `json:"lat,omitempty"`
	Lon       float64   `json:"lon,omitempty"`
	IP        string    `json:"ip,omitempty"`
	ASN       int       `json:"asn,omitempty"`
	ASOrg     string    `json:"as_org,omitempty"`
	Provider  string    `json:"provider,omitempty"`
	Source    string    `json:"source,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

type Task struct {
	ID            string               `json:"id"`
	ApprovalID    string               `json:"approval_id,omitempty"`
	ActorID       string               `json:"actor_id"`
	TokenID       string               `json:"token_id"`
	Targets       []string             `json:"targets"`
	Interpreter   string               `json:"interpreter"`
	Script        string               `json:"script"`
	TimeoutSec    int                  `json:"timeout_sec"`
	OutputLimit   int                  `json:"output_limit"`
	Status        string               `json:"status"`
	LeaseID       string               `json:"lease_id,omitempty"`
	LeasedBy      string               `json:"leased_by,omitempty"`
	TargetLeases  map[string]TaskLease `json:"target_leases,omitempty"`
	RerunOfTaskID string               `json:"rerun_of_task_id,omitempty"`
	RerunOfNodeID string               `json:"rerun_of_node_id,omitempty"`
	CreatedAt     time.Time            `json:"created_at"`
	StartedAt     time.Time            `json:"started_at,omitempty"`
	FinishedAt    time.Time            `json:"finished_at,omitempty"`
}

type TaskLease struct {
	LeaseID   string    `json:"lease_id"`
	StartedAt time.Time `json:"started_at,omitempty"`
}

type TaskResult struct {
	TaskID     string    `json:"task_id"`
	LeaseID    string    `json:"lease_id,omitempty"`
	NodeID     string    `json:"node_id"`
	ExitCode   int       `json:"exit_code"`
	Stdout     string    `json:"stdout"`
	Stderr     string    `json:"stderr"`
	Error      string    `json:"error"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
}

type TerminalSession struct {
	ID        string    `json:"id"`
	NodeID    string    `json:"node_id"`
	ActorID   string    `json:"actor_id,omitempty"`
	TokenID   string    `json:"token_id,omitempty"`
	Shell     string    `json:"shell,omitempty"`
	Cols      int       `json:"cols,omitempty"`
	Rows      int       `json:"rows,omitempty"`
	Status    string    `json:"status"`
	Error     string    `json:"error,omitempty"`
	BytesIn   int64     `json:"bytes_in,omitempty"`
	BytesOut  int64     `json:"bytes_out,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	OpenedAt  time.Time `json:"opened_at,omitempty"`
	ClosedAt  time.Time `json:"closed_at,omitempty"`
	LastSeen  time.Time `json:"last_seen,omitempty"`
}

type TerminalEvent struct {
	Seq       int64     `json:"seq"`
	Kind      string    `json:"kind"`
	Data      string    `json:"data,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type TerminalInput struct {
	Seq       int64     `json:"seq"`
	Kind      string    `json:"kind"`
	Data      string    `json:"data,omitempty"`
	Cols      int       `json:"cols,omitempty"`
	Rows      int       `json:"rows,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type AuditEvent struct {
	ID            string            `json:"id"`
	At            time.Time         `json:"at"`
	ActorID       string            `json:"actor_id"`
	TokenID       string            `json:"token_id"`
	NodeID        string            `json:"node_id"`
	Action        string            `json:"action"`
	Scope         string            `json:"scope"`
	Decision      string            `json:"decision"`
	Reason        string            `json:"reason"`
	CorrelationID string            `json:"correlation_id"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

// APIError is the stable machine-readable error shape shared by server,
// dashboard, agents and plugins. Messages are user-facing; callers should make
// authorization and retry decisions from Code.
type APIError struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	RequestID string `json:"request_id"`
}

type APIErrorResponse struct {
	Error APIError `json:"error"`
}

const (
	APIErrorBadRequest       = "bad_request"
	APIErrorUnauthorized     = "unauthorized"
	APIErrorForbidden        = "forbidden"
	APIErrorNotFound         = "not_found"
	APIErrorMethodNotAllowed = "method_not_allowed"
	APIErrorRateLimited      = "rate_limited"
	APIErrorBadGateway       = "bad_gateway"
	APIErrorInternal         = "internal_error"
	APIErrorRequestFailed    = "request_failed"

	APIErrorCapabilityDenied        = "capability_denied"
	APIErrorApprovalStale           = "approval_stale"
	APIErrorAgentUpdateNoop         = "agent_update_noop"
	APIErrorInvalidNodeToken        = "invalid_node_token"
	APIErrorInvalidTaskLease        = "invalid_task_lease"
	APIErrorTaskOutputLimitExceeded = "task_output_limit_exceeded"
)

type KVEntry struct {
	Bucket    string    `json:"bucket"`
	Key       string    `json:"key"`
	Value     string    `json:"value"`
	UpdatedAt time.Time `json:"updated_at"`
}

type StaticObject struct {
	Bucket      string    `json:"bucket"`
	Path        string    `json:"path"`
	Content     string    `json:"content"`
	ContentType string    `json:"content_type"`
	Size        int       `json:"size"`
	UpdatedAt   time.Time `json:"updated_at"`
}

const (
	StorageKindKV     = "kv"
	StorageKindStatic = "static"

	StorageAccessAdmin = "admin"
	StorageAccessRead  = "read"
	StorageAccessWrite = "write"
)

type StorageBucket struct {
	ID               string    `json:"id"`
	Kind             string    `json:"kind"`
	Name             string    `json:"name"`
	DisplayName      string    `json:"display_name,omitempty"`
	Description      string    `json:"description,omitempty"`
	IndexDocument    string    `json:"index_document,omitempty"`
	NotFoundDocument string    `json:"not_found_document,omitempty"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

type StorageBinding struct {
	ID         string    `json:"id"`
	Kind       string    `json:"kind"`
	Bucket     string    `json:"bucket"`
	Hostname   string    `json:"hostname"`
	PathPrefix string    `json:"path_prefix,omitempty"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type StorageAccessToken struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	TokenHash  string    `json:"token_hash,omitempty"`
	Kind       string    `json:"kind"`
	Access     string    `json:"access"`
	Buckets    []string  `json:"buckets,omitempty"`
	RevokedAt  time.Time `json:"revoked_at,omitempty"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type WorkerScript struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Source       string    `json:"source"`
	Capabilities []string  `json:"capabilities"`
	Public       bool      `json:"public"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// PluginInstallation is the persisted lifecycle record for a verified plugin
// bundle. It is intentionally metadata-only: artifacts and runtime handles stay
// outside the shared API model.
type PluginInstallation struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Type           string    `json:"type"`
	Version        string    `json:"version,omitempty"`
	Entrypoint     string    `json:"entrypoint,omitempty"`
	Publisher      string    `json:"publisher,omitempty"`
	Capabilities   []string  `json:"capabilities"`
	ArtifactSHA256 string    `json:"artifact_sha256,omitempty"`
	BundlePath     string    `json:"bundle_path,omitempty"`
	Status         string    `json:"status"`
	VerifiedAt     time.Time `json:"verified_at,omitempty"`
	InstalledAt    time.Time `json:"installed_at,omitempty"`
	ActivatedAt    time.Time `json:"activated_at,omitempty"`
	DisabledAt     time.Time `json:"disabled_at,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

type Approval struct {
	ID         string    `json:"id"`
	NodeID     string    `json:"node_id"`
	Plugin     string    `json:"plugin"`
	Action     string    `json:"action"`
	Plan       string    `json:"plan"`
	Status     string    `json:"status"`
	Reason     string    `json:"reason,omitempty"`
	ActorID    string    `json:"actor_id"`
	ApprovedBy string    `json:"approved_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

const (
	DDNSProviderCloudflare = "cloudflare"
	DDNSProviderWebhook    = "webhook"
)

// DDNSProfile describes how a node's public IP should be published to DNS. It is
// bound to a node; when that node's observed public IP changes, the bound
// profiles' records are updated.
type DDNSProfile struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	NodeID     string   `json:"node_id"`
	Provider   string   `json:"provider"`
	Domains    []string `json:"domains"`
	EnableIPv4 bool     `json:"enable_ipv4"`
	EnableIPv6 bool     `json:"enable_ipv6"`
	MaxRetries int      `json:"max_retries"`
	TTL        int      `json:"ttl"`

	// Cloudflare provider
	CFAPIToken string `json:"cf_api_token,omitempty"`

	// Webhook provider. Body/URL support the templates #ip#, #domain#, #type#.
	WebhookURL     string `json:"webhook_url,omitempty"`
	WebhookMethod  string `json:"webhook_method,omitempty"`
	WebhookBody    string `json:"webhook_body,omitempty"`
	WebhookHeaders string `json:"webhook_headers,omitempty"`

	// Status (updated by the server after each run).
	LastIPv4  string    `json:"last_ipv4,omitempty"`
	LastIPv6  string    `json:"last_ipv6,omitempty"`
	LastRunAt time.Time `json:"last_run_at,omitempty"`
	LastError string    `json:"last_error,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

const (
	MonitorTypeTCP  = "tcp"
	MonitorTypeHTTP = "http"
	MonitorTypeICMP = "icmp"
)

// Monitor is a periodic reachability/latency probe executed by assigned agents.
// Targets are host:port for tcp/icmp probes and a URL for http probes. A monitor
// runs on every node when AssignAll is set, otherwise on the nodes in NodeIDs —
// this is how a group's members continuously measure their group leader.
type Monitor struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Target      string    `json:"target"`
	IntervalSec int       `json:"interval_sec"`
	TimeoutSec  int       `json:"timeout_sec"`
	AssignAll   bool      `json:"assign_all"`
	NodeIDs     []string  `json:"node_ids,omitempty"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// MonitorResult is a single probe outcome reported by an agent.
type MonitorResult struct {
	MonitorID string    `json:"monitor_id"`
	NodeID    string    `json:"node_id"`
	At        time.Time `json:"at"`
	Success   bool      `json:"success"`
	LatencyMs float64   `json:"latency_ms"`
	Error     string    `json:"error,omitempty"`
}

// LogSource declares a file on a node whose appended lines are tailed by the
// assigned agent and shipped to the server. It is assignment-driven like
// Monitor: exactly one node owns a source (a path is node-local), identified by
// NodeID. LogSource carries no secrets.
type LogSource struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	NodeID        string    `json:"node_id"`
	Path          string    `json:"path"`
	Enabled       bool      `json:"enabled"`
	MaxLineBytes  int       `json:"max_line_bytes"`  // truncate longer lines (server default 16384)
	MaxBatchLines int       `json:"max_batch_lines"` // agent batch cap (server default 500)
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// LogLine is one ingested line as persisted/queried. Seq is the server-assigned
// monotonic per-source ingest sequence (the query cursor); Offset is the agent's
// byte offset after this line in the (rotation-scoped) source file.
type LogLine struct {
	SourceID  string    `json:"source_id"`
	NodeID    string    `json:"node_id"`
	Path      string    `json:"path"`
	Seq       uint64    `json:"seq"`
	Offset    uint64    `json:"offset"`
	At        time.Time `json:"at"`
	Line      string    `json:"line"`
	Truncated bool      `json:"truncated,omitempty"`
}

// LogBatch is the agent -> server ingest envelope (one source per batch).
type LogBatch struct {
	SourceID   string    `json:"source_id"`
	Path       string    `json:"path"`      // echoed for server cross-check vs the source record
	RotID      string    `json:"rot_id"`    // opaque per-file-incarnation id (inode/ctime)
	FirstOff   uint64    `json:"first_off"` // offset before the first line in this batch
	LastOff    uint64    `json:"last_off"`  // offset after the last line (== agent checkpoint)
	Dropped    uint64    `json:"dropped"`   // lines the agent dropped (backpressure) since last batch
	Lines      []string  `json:"lines"`     // raw lines, ordered, no trailing newline
	CapturedAt time.Time `json:"captured_at"`
}

// NotifyChannel is a persisted notification destination. Config holds
// provider-specific fields (e.g. token, chat_id, webhook_url); its values are
// secret and never serialized back to clients.
type NotifyChannel struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Kind      string            `json:"kind"`
	Config    map[string]string `json:"config,omitempty"`
	Enabled   bool              `json:"enabled"`
	CreatedAt time.Time         `json:"created_at"`
	UpdatedAt time.Time         `json:"updated_at"`
}

// NotifyRule routes notification events to one or more destinations. EventTypes
// uses stable server event ids such as monitor.down or ssh.login; "*" matches
// all notification events. Templates are intentionally small string templates
// expanded by the server with event_type, title, and body variables.
type NotifyRule struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	EventTypes    []string  `json:"event_types,omitempty"`
	ChannelIDs    []string  `json:"channel_ids,omitempty"`
	TitleTemplate string    `json:"title_template,omitempty"`
	BodyTemplate  string    `json:"body_template,omitempty"`
	Enabled       bool      `json:"enabled"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// TunnelIngress maps a public hostname to a node-local service for a Cloudflare
// Tunnel. Service is a cloudflared service URL, e.g. http://localhost:8088,
// ssh://localhost:22, or the literal http_status:404.
type TunnelIngress struct {
	Hostname string `json:"hostname"`
	Service  string `json:"service"`
	Path     string `json:"path,omitempty"`
}

// TunnelProfile describes a Cloudflare Tunnel deployed on a node. Credentials
// are node-local (CredentialsFile path); the server only stores the topology.
type TunnelProfile struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	NodeID          string          `json:"node_id"`
	TunnelID        string          `json:"tunnel_id"`
	CredentialsFile string          `json:"credentials_file,omitempty"`
	Ingress         []TunnelIngress `json:"ingress"`
	CreatedAt       time.Time       `json:"created_at"`
	UpdatedAt       time.Time       `json:"updated_at"`
}

// OIDCProvider is an admin-configured external identity provider for SSO login.
// ClientSecret is a secret-at-rest field (encrypted by the store boundary) and
// is never returned by the API.
type OIDCProvider struct {
	ID             string    `json:"id"`
	DisplayName    string    `json:"display_name"`
	Issuer         string    `json:"issuer"`
	ClientID       string    `json:"client_id"`
	ClientSecret   string    `json:"client_secret,omitempty"`
	Scopes         []string  `json:"scopes,omitempty"`
	AllowedDomains []string  `json:"allowed_domains,omitempty"`
	Enabled        bool      `json:"enabled"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// OIDCIdentity is the durable link between an external subject and a local user.
// Keyed in the store by (ProviderID, Subject): the trust anchor is the
// admin-vetted provider record, not the bare issuer string, so a second
// provider that happens to share an issuer cannot reuse another provider's
// links. Subject is the stable identifier; Email/Issuer are reference only.
type OIDCIdentity struct {
	ProviderID string    `json:"provider_id"`
	Issuer     string    `json:"issuer"`
	Subject    string    `json:"subject"`
	UserID     string    `json:"user_id"`
	Email      string    `json:"email,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}
