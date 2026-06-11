package model

import "time"

const (
	TaskQueued   = "queued"
	TaskLeased   = "leased"
	TaskFinished = "finished"
	TaskFailed   = "failed"

	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalRejected = "rejected"
	ApprovalApplied  = "applied"
)

type User struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"password_hash"`
	Scopes       []string  `json:"scopes"`
	TOTPEnabled  bool      `json:"totp_enabled"`
	CreatedAt    time.Time `json:"created_at"`
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
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	TokenHash    string    `json:"token_hash"`
	Tags         []string  `json:"tags"`
	Role         string    `json:"role"`
	WireGuardIP  string    `json:"wireguard_ip"`
	PublicIP     string    `json:"public_ip"`
	PublicIPv6   string    `json:"public_ipv6,omitempty"`
	AgentVersion string    `json:"agent_version"`
	Online       bool      `json:"online"`
	LastSeen     time.Time `json:"last_seen"`
	Metrics      Metrics   `json:"metrics"`
	CreatedAt    time.Time `json:"created_at"`
}

type Metrics struct {
	CPUPercent    float64   `json:"cpu_percent"`
	Load1         float64   `json:"load1"`
	MemoryUsed    uint64    `json:"memory_used"`
	MemoryTotal   uint64    `json:"memory_total"`
	DiskUsed      uint64    `json:"disk_used"`
	DiskTotal     uint64    `json:"disk_total"`
	NetRxBytes    uint64    `json:"net_rx_bytes"`
	NetTxBytes    uint64    `json:"net_tx_bytes"`
	UptimeSeconds uint64    `json:"uptime_seconds"`
	CollectedAt   time.Time `json:"collected_at"`
}

type Task struct {
	ID          string    `json:"id"`
	ActorID     string    `json:"actor_id"`
	TokenID     string    `json:"token_id"`
	Targets     []string  `json:"targets"`
	Interpreter string    `json:"interpreter"`
	Script      string    `json:"script"`
	TimeoutSec  int       `json:"timeout_sec"`
	OutputLimit int       `json:"output_limit"`
	Status      string    `json:"status"`
	LeasedBy    string    `json:"leased_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	FinishedAt  time.Time `json:"finished_at,omitempty"`
}

type TaskResult struct {
	TaskID     string    `json:"task_id"`
	NodeID     string    `json:"node_id"`
	ExitCode   int       `json:"exit_code"`
	Stdout     string    `json:"stdout"`
	Stderr     string    `json:"stderr"`
	Error      string    `json:"error"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
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

type WorkerScript struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Source       string    `json:"source"`
	Capabilities []string  `json:"capabilities"`
	Public       bool      `json:"public"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Approval struct {
	ID         string    `json:"id"`
	NodeID     string    `json:"node_id"`
	Plugin     string    `json:"plugin"`
	Action     string    `json:"action"`
	Plan       string    `json:"plan"`
	Status     string    `json:"status"`
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
