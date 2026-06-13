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
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	TokenHash          string    `json:"token_hash"`
	Tags               []string  `json:"tags"`
	Role               string    `json:"role"`
	WireGuardIP        string    `json:"wireguard_ip"`
	WireGuardPublicKey string    `json:"wireguard_public_key,omitempty"`
	WireGuardEndpoint  string    `json:"wireguard_endpoint,omitempty"`
	WireGuardPort      int       `json:"wireguard_port,omitempty"`
	PublicIP           string    `json:"public_ip"`
	PublicIPv6         string    `json:"public_ipv6,omitempty"`
	AgentVersion       string    `json:"agent_version"`
	Online             bool      `json:"online"`
	Disabled           bool      `json:"disabled,omitempty"`
	LastSeen           time.Time `json:"last_seen"`
	Metrics            Metrics   `json:"metrics"`
	CreatedAt          time.Time `json:"created_at"`
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
	LeaseID     string    `json:"lease_id,omitempty"`
	LeasedBy    string    `json:"leased_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	StartedAt   time.Time `json:"started_at,omitempty"`
	FinishedAt  time.Time `json:"finished_at,omitempty"`
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
