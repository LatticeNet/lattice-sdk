package model

import "time"

// Design 31, S5: an agent update downloads from an ordered list of sources
// the server computes when it plans and the approval binds: mirrors preferred
// for the node, the control plane when it holds the pinned bytes, mirrors
// marked global, then the upstream release. A mirror is any HTTPS server that
// holds release binaries at <base_url>/<version>/<os>/<arch>/<sha256>, the
// control plane's own object path. The registry of mirrors is small, and
// every change to it is a reviewed agent.mirrors plan.

// The approval plugin and plan kind of a registry change.
const (
	AgentMirrorsApprovalPlugin = "agent.mirrors"
	AgentMirrorsPlanKind       = "agent.mirrors"
)

// Actions an AgentMirrorPlanRequest names.
const (
	AgentMirrorActionCreate = "create"
	AgentMirrorActionChange = "change"
	AgentMirrorActionDelete = "delete"
)

// Kinds of AgentUpdateSource.
const (
	// AgentSourceKindControlPlane is this control plane's own binary route,
	// the only source that is sent the task lease.
	AgentSourceKindControlPlane = "control-plane"
	// AgentSourceKindMirror is a registry mirror: no credential, no redirect.
	AgentSourceKindMirror = "mirror"
	// AgentSourceKindUpstream is the release URL, always last.
	AgentSourceKindUpstream = "upstream"
)

// AgentFetchKindMirrorPrefix starts the summary-line kind of a mirror fetch,
// followed by the mirror's id: m.<id>.
const AgentFetchKindMirrorPrefix = "m."

// AgentMirror is one registry entry. The server sets CreatedAt and UpdatedAt;
// everything else is what an approved plan wrote.
type AgentMirror struct {
	// ID is the mirror's stable name: lowercase letters, digits and hyphens,
	// at most 31 characters, starting with a letter or digit. It names the
	// mirror in plans and in the fetch summary (m.<id>).
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
	// BaseURL is an HTTPS origin and optional path, without userinfo, query
	// or fragment, under which the mirror holds the release binaries.
	BaseURL string `json:"base_url"`
	// PreferFor lists node ids and static group ids. A node named here, or a
	// member of a group named here, tries this mirror before the control
	// plane. Group selectors never count: the list is built from stable
	// inputs only, so a plan does not change when a node's facts do.
	PreferFor []string `json:"prefer_for,omitempty"`
	// Global puts the mirror after the control plane for every node it is
	// not preferred for, and among the sources of a new node's install.
	Global bool `json:"global,omitempty"`
	// Priority orders mirrors within the preferred and the global group: a
	// smaller number comes first, and ties go by id. When a plan has more
	// sources than it may carry, the mirrors that come last are dropped.
	Priority int `json:"priority"`
	// Enabled mirrors are listed in plans; a disabled one is kept but never
	// listed.
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at,omitzero"`
	UpdatedAt time.Time `json:"updated_at,omitzero"`
}

// AgentUpdateSource is one download source of an agent update plan, in the
// order the node tries them.
type AgentUpdateSource struct {
	// Kind is control-plane, mirror or upstream.
	Kind string `json:"kind"`
	URL  string `json:"url"`
	// Mirror is the registry id of a mirror source, empty otherwise.
	Mirror string `json:"mirror,omitempty"`
	// Reason says why the source is in the list at that place.
	Reason string `json:"reason"`
}

// AgentMirrorPlanRequest asks for an agent.mirrors plan. Create and change
// carry the whole entry; delete names it by Mirror.ID alone.
type AgentMirrorPlanRequest struct {
	Action string      `json:"action"`
	Mirror AgentMirror `json:"mirror"`
}

// AgentMirrorPlan is the document an agent.mirrors approval carries and the
// operator reviews. It is rendered again from live state when the approval
// is decided and refused as stale when the bytes differ.
type AgentMirrorPlan struct {
	Kind   string `json:"kind"`
	Action string `json:"action"`
	// Mirror is the entry as the plan leaves it; for a delete, the entry
	// removed.
	Mirror AgentMirror `json:"mirror"`
	// Previous is the entry before a change or a delete.
	Previous *AgentMirror `json:"previous,omitempty"`
	// Diff lists the fields that change, as "field: before -> after".
	Diff []string `json:"diff"`
	// BaseRevision is the registry revision the plan was made against; an
	// approval made against an older one is stale.
	BaseRevision int64 `json:"base_revision"`
	// Changes lists every node whose source order the plan changes.
	Changes []AgentMirrorOrderChange `json:"changes"`
}

// AgentMirrorOrderChange is one node's source order before and after a plan,
// as AgentMirrorOrder labels.
type AgentMirrorOrderChange struct {
	NodeID string   `json:"node_id"`
	Name   string   `json:"name,omitempty"`
	Before []string `json:"before"`
	After  []string `json:"after"`
}

// AgentMirrorPlanResponse answers a plan request.
type AgentMirrorPlanResponse struct {
	Approval Approval        `json:"approval"`
	Plan     AgentMirrorPlan `json:"plan"`
}

// AgentMirrorOrder is one node's source order as the registry makes it, for
// a version the control plane holds: labels "mirror:<id>", "control-plane"
// and "upstream", in the order a plan would list them.
type AgentMirrorOrder struct {
	NodeID  string   `json:"node_id"`
	Name    string   `json:"name,omitempty"`
	Sources []string `json:"sources"`
}

// AgentMirrorHealth is what the nodes' last update downloads say about one
// mirror: how many fetched from it, and how many of those fetches wrote a
// chunk that failed the manifest. It is node-reported telemetry for display
// and never feeds the order.
type AgentMirrorHealth struct {
	Mirror        string `json:"mirror"`
	Fetches       int    `json:"fetches"`
	ChunkFailures int    `json:"chunk_failures"`
}

// AgentMirrorsView answers GET /api/nodes/agent-updates/mirrors.
type AgentMirrorsView struct {
	Mirrors  []AgentMirror `json:"mirrors"`
	Revision int64         `json:"revision"`
	// Order is the source order of every node the caller may read.
	Order []AgentMirrorOrder `json:"order"`
	// Pending lists the ids of open agent.mirrors approvals.
	Pending []string            `json:"pending"`
	Health  []AgentMirrorHealth `json:"health"`
}
