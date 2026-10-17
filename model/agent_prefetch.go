package model

// Design 31, S4: an agent fetches the binary of its node's open agent update
// in the background, before the update's task runs, into the very file the
// update script continues. The server names the file in the config pull
// (AgentConfig.AgentUpdate) and the agent reports its progress in its
// heartbeat (the "prefetch" key, AgentPrefetchFacts).

// AgentUpdateConfig is the agent_update block of the agent config pull. A
// server that serves prefetch always sends it, so an agent tells such a
// server (a block, perhaps without Prefetch) from an older one (no block),
// and against an older one neither fetches nor removes anything.
type AgentUpdateConfig struct {
	// Prefetch names the file to fetch now; absent when there is none.
	Prefetch *AgentUpdatePrefetch `json:"prefetch,omitempty"`
	// Keep lists the digests of every pending or approved agent update of
	// this node, running ones included. The agent removes the kept
	// downloads whose digest is not here and never one that is. It is
	// always sent, empty as [].
	Keep []string `json:"keep"`
}

// AgentUpdatePrefetch names one file by its plan's approval, version,
// platform, digests and sizes, and never by URL: the agent builds the request
// from its own enrolled server address and these fields, which it validates.
type AgentUpdatePrefetch struct {
	ApprovalID string `json:"approval_id"`
	Version    string `json:"version"`
	OS         string `json:"os"`
	Arch       string `json:"arch"`
	// SHA256 is the digest of the binary the update installs.
	SHA256 string `json:"sha256"`
	// CompressedSHA256 is set when the control plane serves the binary
	// gzip-compressed; it then names the file fetched.
	CompressedSHA256 string `json:"compressed_sha256,omitempty"`
	// Size is the size of the file fetched, the compressed one when
	// CompressedSHA256 is set; BinarySize is that of the binary installed.
	Size       int64 `json:"size"`
	BinarySize int64 `json:"binary_size"`
	// InstallPath is the plan's install path, from which the agent resolves
	// the directory the update script keeps its download in, by the
	// script's own rule.
	InstallPath string `json:"install_path"`
}

// AgentPrefetchFacts is the "prefetch" key of an agent heartbeat, sent while
// the config names a file: which file, how much of it is on disk, and what
// the agent is doing about it.
type AgentPrefetchFacts struct {
	ApprovalID string `json:"approval_id"`
	// SHA256 is the digest of the file fetched, the compressed one for a
	// compressed plan.
	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`
	Size   int64  `json:"size"`
	// State is one of the AgentPrefetch* states; a consumer drops a report
	// with any other.
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// The states an agent reports in AgentPrefetchFacts.State.
const (
	// AgentPrefetchFetching: a download is running.
	AgentPrefetchFetching = "fetching"
	// AgentPrefetchComplete: the file holds the pinned bytes.
	AgentPrefetchComplete = "complete"
	// AgentPrefetchWaiting: between attempts, or stopped while a task runs;
	// Reason says why.
	AgentPrefetchWaiting = "waiting"
	// AgentPrefetchRefused: the node does not prefetch this file (a veto, a
	// non-root agent, the disk, the install path); Reason says why.
	AgentPrefetchRefused = "refused"
)
