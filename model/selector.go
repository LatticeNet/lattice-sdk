package model

// TargetSelector chooses nodes for a target field (lattice docs design 32
// D5). Check sources and targets, policy targets and remotes, security-group
// bindings and mesh membership share this one stored shape. It is stored as
// written and resolved each time it is used, so a node that joins a named
// group joins whatever the selector targets, and one that leaves it leaves.
//
// A node is selected when All is set, when Nodes names it, or when it is a
// member of a group Groups names; a node Exclude names is never selected,
// whatever else matches it. Group criteria resolve through the existing
// group resolver (lattice-server internal/groups): a group's members are its
// explicit Members together with the nodes its GroupSelector matches, and a
// GroupSelector's set criteria combine with AND. Tags are not a criterion of
// their own: selecting by tag means naming a group whose selector matches
// that tag. A selector with nothing set selects no node.
type TargetSelector struct {
	Nodes   []string `json:"nodes,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	All     bool     `json:"all,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}
