package model

// TargetSelector chooses a set of nodes for anything that targets nodes:
// check sources and targets, outbound policy targets, and later security
// group bindings and mesh membership (design 32 D5). It is stored as written
// and resolved when used, so a node that joins a named group joins the target.
//
// The resolved set is the union of the named nodes, the members of the named
// groups, and every node when All is set, minus the nodes in Exclude. A node
// group's own selector already matches tags, so a tag is selected by making a
// group for it rather than by a criterion here.
type TargetSelector struct {
	Nodes   []string `json:"nodes,omitempty"`
	Groups  []string `json:"groups,omitempty"`
	All     bool     `json:"all,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
}
