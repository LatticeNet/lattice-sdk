package model

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// A fleet-bound record (design 28) renders to a SelectionPlan instead of a
// document. The plugin runs the record's chain over catalogue rows that carry
// placeholder credentials, and the plan says what came out. The core then
// validates every fleet node against the catalogue, binds the share's
// identity in place of each placeholder, and calls convert, which has no
// network and no store, to produce the document. No method that runs scripts
// or reaches the network ever holds a fleet credential.

// Plan kinds (SelectionPlan.Kind).
const (
	// SelectionPlanKindNodes is a typed-node plan: the ordered node list a
	// fleet record, a collection, or a provider record that pulled fleet
	// nodes produced. The core binds the fleet nodes and converts the list.
	SelectionPlanKindNodes = "nodes"
	// SelectionPlanKindDocument is a document plan: the text a file or a
	// mihomo config produced with placeholders still in it, plus the typed
	// fleet nodes it was produced from. The core validates those nodes and
	// convert substitutes the bound credentials into the text.
	SelectionPlanKindDocument = "document"
)

// Bounds of plans, placeholders and the response chain.
const (
	// MaxSelectionPlanBytes bounds one encoded plan. A 4096-node plan with
	// Reality and transport options measures 3 to 4 MB.
	MaxSelectionPlanBytes = 6 << 20
	// MaxRenderPlanBytes is the largest plan a render reply may carry: the
	// render stdout budget, which equals MaxSelectionPlanBytes, less the
	// half MiB the reply's other fields and the framing take. A plugin
	// refuses a plan over it with plan_too_large rather than letting the core
	// kill the call at the stdout budget.
	MaxRenderPlanBytes = MaxSelectionPlanBytes - 512<<10
	// MaxBindProbeConsecutiveFailures bounds
	// ProbeExclusionPolicy.ConsecutiveFailures.
	MaxBindProbeConsecutiveFailures = 10
	// MaxConvertRequestBytes bounds one encoded convert request, which
	// carries a bound plan. It is inside MaxSubscriptionRequestBytes.
	MaxConvertRequestBytes = 6 << 20
	// MaxPlanClonesPerLine is how many plan nodes may carry one line_uuid
	// (Handle Duplicate in rename mode, cloning scripts). The core excludes
	// every node past it.
	MaxPlanClonesPerLine = 4
	// MaxResponseChainBytes bounds a response chain: the sum, over its
	// steps, of the bytes of the name, the inlined source and the arguments.
	MaxResponseChainBytes = 512 << 10
	// MaxResponseChainSteps bounds the steps of a response chain.
	MaxResponseChainSteps = 32
	// MaxResponseStepNameBytes bounds a response step's name.
	MaxResponseStepNameBytes = 128

	// PlanPlaceholderPrefix starts every plan placeholder. A placeholder is
	// LATTICE-SYN-<line_uuid>-<field>-<random>: the line it stands in for,
	// the credential field it occupies, and 32 lowercase hex digits drawn
	// fresh for each render. It is not a valid credential anywhere.
	PlanPlaceholderPrefix = "LATTICE-SYN-"
	// PlanPlaceholderRandomBytes is the entropy of a placeholder's random part.
	PlanPlaceholderRandomBytes = 16
	// MaxPlanPlaceholderFieldBytes bounds a placeholder's field name.
	MaxPlanPlaceholderFieldBytes = 32
	// MaxPlanPlaceholderBytes is the longest placeholder.
	MaxPlanPlaceholderBytes = len(PlanPlaceholderPrefix) + 36 + 1 + MaxPlanPlaceholderFieldBytes + 1 + 2*PlanPlaceholderRandomBytes
)

// planPlaceholderField is a credential field name: lowercase, starting with a
// letter, with digits and underscores. A mihomo field with a hyphen is named
// with an underscore. The field cannot hold a hyphen, which keeps the
// placeholder's parts unambiguous.
var planPlaceholderField = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// planPlaceholderBody matches the part of a placeholder after the prefix.
var planPlaceholderBody = regexp.MustCompile(`^([0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})-([a-z][a-z0-9_]{0,31})-([0-9a-f]{32})`)

// The top-level keys of a plan node, by what each side does with them. A
// plan node carries its catalogue metadata flat, under these names, never in
// a nested object, because the core admits a node key only from its compared,
// mutable and carried sets.
var (
	// SelectionPlanLatticeFields are the catalogue metadata keys a plan node
	// carries at the top level: the core carries them without comparing
	// them, and convert strips them before any producer runs. line_uuid is
	// not here, because the core compares it with the node's line; convert
	// strips it with these (SelectionPlanStrippedFields).
	SelectionPlanLatticeFields = []string{"line_hash_id", "node_id", "geo", "chain", "tags", "groups", "probe", "addresses"}

	// SelectionPlanStrippedFields is what convert removes from every node
	// before any producer runs: the Lattice fields and line_uuid.
	SelectionPlanStrippedFields = append([]string{"line_uuid"}, SelectionPlanLatticeFields...)

	// SelectionPlanCarriedFields is the core's whole carried set: the
	// Lattice fields plus the protocol tuning fields and the parser
	// annotations the URI parsers set from a template's parameters. The core
	// carries these keys without comparing them; a node key outside the
	// core's compared, mutable and carried sets is excluded as
	// plan_rejected:<key>.
	SelectionPlanCarriedFields = append([]string{
		"flow", "packet-encoding", "congestion-controller", "udp-relay-mode", "reduce-rtt", "up", "down",
		"_h2", "_mode", "_grpc-type", "_spider-x", "_pqv", "_v2ray-http-upgrade-ed",
	}, SelectionPlanLatticeFields...)
)

// SelectionPlan is what render returns for a fleet-bound record in place of
// a document.
type SelectionPlan struct {
	// Kind is SelectionPlanKindNodes or SelectionPlanKindDocument.
	Kind string `json:"kind"`
	// Nodes are, for a typed-node plan, the output nodes in order, fleet and
	// provider alike; for a document plan, the typed fleet nodes the document
	// was produced from.
	Nodes []SelectionPlanNode `json:"nodes"`
	// Document is the produced text of a document plan, placeholders
	// included. Empty for a typed-node plan.
	Document string `json:"document,omitempty"`
	// ResponseChain is the record's Response Transformer steps, resolved and
	// inlined by render, because convert cannot read the store. The core
	// passes it to convert unchanged.
	ResponseChain []ResponseTransformerStep `json:"response_chain,omitempty"`
	// Selection is the selection the plan was rendered from. A core takes
	// the selected line set from it in place of the record's snapshot. On
	// the serve path the core also requires its CatalogueVersion to equal the
	// snapshot's and its lines to be among the snapshot's rows, refusing
	// selection_mismatch otherwise, so a plan always says what its snapshot
	// said. A preview of a staged revision carries the revision's own fresh
	// selection, which the core uses as it is. Nil in a plan from a plugin
	// that predates it; the core then reads the snapshot.
	Selection *PlanSelection `json:"selection,omitempty"`
	// Policy is the served record's opt-in exclusion rules, which the core
	// applies when it binds. Nil when the record opts into none.
	Policy *BindPolicy `json:"policy,omitempty"`
}

// PlanSelection is the selection a plan was rendered from: the catalogue
// version and the lines it selected.
type PlanSelection struct {
	// CatalogueVersion is the catalogue version the rows were read at.
	CatalogueVersion string `json:"catalogue_version"`
	// LineUUIDs are the selected lines: at most MaxSubscriptionRecordNodes,
	// each a lowercase UUIDv4, none twice.
	LineUUIDs []string `json:"line_uuids"`
}

// BindPolicy is a record's opt-in exclusion rules, applied by the core at
// bind. Every rule is off when its field is absent.
type BindPolicy struct {
	// Probe excludes a line whose probe failed too many times in a row.
	Probe *ProbeExclusionPolicy `json:"probe,omitempty"`
	// Usage excludes a line on which the share's identity used too much in
	// its current period.
	Usage *UsageExclusionPolicy `json:"usage,omitempty"`
	// DDNSDial says the record dials verified DDNS names in place of a
	// line's address, so the core's cache key for a share must cover each
	// name's verification as well.
	DDNSDial bool `json:"ddns_dial,omitempty"`
}

// ProbeExclusionPolicy excludes a line whose last probe failed and whose
// failure count since the last pass is at least ConsecutiveFailures. A line
// with no probe block is never excluded by it.
type ProbeExclusionPolicy struct {
	// ConsecutiveFailures is 1 to MaxBindProbeConsecutiveFailures.
	ConsecutiveFailures int `json:"consecutive_failures"`
}

// UsageExclusionPolicy excludes a line on which the share's identity used
// more than MaxBytesPerLine in its current period: its monthly quota period,
// or the calendar month when it has none.
type UsageExclusionPolicy struct {
	// MaxBytesPerLine is positive. The rule fires strictly above it.
	MaxBytesPerLine int64 `json:"max_bytes_per_line"`
}

// Validate checks a selection's version and its line list.
func (s PlanSelection) Validate() error {
	if !validCatalogueToken(s.CatalogueVersion) {
		return errors.New("plan selection needs a catalogue_version")
	}
	if len(s.LineUUIDs) > MaxSubscriptionRecordNodes {
		return fmt.Errorf("plan selection names more than %d lines", MaxSubscriptionRecordNodes)
	}
	seen := make(map[string]struct{}, len(s.LineUUIDs))
	for _, id := range s.LineUUIDs {
		if !subscriptionSourceUUIDv4.MatchString(id) {
			return fmt.Errorf("plan selection line_uuid %q is not a lowercase uuidv4", id)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("plan selection names line %s twice", id)
		}
		seen[id] = struct{}{}
	}
	return nil
}

// Validate checks a policy's ranges.
func (p BindPolicy) Validate() error {
	if p.Probe != nil && (p.Probe.ConsecutiveFailures < 1 || p.Probe.ConsecutiveFailures > MaxBindProbeConsecutiveFailures) {
		return fmt.Errorf("plan policy probe consecutive_failures must be 1 to %d", MaxBindProbeConsecutiveFailures)
	}
	if p.Usage != nil && p.Usage.MaxBytesPerLine <= 0 {
		return errors.New("plan policy usage max_bytes_per_line must be positive")
	}
	return nil
}

// SelectionPlanNode is one node of a plan.
type SelectionPlanNode struct {
	// LineUUID is the fleet line this node stands for. A fleet node without
	// one is excluded by the core with no_line, so a script cannot place a
	// foreign node in a fleet position.
	LineUUID string `json:"line_uuid,omitempty"`
	// Placeholders maps each credential field of the node to the placeholder
	// the plugin put there for this line. The core requires the node to
	// still carry each one, unmodified, before it binds.
	Placeholders map[string]string `json:"placeholders,omitempty"`
	// Provider marks a node materialised in full from provider content (the
	// operator's own provider, not the fleet). It carries no line and no
	// placeholder, and the core does not bind it. A typed-node plan of a
	// collection mixes both; a document plan carries fleet nodes only.
	Provider bool `json:"provider,omitempty"`
	// Node is the post-chain node model as a JSON object, in the field names
	// scripts see. Producers never emit its script map.
	Node json.RawMessage `json:"node"`
}

// NewPlanPlaceholder returns a fresh placeholder for one credential field of
// one line, with a random part from crypto/rand.
func NewPlanPlaceholder(lineUUID, field string) (string, error) {
	if !subscriptionSourceUUIDv4.MatchString(lineUUID) {
		return "", errors.New("placeholder line_uuid must be a lowercase uuidv4")
	}
	if !planPlaceholderField.MatchString(field) {
		return "", fmt.Errorf("placeholder field %q is not a credential field name", field)
	}
	random := make([]byte, PlanPlaceholderRandomBytes)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return PlanPlaceholderPrefix + lineUUID + "-" + field + "-" + hex.EncodeToString(random), nil
}

// ParsePlanPlaceholder splits a placeholder into the line and the credential
// field it stands for, and refuses anything that is not exactly one
// well-formed placeholder.
func ParsePlanPlaceholder(value string) (lineUUID, field string, err error) {
	body, ok := strings.CutPrefix(value, PlanPlaceholderPrefix)
	if !ok {
		return "", "", errors.New("not a plan placeholder")
	}
	match := planPlaceholderBody.FindStringSubmatch(body)
	if match == nil || len(match[0]) != len(body) {
		return "", "", errors.New("malformed plan placeholder")
	}
	return match[1], match[2], nil
}

// CountPlanPlaceholders counts every well-formed placeholder in a document,
// wherever it occurs, including inside a longer word. The core compares the
// counts with the validated clones of each line: a placeholder a script
// copied into a name or a comment raises its count and the document is
// refused with placeholder_count.
func CountPlanPlaceholders(document string) map[string]int {
	counts := make(map[string]int)
	rest := document
	for {
		at := strings.Index(rest, PlanPlaceholderPrefix)
		if at < 0 {
			return counts
		}
		body := rest[at+len(PlanPlaceholderPrefix):]
		if match := planPlaceholderBody.FindString(body[:min(len(body), MaxPlanPlaceholderBytes)]); match != "" {
			counts[PlanPlaceholderPrefix+match]++
			rest = body[len(match):]
			continue
		}
		rest = body
	}
}

// Validate checks a plan's structure and bounds. A node the core will exclude
// (a fleet node without a line, a fifth clone, a node outside its line's
// allowed hosts) is not a structural error; a node that contradicts itself
// is, and so is a node object with a duplicate key at any depth, where the
// core's validator and its binder could read different values.
func (p SelectionPlan) Validate() error {
	return p.validate(false)
}

// validate is Validate; keysChecked skips the duplicate-key scan of each node
// when the caller already scanned the whole encoded plan.
func (p SelectionPlan) validate(keysChecked bool) error {
	switch p.Kind {
	case SelectionPlanKindNodes:
		if p.Document != "" {
			return errors.New("a typed-node plan carries no document")
		}
	case SelectionPlanKindDocument:
		if p.Document == "" {
			return errors.New("a document plan needs its document")
		}
	default:
		return fmt.Errorf("unknown plan kind %q", p.Kind)
	}
	if len(p.Nodes) > MaxSubscriptionRecordNodes {
		return fmt.Errorf("plan has more than %d nodes", MaxSubscriptionRecordNodes)
	}
	for i, node := range p.Nodes {
		if err := node.validate(); err != nil {
			return fmt.Errorf("plan node %d: %w", i, err)
		}
		if !keysChecked {
			if err := rejectDuplicateJSONFields(node.Node); err != nil {
				return fmt.Errorf("plan node %d: %w", i, err)
			}
		}
		if p.Kind == SelectionPlanKindDocument && node.Provider {
			return fmt.Errorf("plan node %d: a document plan carries fleet nodes only", i)
		}
	}
	if p.Selection != nil {
		if err := p.Selection.Validate(); err != nil {
			return err
		}
	}
	if p.Policy != nil {
		if err := p.Policy.Validate(); err != nil {
			return err
		}
	}
	return ValidateResponseChain(p.ResponseChain)
}

func (n SelectionPlanNode) validate() error {
	if !isJSONObject(n.Node) {
		return errors.New("node must be a JSON object")
	}
	if n.Provider {
		if n.LineUUID != "" || len(n.Placeholders) > 0 {
			return errors.New("a provider node carries no line and no placeholder")
		}
		return nil
	}
	if n.LineUUID == "" {
		if len(n.Placeholders) > 0 {
			return errors.New("placeholders without a line_uuid")
		}
		return nil
	}
	if !subscriptionSourceUUIDv4.MatchString(n.LineUUID) {
		return errors.New("line_uuid must be a lowercase uuidv4")
	}
	for field, placeholder := range n.Placeholders {
		line, placed, err := ParsePlanPlaceholder(placeholder)
		if err != nil {
			return fmt.Errorf("placeholder for %q: %w", field, err)
		}
		if line != n.LineUUID || placed != field {
			return fmt.Errorf("placeholder for %q names line %s field %q", field, line, placed)
		}
	}
	return nil
}

// ExcessClones returns, in plan order, the index of every node that is past
// the MaxPlanClonesPerLine-th node carrying the same line_uuid. The core
// excludes them.
func (p SelectionPlan) ExcessClones() []int {
	seen := make(map[string]int)
	var out []int
	for i, node := range p.Nodes {
		if node.LineUUID == "" {
			continue
		}
		seen[node.LineUUID]++
		if seen[node.LineUUID] > MaxPlanClonesPerLine {
			out = append(out, i)
		}
	}
	return out
}

// EncodeSelectionPlan validates a plan and encodes it, refusing an encoding
// over MaxSelectionPlanBytes.
func EncodeSelectionPlan(p SelectionPlan) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxSelectionPlanBytes {
		return nil, fmt.Errorf("plan encodes to %d bytes, over %d", len(raw), MaxSelectionPlanBytes)
	}
	return raw, nil
}

// DecodeSelectionPlan decodes a plan with its size checked first, duplicate
// keys refused at any depth, unknown fields refused and no trailing data,
// then validates it.
//
// Refusing unknown fields is the plan's compatibility policy, and it is
// deliberate. The catalogue negotiates through selector_fields because an
// unknown selector field only narrows a read; a plan field would change what
// the core binds, and a core that dropped one would bind without it. So a
// core refuses a plan field it does not know, and a plugin emits a new plan
// field only when its manifest's compatibility.server floor guarantees a core
// that knows it.
func DecodeSelectionPlan(raw []byte) (SelectionPlan, error) {
	if len(raw) == 0 || len(raw) > MaxSelectionPlanBytes {
		return SelectionPlan{}, errors.New("invalid plan size")
	}
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return SelectionPlan{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var plan SelectionPlan
	if err := decoder.Decode(&plan); err != nil {
		return SelectionPlan{}, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return SelectionPlan{}, err
	}
	if err := plan.validate(true); err != nil {
		return SelectionPlan{}, err
	}
	return plan, nil
}

func isJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) > 0 && trimmed[0] == '{' && json.Valid(trimmed)
}
