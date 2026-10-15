package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
)

// The line catalogue (design 28) is the credential-free view of the fleet's
// lines that the Sub-Store plugin selects over. The core serves it as method
// catalogue of the core-backed service latticenet.vpn-core/lines under scope
// vpncore:read: one LineCatalogueRow per line, cursor-paginated, filtered by
// an optional LineCatalogueSelector before paging.
//
// Credential-free is the contract, and the core is what keeps it: every
// template a row carries has passed the core's fragment-survival refusal (no
// part of the line owner's credential four bytes or longer survives in it).
// That check needs the credential, so only the core can run it.
//
// Validate is a consumer's structural second line, and it is narrower. A
// template param must be one of the connection parameters the core's builder
// keeps (the allowlist below); the parameters a client entry takes from an
// identity's credential are refused by name. No param value and no string
// anywhere in Extra may look like a sealed secret, a private key or a URL,
// and no Extra key at any depth may be a credential name. Extra is bounded.
// A credential the core let through under an allowlisted name in a shape
// none of these patterns catches would still pass Validate.

// Chain roles (LineCatalogueChain.Role).
const (
	// LineChainRoleSingle is a line that is not part of a chain.
	LineChainRoleSingle = "single"
	// LineChainRoleEntry is the line a client connects to at the start of a
	// chain.
	LineChainRoleEntry = "entry"
	// LineChainRoleRelay is a line in the middle of a chain.
	LineChainRoleRelay = "relay"
	// LineChainRoleExit is the line whose node carries the traffic out.
	LineChainRoleExit = "exit"
)

// Path states of a committed chain root (LineCatalogueChain.PathState). Any
// state other than LinePathConverged excludes the line when the core binds.
const (
	// LinePathConverged: every hop observed equals the committed definition.
	LinePathConverged = "converged"
	// LinePathDrifted: an observed hop differs from the committed target.
	LinePathDrifted = "drifted"
	// LinePathBusy: a plan attempt on the path is in progress.
	LinePathBusy = "busy"
)

// Service states (LineCatalogueRow.ServiceState and
// LineCatalogueChain.PathServiceState): the process truth of a line.
const (
	LineServiceStateRunning    = "running"
	LineServiceStateDown       = "down"
	LineServiceStateRestarting = "restarting"
	LineServiceStateUnknown    = "unknown"
)

// LineCatalogueUnavailableProbe names, in LineCatalogueResponse.Unavailable,
// the probe block: no producer fills it on this core, so every row's probe
// is null and a predicate over it can only be unknown.
const LineCatalogueUnavailableProbe = "probe"

// Probe verdicts (LineCatalogueProbe.Verdict).
const (
	// LineProbeVerdictPass: the most recent probe of the line succeeded.
	LineProbeVerdictPass = "pass"
	// LineProbeVerdictFail: the most recent probe of the line failed.
	LineProbeVerdictFail = "fail"
)

// Bounds of the line catalogue.
const (
	// MaxSubscriptionRecordNodes is the most nodes one Sub-Store record may
	// hold (design 28). It bounds an explicit line list in a selector, the
	// nodes of a selection plan and the nodes of a convert request.
	MaxSubscriptionRecordNodes = 4096
	// MaxLineCataloguePageRows bounds the rows of one catalogue page.
	MaxLineCataloguePageRows = 1000
	// MaxLineCataloguePageBytes bounds one encoded catalogue page. It sits
	// 64 KiB inside the 4 MiB host-call result a plugin receives
	// (plugin.DefaultMaxHostResponsePayloadBytes), which leaves room for any
	// envelope around the page. A core cuts a page at MaxLineCataloguePageRows
	// rows or at this many bytes, whichever comes first.
	MaxLineCataloguePageBytes = 4<<20 - 64<<10
	// MaxLineCatalogueRowBytes bounds one encoded row, so every page can hold
	// at least one row and a read always makes progress.
	MaxLineCatalogueRowBytes = 64 << 10
	// MaxLineCatalogueExtraBytes bounds a row's Extra: the sum of its keys'
	// lengths and its values' encoded lengths.
	MaxLineCatalogueExtraBytes = 4 << 10
	// MaxLineCatalogueSelectorValues bounds each value list in a selector
	// other than LineUUIDs.
	MaxLineCatalogueSelectorValues = 256
	// MaxLineCatalogueRenewalDays bounds LineCatalogueSelector.RenewalWithinDays.
	MaxLineCatalogueRenewalDays = 3660
	// MaxLineCatalogueProbeHours bounds
	// LineCatalogueSelector.ProbePassedWithinHours (one year).
	MaxLineCatalogueProbeHours = 8760
	// MaxLineCatalogueRequestBytes bounds one encoded LineCatalogueRequest.
	// A selector naming MaxSubscriptionRecordNodes lines encodes in about
	// 160 KiB.
	MaxLineCatalogueRequestBytes = 1 << 20
	// MaxLineCatalogueTokenBytes bounds a cursor and a catalogue version.
	MaxLineCatalogueTokenBytes = 1 << 10

	// MaxLineTemplateParams, MaxLineTemplateDropped and
	// MaxLineTemplateValueBytes mirror the core's own template store bounds.
	MaxLineTemplateParams     = 24
	MaxLineTemplateDropped    = 32
	MaxLineTemplateValueBytes = 512
)

// LineTemplateReservedParams are the parameters a client entry takes from the
// identity's credential payload or from the template's own fields, never from
// Params. A catalogue template that carries one is refused: it would either
// leak a credential or override the identity's.
var LineTemplateReservedParams = map[string]bool{
	"id": true, "add": true, "port": true, "ps": true, "v": true, "flow": true,
}

// lineTemplateParams are the only params a catalogue template may carry: the
// connection parameters the core's template builder keeps from a share URI
// (lineClientURIParams in lattice-server) and from a vmess document
// (lineClientVMessFields). The builder drops every other parameter, so a
// template with another key did not come from it. A parameter the core
// starts to keep is added here in the same change.
var lineTemplateParams = map[string]bool{
	"aid": true, "allowInsecure": true, "alpn": true, "congestion_control": true, "encryption": true,
	"fp": true, "headerType": true, "host": true, "insecure": true, "mode": true, "net": true,
	"path": true, "pbk": true, "pinSHA256": true, "security": true, "serviceName": true,
	"sid": true, "sni": true, "spx": true, "tls": true, "type": true,
}

// lineCatalogueExtraKey is the shape of a key in a row's Extra: a lowercase
// snake_case name, like every other catalogue field.
var lineCatalogueExtraKey = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// LineCatalogueRow is one line as the catalogue serves it: what the line is,
// where it runs, what is known about its health, and the credential-free
// template the core binds an identity's credential into.
type LineCatalogueRow struct {
	// LineUUID is the line's durable control-plane identity, a lowercase
	// UUIDv4. Plans name lines by it.
	LineUUID string `json:"line_uuid"`
	// LineHashID is the line's connection-shape handle in the read model.
	LineHashID string `json:"line_hash_id"`
	// NodeID is the node the line runs on.
	NodeID string `json:"node_id"`
	// NodeName is that node's display name.
	NodeName string `json:"node_name,omitempty"`
	// Name is the line's own name.
	Name string `json:"name,omitempty"`
	// Label is the entry label the core shows for the line and names its
	// bind entries by: the node name, then the line's name, tag or hash id.
	// A consumer names the line's nodes by it as given and never derives it
	// from Name, which is empty for many lines.
	Label string `json:"label,omitempty"`
	// NodeTags are the node's tags.
	NodeTags []string `json:"node_tags,omitempty"`
	// GroupIDs are the groups the node belongs to.
	GroupIDs []string `json:"group_ids,omitempty"`
	// Geo is where the node is. It describes the entry machine; for a
	// chained line Chain.ExitGeo says where traffic leaves.
	Geo *NodeGeo `json:"geo,omitempty"`
	// Machine is the node's machine profile, reduced to what filters use.
	Machine *LineCatalogueMachine `json:"machine,omitempty"`
	// DDNSNames are the DNS names the node's DDNS profiles publish.
	DDNSNames []LineCatalogueDDNSName `json:"ddns_names,omitempty"`
	// Protocol is the line's protocol, such as vless or hysteria2.
	Protocol string `json:"protocol"`
	// Transport is the line's transport, such as tcp, ws or grpc.
	Transport string `json:"transport,omitempty"`
	// Security is the line's security layer, such as tls or reality.
	Security string `json:"security,omitempty"`
	// PublicHost is where the outside reaches the line.
	PublicHost string `json:"public_host,omitempty"`
	// PublicPort is the port the outside reaches, zero when it equals the
	// listen port.
	PublicPort int `json:"public_port,omitempty"`
	// ProviderEdge is the provider hostname that forwards into a node behind
	// NAT.
	ProviderEdge string `json:"provider_edge,omitempty"`
	// Addresses are the canonical IP addresses the line's host names
	// resolved to at the last template sync. A plan node whose server is one
	// of them is still the line's own node.
	Addresses []string `json:"addresses,omitempty"`
	// Managed is set for a line under Lattice config management.
	Managed bool `json:"managed,omitempty"`
	// Overlay is set for a line backed by a design-17 managed overlay.
	Overlay bool `json:"overlay,omitempty"`
	// OverlayStatus is the overlay's state: planned, applied or failed.
	OverlayStatus string `json:"overlay_status,omitempty"`
	// Status is the configuration truth: ok, pending, error or stale.
	Status string `json:"status,omitempty"`
	// ServiceState is the process truth: running, down, restarting or
	// unknown. A line that is down is excluded when the core binds.
	ServiceState string `json:"service_state,omitempty"`
	// Chain places the line in a chain. Every row carries it; a line outside
	// any chain has role single.
	Chain LineCatalogueChain `json:"chain"`
	// Probe is the line's last probe verdict. It is null until the probe's
	// history records lines, and null never excludes a line: a predicate over
	// a null block is unknown.
	Probe *LineCatalogueProbe `json:"probe"`
	// Usage is the named identity's usage of this line in the current
	// period, present only when the request named an identity.
	Usage *LineCatalogueUsage `json:"usage,omitempty"`
	// Template is the line's credential-free client template. For a
	// committed chain root (Chain.Root) it is the composed entry template.
	// Nil when the line has no template yet; the core cannot bind such a
	// line.
	Template *LineCatalogueTemplate `json:"template,omitempty"`
	// Extra carries fields added after this version, so a new field needs no
	// new capability wave. Keys are lowercase snake_case names, the whole map
	// is at most MaxLineCatalogueExtraBytes, and no key at any depth is a
	// credential name.
	Extra map[string]json.RawMessage `json:"extra,omitempty"`
}

// LineCatalogueMachine is the part of a node's machine profile the catalogue
// serves. Console links, prices and notes stay in the core.
type LineCatalogueMachine struct {
	// Vendor is the provider the machine is rented from.
	Vendor string `json:"vendor,omitempty"`
	// Region is the vendor's region name for the machine.
	Region string `json:"region,omitempty"`
	// NextRenewal is when the machine's current term ends. Zero when unknown.
	NextRenewal time.Time `json:"next_renewal,omitzero"`
}

// LineCatalogueDDNSName is one DNS name a node's DDNS profile publishes.
type LineCatalogueDDNSName struct {
	// Name is the lowercase DNS name.
	Name string `json:"name"`
	// Verified is set when the name resolved to the node's current public
	// address at the last template sync. Only a verified name may stand in
	// for a line's dial address.
	Verified bool `json:"verified,omitempty"`
	// Target is the host a cname-type profile's name points at, set when the
	// name is verified by resolving to that host's addresses. A line behind
	// NAT may be dialled only by a verified name whose Target is its provider
	// edge.
	Target string `json:"target,omitempty"`
}

// LineCatalogueChain places a line in a chain.
type LineCatalogueChain struct {
	// Role is one of the LineChainRole values.
	Role string `json:"role"`
	// Root is set for the root of a committed chain definition: the row's
	// template is the composed entry template and PathState applies.
	Root bool `json:"root,omitempty"`
	// DownstreamLineUUID is the next line on the path, when there is one.
	DownstreamLineUUID string `json:"downstream_line_uuid,omitempty"`
	// PathState is one of the LinePath values, set for a committed chain
	// root.
	PathState string `json:"path_state,omitempty"`
	// ExitGeo is where traffic leaves the chain: the committed exit line's
	// node geo, replaced by the probe's measured exit location when one
	// exists. Geo predicates read it in place of the row's Geo.
	ExitGeo *NodeGeo `json:"exit_geo,omitempty"`
	// Unresolved is set on a relay whose outbound resolves to no fleet line.
	// Such a relay's exit is unknown, so its effective geo is unknown too: a
	// geo predicate never reads the row's own Geo in its place.
	Unresolved bool `json:"unresolved,omitempty"`
	// PathServiceState is the worst service state along the line's
	// single-successor path (down, then restarting, then unknown, then
	// running), empty when the line has no path.
	PathServiceState string `json:"path_service_state,omitempty"`
}

// LineCatalogueProbe is a line's last probe verdict, derived by the core from
// the probe history. The plugin stores nothing about probes.
type LineCatalogueProbe struct {
	// Verdict is one of the LineProbeVerdict values.
	Verdict string `json:"verdict"`
	// At is when the verdict was measured.
	At time.Time `json:"at"`
	// Vantage is where the probe ran: "control-plane" or "node:<id>".
	Vantage string `json:"vantage,omitempty"`
	// ConsecutiveFailures counts the failures since the last pass, read from
	// the history.
	ConsecutiveFailures int `json:"consecutive_failures"`
	// ColdP50MS is the median cold delay in milliseconds, zero when unknown.
	ColdP50MS int `json:"cold_p50_ms,omitempty"`
	// UDPOK reports whether UDP relayed, nil when it was not tested.
	UDPOK *bool `json:"udp_ok,omitempty"`
}

// LineCatalogueUsage is one identity's traffic on one line in the identity's
// current period.
type LineCatalogueUsage struct {
	// IdentityID is the identity the request named.
	IdentityID string `json:"identity_id"`
	// UsedBytes is the identity's traffic on the line in the period.
	UsedBytes int64 `json:"used_bytes"`
	// From is when the period started.
	From time.Time `json:"from,omitzero"`
	// To is when the period ends.
	To time.Time `json:"to,omitzero"`
}

// LineCatalogueTemplate is a line's credential-free client template: the
// endpoint a client dials and the connection parameters, with the
// credential left out.
type LineCatalogueTemplate struct {
	// Protocol is the template's protocol, which a client entry is built for.
	Protocol string `json:"protocol"`
	// Host is the endpoint host a client dials.
	Host string `json:"host"`
	// Port is the endpoint port a client dials.
	Port int `json:"port"`
	// Params are the kept connection parameters. Never a credential.
	Params map[string]string `json:"params,omitempty"`
	// Dropped names, sorted, the parameters the template did not keep. A
	// template that dropped one is lossy and the core builds no entry from it.
	Dropped []string `json:"dropped,omitempty"`
	// Digest identifies the template's content. Equal digests mean equal
	// templates; the probe history joins on it.
	Digest string `json:"digest"`
}

// LineCatalogueSelector is the structured filter a catalogue request pushes
// into the core. Set fields combine with AND, the values of one list with OR,
// and an unset field constrains nothing. The core refuses a field it does not
// know, and advertises the fields it evaluates in
// LineCatalogueResponse.SelectorFields; a plugin pushes only those and runs
// any other predicate itself.
//
// Country and region match a row's effective geo: Chain.ExitGeo when the row
// has one, else Geo. A filter step that asks for the entry geo of a chained
// line is not pushable and runs in the plugin.
type LineCatalogueSelector struct {
	// LineUUIDs pins an explicit line list. The response keeps this order,
	// which is how a record pins chain roots in their committed order.
	LineUUIDs []string `json:"line_uuids,omitempty"`
	// Countries are ISO 3166-1 alpha-2 codes, compared case-insensitively.
	Countries []string `json:"countries,omitempty"`
	// Regions are geo region names, compared case-insensitively.
	Regions []string `json:"regions,omitempty"`
	// Protocols matches the row's protocol.
	Protocols []string `json:"protocols,omitempty"`
	// Transports matches the row's transport.
	Transports []string `json:"transports,omitempty"`
	// NodeTags matches a row whose node carries any of the tags.
	NodeTags []string `json:"node_tags,omitempty"`
	// GroupIDs matches a row whose node is in any of the groups.
	GroupIDs []string `json:"group_ids,omitempty"`
	// ServiceStates matches the row's service state.
	ServiceStates []string `json:"service_states,omitempty"`
	// ChainRoles are LineChainRole values.
	ChainRoles []string `json:"chain_roles,omitempty"`
	// RenewalWithinDays matches a row whose machine renews within this many
	// days from the core's clock. A row with no known renewal never matches.
	RenewalWithinDays *int `json:"renewal_within_days,omitempty"`
	// ProbePassedWithinHours matches a row whose last probe passed within
	// this many hours. A row with a null probe block never matches.
	ProbePassedWithinHours *int `json:"probe_passed_within_hours,omitempty"`
}

// LineCatalogueRequest is the payload of the catalogue method.
type LineCatalogueRequest struct {
	// IdentityID asks for that identity's per-line usage in each row.
	IdentityID string `json:"identity_id,omitempty"`
	// Selector filters the rows before paging. Nil selects every line.
	Selector *LineCatalogueSelector `json:"selector,omitempty"`
	// Cursor is the Cursor of the previous page, empty for the first page.
	Cursor string `json:"cursor,omitempty"`
	// Limit is the page size; zero asks for the core's default. At most
	// MaxLineCataloguePageRows. A page may hold fewer rows, when it reaches
	// MaxLineCataloguePageBytes first; only an empty Cursor ends a read.
	Limit int `json:"limit,omitempty"`
}

// LineCatalogueResponse is one page of the catalogue.
type LineCatalogueResponse struct {
	// CatalogueVersion is a canonical version of the whole selection, the
	// same on every page of one read. A page that carries another version
	// means the catalogue moved under the read, which then starts over. It
	// doubles as a fleet snapshot's source version.
	CatalogueVersion string `json:"catalogue_version"`
	// Rows are this page's lines.
	Rows []LineCatalogueRow `json:"rows"`
	// Cursor reads the next page. Empty on the last page.
	Cursor string `json:"cursor,omitempty"`
	// SelectorFields lists the selector fields, by JSON name, that this core
	// evaluates. The first page carries it.
	SelectorFields []string `json:"selector_fields,omitempty"`
	// Unavailable names the row blocks this core never fills, such as
	// LineCatalogueUnavailableProbe. A predicate over one is unknown on every
	// row, so a consumer offers none and saves none.
	Unavailable []string `json:"unavailable,omitempty"`
}

// Validate checks a row's shape: its identity, its enums, its addresses, that
// its template keeps only known connection parameters, that its Extra is
// bounded and credential-free in shape, and that it encodes to at most
// MaxLineCatalogueRowBytes.
func (r LineCatalogueRow) Validate() error {
	_, err := r.validate()
	return err
}

// validate is Validate, and it also returns the row's encoded length.
func (r LineCatalogueRow) validate() (int, error) {
	if err := r.validateFields(); err != nil {
		return 0, err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return 0, fmt.Errorf("line catalogue row %s: %w", r.LineUUID, err)
	}
	if len(raw) > MaxLineCatalogueRowBytes {
		return 0, fmt.Errorf("line catalogue row %s encodes to %d bytes, over %d", r.LineUUID, len(raw), MaxLineCatalogueRowBytes)
	}
	return len(raw), nil
}

func (r LineCatalogueRow) validateFields() error {
	if !subscriptionSourceUUIDv4.MatchString(r.LineUUID) {
		return errors.New("line catalogue row: line_uuid must be a lowercase uuidv4")
	}
	for name, value := range map[string]string{"line_hash_id": r.LineHashID, "node_id": r.NodeID, "protocol": r.Protocol} {
		if !validCatalogueID(value) {
			return fmt.Errorf("line catalogue row %s: invalid %s", r.LineUUID, name)
		}
	}
	for name, value := range map[string]string{
		"transport": r.Transport, "security": r.Security, "overlay_status": r.OverlayStatus,
		"status": r.Status, "service_state": r.ServiceState,
	} {
		if value != "" && !validCatalogueID(value) {
			return fmt.Errorf("line catalogue row %s: invalid %s", r.LineUUID, name)
		}
	}
	for _, value := range []string{r.NodeName, r.Name, r.Label, r.PublicHost, r.ProviderEdge} {
		if len(value) > MaxSubscriptionURIBytes {
			return fmt.Errorf("line catalogue row %s: text exceeds %d bytes", r.LineUUID, MaxSubscriptionURIBytes)
		}
	}
	for _, list := range [][]string{r.NodeTags, r.GroupIDs} {
		for _, value := range list {
			if value == "" || len(value) > MaxSubscriptionURIBytes {
				return fmt.Errorf("line catalogue row %s: invalid tag or group", r.LineUUID)
			}
		}
	}
	if r.PublicPort < 0 || r.PublicPort > 65535 {
		return fmt.Errorf("line catalogue row %s: invalid public_port", r.LineUUID)
	}
	for _, address := range r.Addresses {
		if ip := net.ParseIP(address); ip == nil || ip.String() != address {
			return fmt.Errorf("line catalogue row %s: address %q is not a canonical IP", r.LineUUID, address)
		}
	}
	for _, ddns := range r.DDNSNames {
		if net.ParseIP(ddns.Name) != nil || !validSubscriptionHost(ddns.Name) || numericAddressName(ddns.Name) {
			return fmt.Errorf("line catalogue row %s: invalid ddns name %q", r.LineUUID, ddns.Name)
		}
		if ddns.Target != "" && (len(ddns.Target) > MaxSubscriptionURIBytes || !validTemplateText(ddns.Target, 253) ||
			strings.TrimSpace(ddns.Target) != ddns.Target || strings.ContainsAny(ddns.Target, "/@?#[] ")) {
			return fmt.Errorf("line catalogue row %s: invalid ddns target for %q", r.LineUUID, ddns.Name)
		}
	}
	if err := r.Chain.Validate(); err != nil {
		return fmt.Errorf("line catalogue row %s: %w", r.LineUUID, err)
	}
	if r.Probe != nil {
		if err := r.Probe.Validate(); err != nil {
			return fmt.Errorf("line catalogue row %s: %w", r.LineUUID, err)
		}
	}
	if r.Usage != nil {
		if !validCatalogueID(r.Usage.IdentityID) || r.Usage.UsedBytes < 0 {
			return fmt.Errorf("line catalogue row %s: invalid usage", r.LineUUID)
		}
	}
	if r.Template != nil {
		if err := r.Template.Validate(); err != nil {
			return fmt.Errorf("line catalogue row %s: %w", r.LineUUID, err)
		}
	}
	if err := validateLineCatalogueExtra(r.Extra); err != nil {
		return fmt.Errorf("line catalogue row %s: %w", r.LineUUID, err)
	}
	return nil
}

// validateLineCatalogueExtra bounds a row's Extra and screens it the way a
// template's params are screened: every key is a lowercase field name, no
// key at any depth is a credential name, and no string at any depth looks
// like a sealed secret, a private key or a URL.
func validateLineCatalogueExtra(extra map[string]json.RawMessage) error {
	total := 0
	for key, value := range extra {
		if !lineCatalogueExtraKey.MatchString(key) {
			return fmt.Errorf("extra key %q is not a lowercase field name", key)
		}
		total += len(key) + len(value)
		if total > MaxLineCatalogueExtraBytes {
			return fmt.Errorf("extra exceeds %d bytes", MaxLineCatalogueExtraBytes)
		}
		// A duplicate key would hide its first value from the screen below
		// while the raw bytes, which the row re-emits, still carry it.
		if err := rejectDuplicateJSONFields(value); err != nil {
			return fmt.Errorf("extra %q: %w", key, err)
		}
		var decoded any
		if err := json.Unmarshal(value, &decoded); err != nil {
			return fmt.Errorf("extra %q is not valid JSON", key)
		}
		if err := screenCatalogueValue(key, decoded); err != nil {
			return fmt.Errorf("extra %q: %w", key, err)
		}
	}
	return nil
}

// screenCatalogueValue walks one decoded JSON value under name and refuses a
// credential name or a sensitive-looking string anywhere in it.
func screenCatalogueValue(name string, value any) error {
	if credentialName(name) {
		return fmt.Errorf("%q is a credential name", name)
	}
	switch v := value.(type) {
	case string:
		if sensitiveCatalogueText(v) {
			return fmt.Errorf("%q carries sensitive text", name)
		}
	case []any:
		for _, item := range v {
			if err := screenCatalogueValue(name, item); err != nil {
				return err
			}
		}
	case map[string]any:
		for key, item := range v {
			if err := screenCatalogueValue(key, item); err != nil {
				return err
			}
		}
	}
	return nil
}

// credentialName reports whether a field name is one a proxy protocol keeps
// a credential under: the vless, vmess and tuic uuid (id in a vmess
// document), the passwords of trojan, hysteria2, tuic, anytls, shadowsocks
// and socks, the socks username, hysteria's auth string, WireGuard's private
// and pre-shared keys, obfuscation passwords, and anything named a secret or
// a token. Case, hyphens and underscores are ignored, so private-key,
// private_key and privateKey are one name.
func credentialName(name string) bool {
	folded := strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(name))
	switch folded {
	case "id", "uuid", "auth", "authstr", "psk", "username", "pass":
		return true
	}
	for _, stem := range []string{"password", "passwd", "secret", "token", "privatekey", "presharedkey", "credential"} {
		if strings.Contains(folded, stem) {
			return true
		}
	}
	return false
}

// sensitiveCatalogueText reports whether a value looks like a sealed secret,
// a private key or a URL, none of which a credential-free row carries.
func sensitiveCatalogueText(value string) bool {
	return strings.Contains(value, "://") || strings.Contains(strings.ToUpper(value), "PRIVATE KEY") || strings.HasPrefix(value, "lat$")
}

// Validate checks a chain block.
func (c LineCatalogueChain) Validate() error {
	switch c.Role {
	case LineChainRoleSingle, LineChainRoleEntry, LineChainRoleRelay, LineChainRoleExit:
	default:
		return fmt.Errorf("invalid chain role %q", c.Role)
	}
	switch c.PathState {
	case "", LinePathConverged, LinePathDrifted, LinePathBusy:
	default:
		return fmt.Errorf("invalid chain path state %q", c.PathState)
	}
	if c.DownstreamLineUUID != "" && !subscriptionSourceUUIDv4.MatchString(c.DownstreamLineUUID) {
		return errors.New("chain downstream_line_uuid must be a lowercase uuidv4")
	}
	switch c.PathServiceState {
	case "", LineServiceStateRunning, LineServiceStateDown, LineServiceStateRestarting, LineServiceStateUnknown:
	default:
		return fmt.Errorf("invalid chain path_service_state %q", c.PathServiceState)
	}
	return nil
}

// Validate checks a probe block.
func (p LineCatalogueProbe) Validate() error {
	if p.Verdict != LineProbeVerdictPass && p.Verdict != LineProbeVerdictFail {
		return fmt.Errorf("invalid probe verdict %q", p.Verdict)
	}
	if p.ConsecutiveFailures < 0 || p.ColdP50MS < 0 {
		return errors.New("probe counters must not be negative")
	}
	if p.Vantage != "" && !validCatalogueID(p.Vantage) {
		return errors.New("invalid probe vantage")
	}
	return nil
}

// Validate checks a template the way the core's template store does, refuses
// a reserved parameter and any parameter the core's builder does not keep,
// and refuses a value that looks like a sealed secret, a private key or a
// URL.
func (t LineCatalogueTemplate) Validate() error {
	switch {
	case !validCatalogueID(t.Protocol):
		return errors.New("template needs a protocol")
	case strings.TrimSpace(t.Host) == "" || !validTemplateText(t.Host, 253) || strings.ContainsAny(t.Host, "/@?#[] "):
		return errors.New("template has an invalid host")
	case t.Port < 1 || t.Port > 65535:
		return errors.New("template has an invalid port")
	case len(t.Params) > MaxLineTemplateParams:
		return fmt.Errorf("template has more than %d params", MaxLineTemplateParams)
	case len(t.Dropped) > MaxLineTemplateDropped:
		return fmt.Errorf("template names more than %d dropped params", MaxLineTemplateDropped)
	case !validCatalogueID(t.Digest):
		return errors.New("template needs a digest")
	}
	for key, value := range t.Params {
		if key == "" || !validTemplateText(key, 64) || !validTemplateText(value, MaxLineTemplateValueBytes) {
			return fmt.Errorf("template has an invalid param %q", key)
		}
		if LineTemplateReservedParams[key] {
			return fmt.Errorf("template carries the reserved param %q", key)
		}
		if !lineTemplateParams[key] {
			return fmt.Errorf("template param %q is not a connection parameter the core keeps", key)
		}
		if sensitiveCatalogueText(value) {
			return fmt.Errorf("template param %q carries sensitive text", key)
		}
	}
	for _, name := range t.Dropped {
		if name == "" || !validTemplateText(name, 64) {
			return errors.New("template names an invalid dropped param")
		}
	}
	return nil
}

// Validate checks a selector's values and bounds.
func (s LineCatalogueSelector) Validate() error {
	if len(s.LineUUIDs) > MaxSubscriptionRecordNodes {
		return fmt.Errorf("selector names more than %d lines", MaxSubscriptionRecordNodes)
	}
	seen := make(map[string]struct{}, len(s.LineUUIDs))
	for _, id := range s.LineUUIDs {
		if !subscriptionSourceUUIDv4.MatchString(id) {
			return fmt.Errorf("selector line_uuid %q is not a lowercase uuidv4", id)
		}
		if _, dup := seen[id]; dup {
			return fmt.Errorf("selector names line %s twice", id)
		}
		seen[id] = struct{}{}
	}
	for name, values := range map[string][]string{
		"countries": s.Countries, "regions": s.Regions, "protocols": s.Protocols, "transports": s.Transports,
		"node_tags": s.NodeTags, "group_ids": s.GroupIDs, "service_states": s.ServiceStates, "chain_roles": s.ChainRoles,
	} {
		if len(values) > MaxLineCatalogueSelectorValues {
			return fmt.Errorf("selector %s has more than %d values", name, MaxLineCatalogueSelectorValues)
		}
		for _, value := range values {
			if !validCatalogueID(value) {
				return fmt.Errorf("selector %s has an invalid value", name)
			}
		}
	}
	for _, role := range s.ChainRoles {
		if (LineCatalogueChain{Role: role}).Validate() != nil {
			return fmt.Errorf("selector chain_roles has unknown role %q", role)
		}
	}
	if s.RenewalWithinDays != nil && (*s.RenewalWithinDays < 0 || *s.RenewalWithinDays > MaxLineCatalogueRenewalDays) {
		return fmt.Errorf("selector renewal_within_days must be 0 to %d", MaxLineCatalogueRenewalDays)
	}
	if s.ProbePassedWithinHours != nil && (*s.ProbePassedWithinHours < 1 || *s.ProbePassedWithinHours > MaxLineCatalogueProbeHours) {
		return fmt.Errorf("selector probe_passed_within_hours must be 1 to %d", MaxLineCatalogueProbeHours)
	}
	return nil
}

// LineCatalogueSelectorFields returns, sorted, the JSON name of every field
// LineCatalogueSelector defines. A core that evaluates all of them advertises
// this list.
func LineCatalogueSelectorFields() []string {
	t := reflect.TypeOf(LineCatalogueSelector{})
	out := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		out = append(out, jsonFieldName(t.Field(i)))
	}
	sort.Strings(out)
	return out
}

// Fields returns, sorted, the JSON names of the fields this selector sets. An
// empty list is unset, as it is on the wire.
func (s LineCatalogueSelector) Fields() []string {
	v := reflect.ValueOf(s)
	t := v.Type()
	var out []string
	for i := 0; i < t.NumField(); i++ {
		field := v.Field(i)
		if field.IsZero() || (field.Kind() == reflect.Slice && field.Len() == 0) {
			continue
		}
		out = append(out, jsonFieldName(t.Field(i)))
	}
	sort.Strings(out)
	return out
}

// UnsupportedFields returns, sorted, the fields this selector sets that
// advertised does not list. A plugin pushes a selector only when this is
// empty; a core refuses a selector for which it is not.
func (s LineCatalogueSelector) UnsupportedFields(advertised []string) []string {
	known := make(map[string]struct{}, len(advertised))
	for _, name := range advertised {
		known[name] = struct{}{}
	}
	var out []string
	for _, name := range s.Fields() {
		if _, ok := known[name]; !ok {
			out = append(out, name)
		}
	}
	return out
}

// LineCatalogueSelectorMatches reports whether a row passes every selector
// field but the line list. It is the pushdown contract as one function: a
// core evaluates a pushed selector with it and a plugin that runs a
// predicate itself calls it, so the two cannot disagree. A nil selector
// matches every row. The line list is the caller's: a selector that names
// lines selects those lines, in its own order, and then applies this.
//
//   - countries, regions, protocols, transports and service_states compare
//     with Unicode case folding (strings.EqualFold); an empty row value never
//     matches.
//   - node_tags, group_ids and chain_roles compare exactly.
//   - country and region read the row's effective geo: the chain's exit geo
//     when it has one, else the node's. A field the exit geo lacks does not
//     fall back to the node's geo. A relay whose chain is Unresolved has an
//     unknown geo, so country and region never match it, whatever its own
//     Geo says.
//   - renewal_within_days matches a known renewal at or before now plus the
//     window, so a renewal already past matches.
//   - probe_passed_within_hours matches a pass at or after now minus the
//     window; a null probe block never matches.
func LineCatalogueSelectorMatches(row *LineCatalogueRow, sel *LineCatalogueSelector, now time.Time) bool {
	if sel == nil {
		return true
	}
	geo := row.Geo
	if row.Chain.ExitGeo != nil {
		geo = row.Chain.ExitGeo
	}
	if row.Chain.Unresolved {
		geo = nil
	}
	switch {
	case len(sel.Countries) > 0 && (geo == nil || !lineCatalogueHasFold(sel.Countries, geo.Country)):
		return false
	case len(sel.Regions) > 0 && (geo == nil || !lineCatalogueHasFold(sel.Regions, geo.Region)):
		return false
	case len(sel.Protocols) > 0 && !lineCatalogueHasFold(sel.Protocols, row.Protocol):
		return false
	case len(sel.Transports) > 0 && !lineCatalogueHasFold(sel.Transports, row.Transport):
		return false
	case len(sel.ServiceStates) > 0 && !lineCatalogueHasFold(sel.ServiceStates, row.ServiceState):
		return false
	case len(sel.ChainRoles) > 0 && !slices.Contains(sel.ChainRoles, row.Chain.Role):
		return false
	case len(sel.NodeTags) > 0 && !lineCatalogueAny(sel.NodeTags, row.NodeTags):
		return false
	case len(sel.GroupIDs) > 0 && !lineCatalogueAny(sel.GroupIDs, row.GroupIDs):
		return false
	}
	if sel.RenewalWithinDays != nil {
		if row.Machine == nil || row.Machine.NextRenewal.IsZero() ||
			row.Machine.NextRenewal.After(now.Add(time.Duration(*sel.RenewalWithinDays)*24*time.Hour)) {
			return false
		}
	}
	if sel.ProbePassedWithinHours != nil {
		if row.Probe == nil || row.Probe.Verdict != LineProbeVerdictPass ||
			row.Probe.At.Before(now.Add(-time.Duration(*sel.ProbePassedWithinHours)*time.Hour)) {
			return false
		}
	}
	return true
}

func lineCatalogueHasFold(values []string, value string) bool {
	if value == "" {
		return false
	}
	for _, v := range values {
		if strings.EqualFold(v, value) {
			return true
		}
	}
	return false
}

func lineCatalogueAny(wanted, have []string) bool {
	for _, w := range wanted {
		if slices.Contains(have, w) {
			return true
		}
	}
	return false
}

// Validate checks a catalogue request.
func (r LineCatalogueRequest) Validate() error {
	if r.IdentityID != "" && !validCatalogueID(r.IdentityID) {
		return errors.New("catalogue request has an invalid identity_id")
	}
	if r.Cursor != "" && !validCatalogueToken(r.Cursor) {
		return errors.New("catalogue request has an invalid cursor")
	}
	if r.Limit < 0 || r.Limit > MaxLineCataloguePageRows {
		return fmt.Errorf("catalogue request limit must be 0 to %d", MaxLineCataloguePageRows)
	}
	if r.Selector != nil {
		return r.Selector.Validate()
	}
	return nil
}

// DecodeLineCatalogueRequest decodes a catalogue request strictly: bounded
// size, no duplicate keys, no unknown fields, no trailing data. An unknown
// selector field is therefore refused, as the catalogue contract requires.
func DecodeLineCatalogueRequest(raw []byte) (LineCatalogueRequest, error) {
	if len(raw) == 0 || len(raw) > MaxLineCatalogueRequestBytes {
		return LineCatalogueRequest{}, errors.New("invalid catalogue request size")
	}
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return LineCatalogueRequest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var req LineCatalogueRequest
	if err := decoder.Decode(&req); err != nil {
		return LineCatalogueRequest{}, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return LineCatalogueRequest{}, err
	}
	if err := req.Validate(); err != nil {
		return LineCatalogueRequest{}, err
	}
	return req, nil
}

// Validate checks a catalogue page: its version and cursor, its row count,
// every row, that no line appears twice, and that the page encodes to at
// most MaxLineCataloguePageBytes.
func (r LineCatalogueResponse) Validate() error {
	if !validCatalogueToken(r.CatalogueVersion) {
		return errors.New("catalogue page needs a catalogue_version")
	}
	if r.Cursor != "" && !validCatalogueToken(r.Cursor) {
		return errors.New("catalogue page has an invalid cursor")
	}
	if len(r.Rows) > MaxLineCataloguePageRows {
		return fmt.Errorf("catalogue page has more than %d rows", MaxLineCataloguePageRows)
	}
	for _, name := range r.SelectorFields {
		if !validCatalogueID(name) {
			return errors.New("catalogue page advertises an invalid selector field")
		}
	}
	for _, name := range r.Unavailable {
		if !validCatalogueID(name) {
			return errors.New("catalogue page names an invalid unavailable block")
		}
	}
	seen := make(map[string]struct{}, len(r.Rows))
	rowBytes := 0
	for _, row := range r.Rows {
		size, err := row.validate()
		if err != nil {
			return err
		}
		if _, dup := seen[row.LineUUID]; dup {
			return fmt.Errorf("catalogue page lists line %s twice", row.LineUUID)
		}
		seen[row.LineUUID] = struct{}{}
		rowBytes += size
	}
	// The page encodes as its envelope with an empty rows array, plus each
	// row's own encoding and a comma between rows; encoding/json writes a
	// slice element exactly as it writes the value alone. Summing the rows
	// already encoded avoids encoding the whole page a second time.
	envelope := r
	if len(r.Rows) > 0 {
		envelope.Rows = []LineCatalogueRow{}
	}
	head, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	size := len(head) + rowBytes + max(len(r.Rows)-1, 0)
	if size > MaxLineCataloguePageBytes {
		return fmt.Errorf("catalogue page encodes to %d bytes, over %d", size, MaxLineCataloguePageBytes)
	}
	return nil
}

func jsonFieldName(field reflect.StructField) string {
	name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	return name
}

// validCatalogueID is the rule for identifiers and enum values: present,
// bounded, trimmed and printable.
func validCatalogueID(value string) bool {
	return value != "" && value == strings.TrimSpace(value) && len(value) <= MaxSubscriptionURIBytes &&
		!strings.ContainsFunc(value, unicode.IsControl)
}

func validCatalogueToken(value string) bool {
	return validCatalogueID(value) && len(value) <= MaxLineCatalogueTokenBytes
}

func validTemplateText(value string, maxBytes int) bool {
	return len(value) <= maxBytes && !strings.ContainsFunc(value, unicode.IsControl)
}
