package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// The core calls three methods of a subscription plugin's
// latticenet.sub-store/subscription service: fetch, render and convert. The
// types below are their replies and convert's request. Before design 28 the
// core decoded them into anonymous structs and the Sub-Store plugin encoded
// them from its own; these types keep those JSON names and that field order,
// so a value that sets no new field encodes to the same bytes as before and
// an old payload decodes unchanged. Every addition is optional.

// Response headers a record may ask the core to send. The core admits only
// these, checks each value, and never lets a record set the status or
// Subscription-Userinfo.
const (
	ResponseHeaderContentDisposition    = "content-disposition"
	ResponseHeaderProfileUpdateInterval = "profile-update-interval"
	ResponseHeaderProfileWebPageURL     = "profile-web-page-url"
	ResponseHeaderPlanName              = "plan-name"
)

// Bounds of the header channel and the convert log.
const (
	// MaxSubscriptionResponseHeaderBytes bounds the value of every header a
	// record may ask for, the web page URL included.
	MaxSubscriptionResponseHeaderBytes = 2 << 10
	// MinProfileUpdateIntervalHours and MaxProfileUpdateIntervalHours bound
	// profile-update-interval, as the core bounds a share's own interval.
	MinProfileUpdateIntervalHours = 1
	MaxProfileUpdateIntervalHours = 168
	// MaxSubscriptionUserinfoBytes bounds a Subscription-Userinfo value.
	MaxSubscriptionUserinfoBytes = 512
)

// Levels of a ConvertLogEntry: $substore.info and $substore.error.
const (
	ConvertLogInfo  = "info"
	ConvertLogError = "error"
)

// FetchReply is the reply of fetch: the source's current content, which the
// core stores as the record's snapshot. An empty Raw is a failed fetch, never
// a source with no nodes.
type FetchReply struct {
	// Raw is the content the core stores as the snapshot's Raw.
	Raw string `json:"raw"`
	// Userinfo is the provider's Subscription-Userinfo value.
	Userinfo string `json:"userinfo,omitempty"`
	// SourceVersion identifies the secret-free source state behind Raw.
	SourceVersion string `json:"source_version,omitempty"`
	// SourceManifest is the canonical provenance document SourceVersion
	// hashes.
	SourceManifest json.RawMessage `json:"source_manifest,omitempty"`
	// Flow is the provider's flow information. A plugin that fills it also
	// keeps Userinfo above, so a core that predates Flow still passes the
	// traffic figures through.
	Flow *SubscriptionFlow `json:"flow,omitempty"`
}

// SubscriptionFlow is what a provider says about the subscription itself, as
// the plugin captured it on fetch.
type SubscriptionFlow struct {
	// Userinfo is the Subscription-Userinfo value, possibly from a dedicated
	// flow URL rather than the body's response.
	Userinfo string `json:"userinfo,omitempty"`
	// WebPageURL is the provider's Profile-Web-Page-URL. Clients open it, so
	// it must pass ValidateSubscriptionWebPageURL.
	WebPageURL string `json:"web_page_url,omitempty"`
	// PlanName is the provider's Plan-Name.
	PlanName string `json:"plan_name,omitempty"`
	// FetchedAt is when the flow information was read.
	FetchedAt time.Time `json:"fetched_at,omitzero"`
}

// RenderReply is the reply of render. A record that is not fleet-bound
// returns a document in Content; a fleet-bound record returns Plan instead,
// with Content empty.
type RenderReply struct {
	// Content is the produced document. Empty when Plan is set.
	Content string `json:"content"`
	// ContentType is what the plugin says Content is. The core picks the
	// wire content type itself.
	ContentType string `json:"content_type"`
	// NodeCount is how many nodes the document carries, reported to a caller
	// that asked to explain; the serve path does not ask.
	NodeCount int `json:"node_count,omitempty"`
	// DroppedNodeCount is how many nodes the client could not carry.
	DroppedNodeCount int `json:"dropped_node_count,omitempty"`
	// DroppedProtocols names the protocols of those nodes.
	DroppedProtocols []string `json:"dropped_protocols,omitempty"`
	// Headers are the response headers the record asks for. The core admits
	// the allow-listed ones whose values pass
	// ValidateSubscriptionResponseHeader and drops the rest.
	Headers map[string]string `json:"headers,omitempty"`
	// Target is the client the document was produced for. Empty for a file.
	Target string `json:"target,omitempty"`
	// ZeroNodes reports, to a caller that asked, that the document carries
	// no node for the client.
	ZeroNodes bool `json:"zero_nodes,omitempty"`
	// Plan is a fleet-bound record's selection plan.
	Plan *SelectionPlan `json:"plan,omitempty"`
}

// ConvertRequest is the whole input of convert, which produces one client's
// document and has no network, no store and no host calls. Exactly one of
// URIs, Raw, Nodes and Document is set.
type ConvertRequest struct {
	// URIs is one share link per entry, as identity links send them.
	URIs []string `json:"uris,omitempty"`
	// Raw is node text the plugin parses: a URI list, a base64 list, a Clash
	// document.
	Raw string `json:"raw,omitempty"`
	// Target is the client. Empty only with Document, which has no target.
	Target string `json:"target"`
	// Format is "" or "base64" for the client's native form, "plain" for a
	// bare URI list.
	Format string `json:"format,omitempty"`
	// Options are produce flags under upstream's names.
	Options map[string]bool `json:"options,omitempty"`
	// Nodes are a typed-node plan's nodes after the core bound them: each a
	// node model JSON object carrying the identity's credential where the
	// placeholder was. Excluded nodes are absent.
	Nodes []json.RawMessage `json:"nodes,omitempty"`
	// Document is a document plan's text with its bound credentials.
	Document *ConvertDocument `json:"document,omitempty"`
	// ResponseChain is the plan's Response Transformer steps, run on the
	// produced body inside convert.
	ResponseChain []ResponseTransformerStep `json:"response_chain,omitempty"`
}

// ConvertDocument is a document plan's produced text and, for each
// placeholder in it, the credential the core bound. Convert puts each
// credential where its placeholder is and calls nothing.
//
// Validate keeps every credential to one bounded line, so a credential cannot
// add a line to the document. It does not make a credential safe inside a
// quoted scalar: a password holding a quote or a backslash, pasted in byte
// for byte, ends a YAML or JSON string early. Identity passwords come from
// the core's credential store and may hold any printable character, so
// convert must write each credential encoded for the scalar its placeholder
// sits in. A plain textual replacement is correct only where every character
// of the credential is literal.
type ConvertDocument struct {
	// Content is the document plan's text, placeholders included.
	Content string `json:"content"`
	// Substitutions maps each placeholder to the credential bound in its
	// place.
	Substitutions map[string]string `json:"substitutions"`
}

// ResponseTransformerStep is one Response Transformer step with its script
// source already inlined, because convert cannot read the store or the
// network.
type ResponseTransformerStep struct {
	// Name is the step's custom name, which context.process uses to enable
	// or disable it.
	Name string `json:"name,omitempty"`
	// Source is the script.
	Source string `json:"source"`
	// Arguments is the step's $arguments, a JSON object. Absent means none.
	Arguments json.RawMessage `json:"arguments,omitempty"`
	// Enabled says whether the step runs unless context.process changes it.
	Enabled bool `json:"enabled"`
}

// ConvertReply is the reply of convert.
type ConvertReply struct {
	// Content is the produced document.
	Content string `json:"content"`
	// ContentType is what the plugin says Content is.
	ContentType string `json:"content_type"`
	// Target is the client the document was produced for.
	Target string `json:"target"`
	// NodeCount is how many nodes the document carries.
	NodeCount int `json:"node_count"`
	// Headers are the response headers the response chain asked for, under
	// the same allow-list as RenderReply.Headers.
	Headers map[string]string `json:"headers,omitempty"`
	// Log is what the response chain wrote through $substore.info and
	// $substore.error, buffered because convert cannot write the log; the
	// core writes it to the record's processing log.
	Log []ConvertLogEntry `json:"log,omitempty"`
}

// ConvertLogEntry is one buffered log line of a response chain.
type ConvertLogEntry struct {
	// Level is ConvertLogInfo or ConvertLogError.
	Level string `json:"level"`
	// Message is what the script wrote.
	Message string `json:"message"`
}

// Validate checks a fetch reply: content present and inside the raw bound,
// and the flow block when there is one.
func (r FetchReply) Validate() error {
	if r.Raw == "" {
		return errors.New("fetch returned no content")
	}
	if len(r.Raw) > MaxSubscriptionRawBytes {
		return fmt.Errorf("fetch content exceeds %d bytes", MaxSubscriptionRawBytes)
	}
	if r.Flow != nil {
		return r.Flow.Validate()
	}
	return nil
}

// Validate checks every field of a flow block.
func (f SubscriptionFlow) Validate() error {
	if len(f.Userinfo) > MaxSubscriptionUserinfoBytes || strings.ContainsFunc(f.Userinfo, unicode.IsControl) {
		return errors.New("flow userinfo is not a bounded header value")
	}
	if f.WebPageURL != "" {
		if err := ValidateSubscriptionWebPageURL(f.WebPageURL); err != nil {
			return err
		}
	}
	if f.PlanName != "" {
		return ValidateSubscriptionResponseHeader(ResponseHeaderPlanName, f.PlanName)
	}
	return nil
}

// Validate checks that a render reply carries a document or a plan, not
// both, and that its plan is valid.
func (r RenderReply) Validate() error {
	switch {
	case r.Plan == nil && r.Content == "":
		return errors.New("render returned neither a document nor a plan")
	case r.Plan != nil && r.Content != "":
		return errors.New("render returned both a document and a plan")
	case r.Plan != nil:
		return r.Plan.Validate()
	}
	return nil
}

// Validate checks that exactly one input is set, that every input but a
// document names a target, and that the new inputs and the response chain
// are inside their bounds.
func (r ConvertRequest) Validate() error {
	inputs := 0
	for _, set := range []bool{len(r.URIs) > 0, r.Raw != "", len(r.Nodes) > 0, r.Document != nil} {
		if set {
			inputs++
		}
	}
	if inputs != 1 {
		return errors.New("convert needs exactly one of uris, raw, nodes and document")
	}
	if r.Document == nil && !validCatalogueID(r.Target) {
		return errors.New("convert of uris, raw or nodes needs a target")
	}
	if len(r.Nodes) > MaxSubscriptionRecordNodes {
		return fmt.Errorf("convert carries more than %d nodes", MaxSubscriptionRecordNodes)
	}
	for i, node := range r.Nodes {
		if !isJSONObject(node) {
			return fmt.Errorf("convert node %d is not a JSON object", i)
		}
	}
	if r.Document != nil {
		if err := r.Document.Validate(); err != nil {
			return err
		}
	}
	return ValidateResponseChain(r.ResponseChain)
}

// Validate checks a document and its substitutions: every key is a
// placeholder, and every credential is present and free of control
// characters, so a substitution cannot add a line to the document.
func (d ConvertDocument) Validate() error {
	if d.Content == "" {
		return errors.New("convert document is empty")
	}
	for placeholder, credential := range d.Substitutions {
		if _, _, err := ParsePlanPlaceholder(placeholder); err != nil {
			return fmt.Errorf("convert substitution key: %w", err)
		}
		if credential == "" || len(credential) > MaxSubscriptionURIBytes || strings.ContainsFunc(credential, unicode.IsControl) {
			return errors.New("convert substitution value is not a bounded single-line credential")
		}
	}
	return nil
}

// ValidateResponseChain checks a response chain's step count, its total size
// (names, sources and arguments together, at most MaxResponseChainBytes) and
// each step.
func ValidateResponseChain(steps []ResponseTransformerStep) error {
	if len(steps) > MaxResponseChainSteps {
		return fmt.Errorf("response chain has more than %d steps", MaxResponseChainSteps)
	}
	total := 0
	for i, step := range steps {
		if step.Source == "" {
			return fmt.Errorf("response step %d has no source", i)
		}
		if len(step.Name) > MaxResponseStepNameBytes || strings.ContainsFunc(step.Name, unicode.IsControl) {
			return fmt.Errorf("response step %d has an invalid name", i)
		}
		if len(step.Arguments) > 0 && !isJSONObject(step.Arguments) {
			return fmt.Errorf("response step %d arguments must be a JSON object", i)
		}
		total += len(step.Name) + len(step.Source) + len(step.Arguments)
		if total > MaxResponseChainBytes {
			return fmt.Errorf("response chain exceeds %d bytes", MaxResponseChainBytes)
		}
	}
	return nil
}

// EncodeConvertRequest validates a convert request and encodes it, refusing
// an encoding over MaxConvertRequestBytes.
func EncodeConvertRequest(r ConvertRequest) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxConvertRequestBytes {
		return nil, fmt.Errorf("convert request encodes to %d bytes, over %d", len(raw), MaxConvertRequestBytes)
	}
	return raw, nil
}

// DecodeConvertRequest decodes a convert request as strictly as the plugin
// always has: bounded size, no duplicate keys at any depth, no unknown
// fields, no trailing data. It then validates the request.
func DecodeConvertRequest(raw []byte) (ConvertRequest, error) {
	if len(raw) == 0 || len(raw) > MaxConvertRequestBytes {
		return ConvertRequest{}, errors.New("invalid convert request size")
	}
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return ConvertRequest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var req ConvertRequest
	if err := decoder.Decode(&req); err != nil {
		return ConvertRequest{}, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return ConvertRequest{}, err
	}
	if err := req.Validate(); err != nil {
		return ConvertRequest{}, err
	}
	return req, nil
}

// Validate checks a convert reply: content present and every log level known.
func (r ConvertReply) Validate() error {
	if r.Content == "" {
		return errors.New("convert returned no content")
	}
	for _, entry := range r.Log {
		if entry.Level != ConvertLogInfo && entry.Level != ConvertLogError {
			return fmt.Errorf("convert log level %q is unknown", entry.Level)
		}
	}
	return nil
}

// ValidateSubscriptionResponseHeader reports whether a record may ask the
// core to send this header with this value. The name is matched without
// regard to case. Every value is at most MaxSubscriptionResponseHeaderBytes
// and has no control character, so no value can end the header early.
func ValidateSubscriptionResponseHeader(name, value string) error {
	lower := strings.ToLower(name)
	switch lower {
	case ResponseHeaderContentDisposition, ResponseHeaderPlanName, ResponseHeaderProfileUpdateInterval, ResponseHeaderProfileWebPageURL:
	default:
		return fmt.Errorf("header %q is not on the allow-list", name)
	}
	if value == "" || len(value) > MaxSubscriptionResponseHeaderBytes || strings.ContainsFunc(value, unicode.IsControl) {
		return fmt.Errorf("header %q value is empty, too long or carries a control character", lower)
	}
	switch lower {
	case ResponseHeaderProfileUpdateInterval:
		hours, err := strconv.Atoi(value)
		if err != nil || hours < MinProfileUpdateIntervalHours || hours > MaxProfileUpdateIntervalHours {
			return fmt.Errorf("profile-update-interval must be %d to %d hours", MinProfileUpdateIntervalHours, MaxProfileUpdateIntervalHours)
		}
	case ResponseHeaderProfileWebPageURL:
		return ValidateSubscriptionWebPageURL(value)
	}
	return nil
}

// ValidateSubscriptionWebPageURL checks a provider web page URL before a
// client is told to open it: https, no userinfo, at most
// MaxSubscriptionResponseHeaderBytes, and a host that is neither a
// non-public address literal, an address with an IPv6 zone, a name ending in
// a dot, nor a local name. A name is not resolved here; the core resolves it
// and applies its egress address policy.
func ValidateSubscriptionWebPageURL(value string) error {
	return validatePublicHTTPSURL("web page url", value)
}

// validatePublicHTTPSURL is the rule ValidateSubscriptionWebPageURL states,
// for any URL a client or the console opens; what names the URL in errors.
func validatePublicHTTPSURL(what, value string) error {
	if len(value) > MaxSubscriptionResponseHeaderBytes || strings.ContainsFunc(value, func(r rune) bool {
		return unicode.IsControl(r) || unicode.IsSpace(r)
	}) {
		return fmt.Errorf("%s is too long or carries whitespace", what)
	}
	u, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if u.Scheme != "https" || u.Opaque != "" || u.Host == "" {
		return fmt.Errorf("%s must be an absolute https url", what)
	}
	if u.User != nil {
		return fmt.Errorf("%s must not carry userinfo", what)
	}
	host := strings.ToLower(u.Hostname())
	if addr, err := netip.ParseAddr(host); err == nil {
		// A zone names an interface of whoever dials, so the same literal
		// reaches a different place on every host.
		if addr.Zone() != "" {
			return fmt.Errorf("%s host carries an ipv6 zone", what)
		}
		if !publicAddress(addr.Unmap()) {
			return fmt.Errorf("%s host is not a public address", what)
		}
		return nil
	}
	// A trailing dot is the fully qualified form of the same name, and it
	// would carry "localhost." past the suffix checks below.
	if strings.HasSuffix(host, ".") {
		return fmt.Errorf("%s host ends in a dot", what)
	}
	if !strings.Contains(host, ".") || host == "localhost" || strings.HasSuffix(host, ".localhost") ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return fmt.Errorf("%s host is a local name", what)
	}
	if numericAddressName(host) {
		return fmt.Errorf("%s host is a numeric address", what)
	}
	return nil
}

// numericAddressName reports whether a host that netip did not parse as an
// address ends in a numeric label. A top-level label is never numeric, so
// such a host is an address in the shorthand clients still accept ("127.1",
// "0x7f.1"), and it must not pass as a name.
func numericAddressName(host string) bool {
	last := host[strings.LastIndexByte(host, '.')+1:]
	return strings.TrimLeft(last, "0123456789") == "" || strings.HasPrefix(last, "0x")
}

// nonPublicPrefixes are ranges netip counts as global unicast that are not
// public. The IPv4 and documentation ranges mirror the core's outbound guard
// (blockedSpecialUsePrefixes in lattice-server internal/outbound): RFC 6598
// carrier-grade NAT space, the three TEST-NET documentation ranges and
// 2001:db8::/32, and the 198.18.0.0/15 benchmarking range, which proxy
// clients hand out as fake-ip addresses. The NAT64 prefixes are added because
// they embed an IPv4 address the egress policy refuses.
var nonPublicPrefixes = []netip.Prefix{
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
}

func publicAddress(addr netip.Addr) bool {
	if !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return false
	}
	for _, prefix := range nonPublicPrefixes {
		if prefix.Contains(addr) {
			return false
		}
	}
	return true
}
