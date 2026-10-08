package model

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

// These tests hold the design-28 additions to the bytes that ship today. The
// golden strings were produced by lattice-sdk at 14636fd (the share) and by
// the Sub-Store plugin's own wire structs at lattice-plugin-sub-store 872f51c
// (fetch, render, convert), copied verbatim below. A value that sets no new
// field must encode to exactly these bytes, and these bytes must decode to
// exactly the old values.

const (
	goldenShareFull = `{"created_at":"2026-10-01T08:00:00Z","default_format":"base64","enabled":true,"expires_at":"2026-11-01T00:00:00Z","id":"share_1","rotated_at":"2026-10-03T10:00:00Z","schema_version":1,"slug":"team","source":{"kind":"plugin","plugin_id":"latticenet.sub-store","subscription_id":"sub_1"},"token":"tok","update_interval_hours":6,"updated_at":"2026-10-02T09:30:00Z"}`
	goldenShareMin  = `{"id":"share_2","schema_version":1,"slug":"core","token":"tok2","source":{"kind":"core.proxy_user","proxy_user_id":"pu_1"},"enabled":false,"created_at":"2026-10-01T08:00:00Z","updated_at":"2026-10-02T09:30:00Z"}`

	goldenFetchFull     = `{"raw":"vless://x","userinfo":"upload=1; download=2; total=3; expire=4","source_version":"sv1:ab","source_manifest":{"schema":"x"}}`
	goldenFetchMin      = `{"raw":"vless://x"}`
	goldenRenderFull    = `{"content":"proxies: []","content_type":"text/yaml","node_count":3,"dropped_node_count":1,"dropped_protocols":["ssr"],"headers":{"profile-update-interval":"6"},"target":"ClashMeta","zero_nodes":true}`
	goldenRenderMin     = `{"content":"vless://x","content_type":"text/plain"}`
	goldenConvertURIs   = `{"uris":["vless://a","trojan://b"],"target":"sing-box","options":{"include-unsupported-proxy":true,"pretty-yaml":true}}`
	goldenConvertRaw    = `{"raw":"dmxlc3M6Ly94","target":"URI","format":"plain"}`
	goldenConvertReply  = `{"content":"{}","content_type":"application/json","target":"sing-box","node_count":2}`
	goldenConvertReply0 = `{"content":"x","content_type":"text/plain","target":"URI","node_count":0}`
	// The server builds its convert request as a map (identity_link.go at
	// lattice-server 0133390), so its keys arrive sorted.
	goldenServerConvert = `{"options":{"pretty-yaml":true},"target":"ClashMeta","uris":["vless://a"]}`
)

// Verbatim copies of the plugin's wire structs at 872f51c.
type plugin872FetchResult struct {
	Raw            string          `json:"raw"`
	Userinfo       string          `json:"userinfo,omitempty"`
	SourceVersion  string          `json:"source_version,omitempty"`
	SourceManifest json.RawMessage `json:"source_manifest,omitempty"`
}

type plugin872RenderResult struct {
	Content          string            `json:"content"`
	ContentType      string            `json:"content_type"`
	NodeCount        int               `json:"node_count,omitempty"`
	DroppedNodeCount int               `json:"dropped_node_count,omitempty"`
	DroppedProtocols []string          `json:"dropped_protocols,omitempty"`
	Headers          map[string]string `json:"headers,omitempty"`
	Target           string            `json:"target,omitempty"`
	ZeroNodes        bool              `json:"zero_nodes,omitempty"`
}

type plugin872ConvertRequest struct {
	URIs    []string        `json:"uris,omitempty"`
	Raw     string          `json:"raw,omitempty"`
	Target  string          `json:"target"`
	Format  string          `json:"format,omitempty"`
	Options map[string]bool `json:"options,omitempty"`
}

type plugin872ConvertResult struct {
	Content     string `json:"content"`
	ContentType string `json:"content_type"`
	Target      string `json:"target"`
	NodeCount   int    `json:"node_count"`
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// reencode decodes golden into a fresh T and encodes it again.
func reencode[T any](t *testing.T, golden string) (T, string) {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(golden), &v); err != nil {
		t.Fatalf("decode %s: %v", golden, err)
	}
	return v, mustJSON(t, v)
}

func TestShareGoldenFromIntegrationDecodesAndEncodesUnchanged(t *testing.T) {
	for name, golden := range map[string]string{"full": goldenShareFull, "min": goldenShareMin} {
		t.Run(name, func(t *testing.T) {
			share, again := reencode[SubscriptionShare](t, golden)
			if again != golden {
				t.Fatalf("share bytes changed:\n got %s\nwant %s", again, golden)
			}
			if share.DisplayName != "" || share.Remark != "" || share.Icon != nil || share.Tags != nil ||
				share.Order != 0 || share.ArchivedAt != nil || share.Source.IdentityID != "" {
				t.Fatalf("old share decoded with new fields set: %+v", share)
			}
		})
	}
	share, _ := reencode[SubscriptionShare](t, goldenShareFull)
	if string(share.Extra["update_interval_hours"]) != "6" || len(share.Extra) != 1 {
		t.Fatalf("Extra = %v, want only update_interval_hours", share.Extra)
	}
}

func TestShareNewFieldsRoundTripOutsideExtra(t *testing.T) {
	archived := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	in := SubscriptionShare{
		ID: "share_3", SchemaVersion: 1, Slug: "fleet", Token: "t",
		Source:      ShareSource{Kind: ShareSourcePlugin, PluginID: "latticenet.sub-store", SubscriptionID: "rec_1", IdentityID: "vu_7"},
		DisplayName: "Team phones", Remark: "rotated monthly",
		Icon: &ShareIcon{URL: "https://icons.example/phone.png", Color: "#3b82f6", Fit: ShareIconFitCover},
		Tags: []string{"team", "mobile"}, Order: 3, ArchivedAt: &archived,
		Extra: map[string]json.RawMessage{"update_interval_hours": json.RawMessage(`12`)},
	}
	raw := mustJSON(t, in)
	for _, want := range []string{
		`"identity_id":"vu_7"`, `"display_name":"Team phones"`, `"remark":"rotated monthly"`,
		`"icon":{"url":"https://icons.example/phone.png","color":"#3b82f6","fit":"cover"}`,
		`"tags":["team","mobile"]`, `"order":3`, `"archived_at":"2026-10-08T12:00:00Z"`, `"update_interval_hours":12`,
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("encoded share lacks %s: %s", want, raw)
		}
	}
	var out SubscriptionShare
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Extra) != 1 {
		t.Fatalf("a new field leaked into Extra: %v", out.Extra)
	}
	if !reflect.DeepEqual(out.Source, in.Source) || out.DisplayName != in.DisplayName || !reflect.DeepEqual(out.Icon, in.Icon) ||
		!reflect.DeepEqual(out.Tags, in.Tags) || out.Order != 3 || !out.ArchivedAt.Equal(archived) {
		t.Fatalf("round trip lost a field: %+v", out)
	}
}

// Clearing a new field must stick. If the field were missing from the known
// list, the decoded value would also sit in Extra and come back on encode.
func TestShareClearedNewFieldIsNotResurrected(t *testing.T) {
	raw := `{"id":"s","schema_version":1,"slug":"x","token":"t","source":{"kind":"plugin"},"enabled":true,` +
		`"created_at":"2026-10-01T08:00:00Z","updated_at":"2026-10-01T08:00:00Z",` +
		`"display_name":"old","remark":"old","icon":{"url":"u"},"tags":["a"],"order":2,"archived_at":"2026-10-02T00:00:00Z"}`
	var share SubscriptionShare
	if err := json.Unmarshal([]byte(raw), &share); err != nil {
		t.Fatal(err)
	}
	if len(share.Extra) != 0 {
		t.Fatalf("known fields landed in Extra: %v", share.Extra)
	}
	share.DisplayName, share.Remark, share.Icon, share.Tags, share.Order, share.ArchivedAt = "", "", nil, nil, 0, nil
	out := mustJSON(t, share)
	for _, gone := range []string{"display_name", "remark", "icon", "tags", "order", "archived_at"} {
		if strings.Contains(out, `"`+gone+`"`) {
			t.Fatalf("cleared %s came back: %s", gone, out)
		}
	}
}

func TestFetchRenderConvertGoldensFromThePluginEncodeUnchanged(t *testing.T) {
	cases := []struct {
		name, golden string
		again        func() (any, string)
	}{
		{"fetch full", goldenFetchFull, func() (any, string) { v, s := reencode[FetchReply](t, goldenFetchFull); return v, s }},
		{"fetch min", goldenFetchMin, func() (any, string) { v, s := reencode[FetchReply](t, goldenFetchMin); return v, s }},
		{"render full", goldenRenderFull, func() (any, string) { v, s := reencode[RenderReply](t, goldenRenderFull); return v, s }},
		{"render min", goldenRenderMin, func() (any, string) { v, s := reencode[RenderReply](t, goldenRenderMin); return v, s }},
		{"convert uris", goldenConvertURIs, func() (any, string) { v, s := reencode[ConvertRequest](t, goldenConvertURIs); return v, s }},
		{"convert raw", goldenConvertRaw, func() (any, string) { v, s := reencode[ConvertRequest](t, goldenConvertRaw); return v, s }},
		{"convert reply", goldenConvertReply, func() (any, string) { v, s := reencode[ConvertReply](t, goldenConvertReply); return v, s }},
		{"convert reply zero", goldenConvertReply0, func() (any, string) { v, s := reencode[ConvertReply](t, goldenConvertReply0); return v, s }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, again := c.again(); again != c.golden {
				t.Fatalf("bytes changed:\n got %s\nwant %s", again, c.golden)
			}
		})
	}
}

// The SDK types and the plugin's structs encode the same values to the same
// bytes, field order included, so the plugin can switch types without a
// byte of difference on the wire.
func TestSDKTypesEncodeLikeThePluginStructs(t *testing.T) {
	manifest := json.RawMessage(`{"schema":"x"}`)
	pairs := []struct {
		name      string
		old, next any
	}{
		{"fetch", plugin872FetchResult{Raw: "r", Userinfo: "u", SourceVersion: "v", SourceManifest: manifest},
			FetchReply{Raw: "r", Userinfo: "u", SourceVersion: "v", SourceManifest: manifest}},
		{"render", plugin872RenderResult{Content: "c", ContentType: "t", NodeCount: 1, DroppedNodeCount: 2, DroppedProtocols: []string{"ssr"},
			Headers: map[string]string{"plan-name": "p"}, Target: "Surge", ZeroNodes: true},
			RenderReply{Content: "c", ContentType: "t", NodeCount: 1, DroppedNodeCount: 2, DroppedProtocols: []string{"ssr"},
				Headers: map[string]string{"plan-name": "p"}, Target: "Surge", ZeroNodes: true}},
		{"render zero", plugin872RenderResult{}, RenderReply{}},
		{"convert request", plugin872ConvertRequest{URIs: []string{"a"}, Raw: "r", Target: "QX", Format: "plain", Options: map[string]bool{"x": true}},
			ConvertRequest{URIs: []string{"a"}, Raw: "r", Target: "QX", Format: "plain", Options: map[string]bool{"x": true}}},
		{"convert request zero", plugin872ConvertRequest{}, ConvertRequest{}},
		{"convert reply", plugin872ConvertResult{Content: "c", ContentType: "t", Target: "URI", NodeCount: 4},
			ConvertReply{Content: "c", ContentType: "t", Target: "URI", NodeCount: 4}},
		{"convert reply zero", plugin872ConvertResult{}, ConvertReply{}},
	}
	for _, p := range pairs {
		t.Run(p.name, func(t *testing.T) {
			if old, next := mustJSON(t, p.old), mustJSON(t, p.next); old != next {
				t.Fatalf("encodings differ:\nplugin %s\n   sdk %s", old, next)
			}
		})
	}
}

// The plugin's strict decoding refuses unknown fields, so a convert request
// the core sends today must pass DecodeConvertRequest as it is.
func TestTodaysConvertRequestsDecodeStrictly(t *testing.T) {
	for name, golden := range map[string]string{"server map": goldenServerConvert, "uris": goldenConvertURIs, "raw": goldenConvertRaw} {
		t.Run(name, func(t *testing.T) {
			req, err := DecodeConvertRequest([]byte(golden))
			if err != nil {
				t.Fatalf("today's request refused: %v", err)
			}
			if req.Nodes != nil || req.Document != nil || req.ResponseChain != nil {
				t.Fatalf("today's request decoded with new inputs: %+v", req)
			}
		})
	}
	req, _ := DecodeConvertRequest([]byte(goldenServerConvert))
	want := ConvertRequest{URIs: []string{"vless://a"}, Target: "ClashMeta", Options: map[string]bool{"pretty-yaml": true}}
	if !reflect.DeepEqual(req, want) {
		t.Fatalf("server request decoded as %+v, want %+v", req, want)
	}
}
