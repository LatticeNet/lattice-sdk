package model

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// Unknown fields must survive a read-modify-write cycle. Without this, a server
// that reads a record written by a newer version silently destroys the fields it
// did not recognize, and the loss is invisible until someone looks for a setting
// that is simply gone.
func TestSubscriptionShareRoundTripPreservesUnknownFields(t *testing.T) {
	raw := []byte(`{"id":"s1","schema_version":1,"slug":"team","token":"t","source":{"kind":"plugin","plugin_id":"p","subscription_id":"sub"},"future_field":"keep me"}`)

	var share SubscriptionShare
	if err := json.Unmarshal(raw, &share); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	share.Slug = "renamed"

	out, err := json.Marshal(share)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if got["future_field"] != "keep me" {
		t.Fatalf("unknown field dropped: %v", got)
	}
	if got["slug"] != "renamed" {
		t.Fatalf("edit lost: %v", got)
	}
}

func TestSubscriptionShareSourceKinds(t *testing.T) {
	if ShareSourceCoreProxyUser != "core.proxy_user" {
		t.Fatalf("core source kind = %q", ShareSourceCoreProxyUser)
	}
	if ShareSourcePlugin != "plugin" {
		t.Fatalf("plugin source kind = %q", ShareSourcePlugin)
	}
}

// A known field must never be shadowed by a stale Extra entry carrying the same
// name: the edit the caller just made has to win.
func TestSubscriptionShareExtraNeverShadowsAKnownField(t *testing.T) {
	share := SubscriptionShare{
		ID:    "s1",
		Slug:  "real",
		Extra: map[string]json.RawMessage{"slug": json.RawMessage(`"stale"`)},
	}

	out, err := json.Marshal(share)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["slug"] != "real" {
		t.Fatalf("Extra shadowed a known field: slug = %v", got["slug"])
	}
}

func TestShareIconValidate(t *testing.T) {
	png := "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte("\x89PNG\r\n\x1a\n"))
	accepted := []ShareIcon{
		{URL: "https://icons.example/phone.png"},
		{URL: "https://icons.example/phone.png", Color: "#3b82f6", Fit: ShareIconFitCover},
		{URL: png, Fit: ShareIconFitContain},
		{URL: "data:image/webp;base64,UklGRg=="},
	}
	for _, icon := range accepted {
		if err := icon.Validate(); err != nil {
			t.Fatalf("%+v refused: %v", icon, err)
		}
	}
	refused := map[string]ShareIcon{
		"empty url":            {},
		"javascript url":       {URL: "javascript:alert(1)"},
		"http url":             {URL: "http://icons.example/phone.png"},
		"private address":      {URL: "https://10.0.0.1/phone.png"},
		"local name":           {URL: "https://nas.local/phone.png"},
		"userinfo":             {URL: "https://user@icons.example/phone.png"},
		"svg data url":         {URL: "data:image/svg+xml;base64,PHN2Zy8+"},
		"html data url":        {URL: "data:text/html;base64,PGgxPg=="},
		"data url, no base64":  {URL: "data:image/png,rawbytes"},
		"data url, bad base64": {URL: "data:image/png;base64,!!!!"},
		"data url, no payload": {URL: "data:image/png;base64,"},
		"uppercase colour":     {URL: png, Color: "#3B82F6"},
		"short colour":         {URL: png, Color: "#fff"},
		"named colour":         {URL: png, Color: "red"},
		"unknown fit":          {URL: png, Fit: "fill"},
	}
	for name, icon := range refused {
		if err := icon.Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}

	// Standard base64 comes in four-byte groups, so the largest valid data
	// URL sits two bytes under the bound. The bound itself is where a size
	// refusal starts.
	prefix := "data:image/png;base64,"
	dataURL := func(n int) string { return prefix + strings.Repeat("A", n-len(prefix)) }
	largest := dataURL(MaxShareIconDataURLBytes - (MaxShareIconDataURLBytes-len(prefix))%4)
	if err := (ShareIcon{URL: largest}).Validate(); err != nil {
		t.Fatalf("data url of %d bytes refused: %v", len(largest), err)
	}
	if err := (ShareIcon{URL: dataURL(MaxShareIconDataURLBytes)}).Validate(); err == nil || strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("data url at the bound: err = %v, want a base64 refusal and no size refusal", err)
	}
	if err := (ShareIcon{URL: dataURL(MaxShareIconDataURLBytes + 1)}).Validate(); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("data url one byte over the bound: err = %v, want a size refusal", err)
	}
}

func validOperatorShare() SubscriptionShare {
	return SubscriptionShare{
		ID: "share_3", SchemaVersion: 1, Slug: "fleet", Token: "t",
		Source:      ShareSource{Kind: ShareSourcePlugin, PluginID: "latticenet.sub-store", SubscriptionID: "rec_1", IdentityID: "vu_7"},
		DisplayName: "Team phones", Remark: "rotated monthly\n\tsee the runbook",
		Icon: &ShareIcon{URL: "https://icons.example/phone.png", Color: "#3b82f6", Fit: ShareIconFitCover},
		Tags: []string{"team", "mobile"}, Order: 3,
	}
}

func TestShareValidateOperatorFields(t *testing.T) {
	if err := validOperatorShare().ValidateOperatorFields(); err != nil {
		t.Fatalf("valid share refused: %v", err)
	}
	if err := (SubscriptionShare{Source: ShareSource{Kind: ShareSourceCoreProxyUser, ProxyUserID: "pu_1"}}).ValidateOperatorFields(); err != nil {
		t.Fatalf("share with no operator fields refused: %v", err)
	}
	tags := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = "t" + strings.Repeat("x", i)
		}
		return out
	}
	beyondOrder := int64(MaxShareOrder)
	beyondOrder++
	cases := []struct {
		name     string
		edit     func(*SubscriptionShare)
		accepted bool
	}{
		{"display name at bound", func(s *SubscriptionShare) { s.DisplayName = strings.Repeat("n", MaxShareDisplayNameBytes) }, true},
		{"display name over bound", func(s *SubscriptionShare) { s.DisplayName = strings.Repeat("n", MaxShareDisplayNameBytes+1) }, false},
		{"display name with newline", func(s *SubscriptionShare) { s.DisplayName = "Team\nphones" }, false},
		{"remark at bound", func(s *SubscriptionShare) { s.Remark = strings.Repeat("r", MaxShareRemarkBytes) }, true},
		{"remark over bound", func(s *SubscriptionShare) { s.Remark = strings.Repeat("r", MaxShareRemarkBytes+1) }, false},
		{"remark with carriage return", func(s *SubscriptionShare) { s.Remark = "a\r\nb" }, false},
		{"remark with nul", func(s *SubscriptionShare) { s.Remark = "a\x00b" }, false},
		{"tags at bound", func(s *SubscriptionShare) { s.Tags = tags(MaxShareTags) }, true},
		{"tags over bound", func(s *SubscriptionShare) { s.Tags = tags(MaxShareTags + 1) }, false},
		{"tag at bound", func(s *SubscriptionShare) { s.Tags = []string{strings.Repeat("t", MaxShareTagBytes)} }, true},
		{"tag over bound", func(s *SubscriptionShare) { s.Tags = []string{strings.Repeat("t", MaxShareTagBytes+1)} }, false},
		{"empty tag", func(s *SubscriptionShare) { s.Tags = []string{""} }, false},
		{"untrimmed tag", func(s *SubscriptionShare) { s.Tags = []string{" team"} }, false},
		{"tag with tab", func(s *SubscriptionShare) { s.Tags = []string{"te\tam"} }, false},
		{"duplicate tag", func(s *SubscriptionShare) { s.Tags = []string{"team", "team"} }, false},
		{"order zero", func(s *SubscriptionShare) { s.Order = 0 }, true},
		{"order at bound", func(s *SubscriptionShare) { s.Order = MaxShareOrder }, true},
		{"order over bound", func(s *SubscriptionShare) { s.Order = int(beyondOrder) }, false},
		{"negative order", func(s *SubscriptionShare) { s.Order = -1 }, false},
		{"bad icon", func(s *SubscriptionShare) { s.Icon = &ShareIcon{URL: "javascript:alert(1)"} }, false},
		{"plugin source without identity", func(s *SubscriptionShare) { s.Source.IdentityID = "" }, true},
		{"identity on a core source", func(s *SubscriptionShare) {
			s.Source = ShareSource{Kind: ShareSourceCoreProxyUser, ProxyUserID: "pu_1", IdentityID: "vu_7"}
		}, false},
		{"identity with no kind", func(s *SubscriptionShare) { s.Source.Kind = "" }, false},
		{"identity with a newline", func(s *SubscriptionShare) { s.Source.IdentityID = "vu_7\n" }, false},
	}
	for _, c := range cases {
		share := validOperatorShare()
		c.edit(&share)
		if err := share.ValidateOperatorFields(); (err == nil) != c.accepted {
			t.Fatalf("%s: ValidateOperatorFields() = %v, want accepted=%v", c.name, err, c.accepted)
		}
	}
}
