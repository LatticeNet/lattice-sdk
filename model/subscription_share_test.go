package model

import (
	"encoding/json"
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
