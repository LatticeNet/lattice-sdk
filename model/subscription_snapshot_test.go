package model

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestSnapshotKeyIsUnambiguous(t *testing.T) {
	// Concatenating without a separator would make ("ab","c") and ("a","bc")
	// collide, which would serve one subscription's content under another's id.
	if SnapshotKey("ab", "c") == SnapshotKey("a", "bc") {
		t.Fatal("snapshot keys collide across the plugin/subscription boundary")
	}
	if got := SnapshotKey("latticenet.sub-store", "s1"); got != "latticenet.sub-store/s1" {
		t.Fatalf("SnapshotKey = %q", got)
	}
}

func TestSubscriptionSnapshotRoundTrip(t *testing.T) {
	manifest, version, err := CanonicalSubscriptionSourceManifest(validSubscriptionSourceManifest())
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1700000000, 0).UTC()
	snap := SubscriptionSnapshot{
		SchemaVersion: SubscriptionSnapshotSchemaVersion,
		PluginID:      "p", SubscriptionID: "s", Raw: "vless://example",
		Userinfo: "upload=1; download=2; total=3", FetchedAt: at,
		SourceVersion: version, SourceManifest: manifest, Stale: true,
	}
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back SubscriptionSnapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Raw != snap.Raw || back.Userinfo != snap.Userinfo || !back.FetchedAt.Equal(at) {
		t.Fatalf("round trip lost data: %+v", back)
	}
	if back.SourceVersion != snap.SourceVersion || string(back.SourceManifest) != string(snap.SourceManifest) || !back.Stale {
		t.Fatalf("round trip lost v2 provenance: %+v", back)
	}
}

func TestSubscriptionSnapshotV1MigrationMarksFailedLastGoodStale(t *testing.T) {
	for _, tc := range []struct {
		name       string
		fetchError string
		wantStale  bool
	}{
		{name: "successful", wantStale: false},
		{name: "failed last good", fetchError: "upstream unavailable", wantStale: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := json.Marshal(map[string]any{
				"schema_version": 1, "plugin_id": "p", "subscription_id": "s",
				"raw": "vless://credential", "fetched_at": "2023-11-14T22:13:20Z",
				"fetch_error": tc.fetchError,
			})
			if err != nil {
				t.Fatal(err)
			}
			var got SubscriptionSnapshot
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			if got.SchemaVersion != SubscriptionSnapshotSchemaVersion || got.Stale != tc.wantStale {
				t.Fatalf("migrated snapshot = %+v", got)
			}
			if got.SourceVersion != "" || len(got.SourceManifest) != 0 {
				t.Fatalf("v1 migration invented provenance: %+v", got)
			}
			if got.PersistedSchemaVersion() != 1 || !got.NeedsRewrite() {
				t.Fatalf("v1 rewrite authority lost: persisted=%d rewrite=%v", got.PersistedSchemaVersion(), got.NeedsRewrite())
			}
			rewritten, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var reopened SubscriptionSnapshot
			if err := json.Unmarshal(rewritten, &reopened); err != nil {
				t.Fatalf("rewritten legacy snapshot cannot reopen: %v", err)
			}
			if reopened.PersistedSchemaVersion() != 2 || reopened.NeedsRewrite() || reopened.SourceVersion != "" || len(reopened.SourceManifest) != 0 {
				t.Fatalf("rewritten legacy snapshot lost empty-provenance authority: %+v", reopened)
			}
		})
	}
}

func TestSubscriptionSnapshotV2DoesNotNeedRewriteAndClonesManifest(t *testing.T) {
	manifest, version, err := CanonicalSubscriptionSourceManifest(validSubscriptionSourceManifest())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(SubscriptionSnapshot{SchemaVersion: 2, PluginID: "p", SubscriptionID: "s", SourceVersion: version, SourceManifest: manifest})
	if err != nil {
		t.Fatal(err)
	}
	var got SubscriptionSnapshot
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.PersistedSchemaVersion() != 2 || got.NeedsRewrite() {
		t.Fatalf("v2 rewrite metadata = %d/%v", got.PersistedSchemaVersion(), got.NeedsRewrite())
	}
	clone := got.Clone()
	clone.SourceManifest[0] = 'x'
	if got.SourceManifest[0] == 'x' {
		t.Fatal("snapshot clone aliases source manifest")
	}
}

func TestSubscriptionSnapshotRejectsUnknownSchema(t *testing.T) {
	var got SubscriptionSnapshot
	err := json.Unmarshal([]byte(`{"schema_version":3,"plugin_id":"p","subscription_id":"s"}`), &got)
	if err == nil {
		t.Fatal("unknown schema version accepted")
	}
}

func TestSubscriptionSnapshotStrictDecoderRejectsInvalidVersionShapes(t *testing.T) {
	manifest, version, err := CanonicalSubscriptionSourceManifest(validSubscriptionSourceManifest())
	if err != nil {
		t.Fatal(err)
	}
	validV2, err := json.Marshal(SubscriptionSnapshot{
		SchemaVersion: 2, PluginID: "p", SubscriptionID: "s", Raw: "raw",
		SourceVersion: version, SourceManifest: manifest,
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"duplicate":                 bytes.Replace(validV2, []byte(`"plugin_id":`), []byte(`"plugin_id":"duplicate","plugin_id":`), 1),
		"unknown":                   bytes.Replace(validV2, []byte(`"plugin_id":`), []byte(`"unknown":true,"plugin_id":`), 1),
		"trailing":                  append(append([]byte(nil), validV2...), []byte(` {}`)...),
		"v1 with source version":    []byte(`{"schema_version":1,"plugin_id":"p","subscription_id":"s","raw":"raw","source_version":"sv1:abc","fetched_at":"0001-01-01T00:00:00Z"}`),
		"v2 missing source version": bytes.Replace(validV2, []byte(`"source_version":"`+version+`",`), nil, 1),
		"v2 missing manifest":       bytes.Replace(validV2, append([]byte(`"source_manifest":`), manifest...), []byte(`"source_manifest":null`), 1),
		"v2 mismatched hash":        bytes.Replace(validV2, []byte(version), []byte("sv1:"+strings.Repeat("0", 64)), 1),
	} {
		t.Run(name, func(t *testing.T) {
			var got SubscriptionSnapshot
			if err := json.Unmarshal(raw, &got); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
		})
	}
}

func TestSubscriptionSnapshotRejectsRawAndResponseBounds(t *testing.T) {
	manifest, version, err := CanonicalSubscriptionSourceManifest(validSubscriptionSourceManifest())
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"raw":      mustMarshalSnapshot(t, SubscriptionSnapshot{SchemaVersion: 2, PluginID: "p", SubscriptionID: "s", Raw: strings.Repeat("r", MaxSubscriptionRawBytes+1), SourceVersion: version, SourceManifest: manifest}),
		"response": append([]byte(`{"schema_version":2,"plugin_id":"p","subscription_id":"s","raw":"`), bytes.Repeat([]byte{'r'}, MaxSubscriptionResponseBytes)...),
	} {
		t.Run(name, func(t *testing.T) {
			var got SubscriptionSnapshot
			if err := json.Unmarshal(raw, &got); err == nil {
				t.Fatal("oversized snapshot accepted")
			}
		})
	}
}

func mustMarshalSnapshot(t *testing.T, snapshot SubscriptionSnapshot) []byte {
	t.Helper()
	raw, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
