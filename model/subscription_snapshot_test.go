package model

import (
	"encoding/json"
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
	at := time.Unix(1700000000, 0).UTC()
	snap := SubscriptionSnapshot{
		SchemaVersion: SubscriptionSnapshotSchemaVersion,
		PluginID:      "p", SubscriptionID: "s", Raw: "vless://example",
		Userinfo: "upload=1; download=2; total=3", FetchedAt: at,
		SourceVersion: "sv1:abc", SourceManifest: json.RawMessage(`{"schema":"manifest.v1"}`), Stale: true,
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
		})
	}
}

func TestSubscriptionSnapshotRejectsUnknownSchema(t *testing.T) {
	var got SubscriptionSnapshot
	err := json.Unmarshal([]byte(`{"schema_version":3,"plugin_id":"p","subscription_id":"s"}`), &got)
	if err == nil {
		t.Fatal("unknown schema version accepted")
	}
}
