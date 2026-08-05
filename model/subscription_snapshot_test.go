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
}
