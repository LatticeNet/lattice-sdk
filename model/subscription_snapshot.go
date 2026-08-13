package model

import (
	"encoding/json"
	"fmt"
	"time"
)

// SubscriptionSnapshotSchemaVersion is the current record shape.
const SubscriptionSnapshotSchemaVersion = 2

// SubscriptionSnapshot is the last content a plugin successfully fetched for one
// subscription, held by the CORE.
//
// The core owns it because a plugin has nowhere durable to keep it: it cannot
// reach bolt, and its runtime working directory is deleted when the runner stops
// it. Raw is therefore an opaque blob from the core's point of view - it is
// stored, handed back on the next render, and never interpreted.
//
// This record is what keeps clients served when a provider goes down or rotates
// its URL, so losing it means subscriptions go dark. It is durable, not a cache.
type SubscriptionSnapshot struct {
	SchemaVersion int `json:"schema_version"`
	// PluginID and SubscriptionID together identify what this is a snapshot of.
	PluginID       string `json:"plugin_id"`
	SubscriptionID string `json:"subscription_id"`
	// Raw is the provider's response body exactly as the plugin received it.
	Raw string `json:"raw"`
	// SourceVersion identifies the exact secret-free source state used to render
	// Raw. SourceManifest is its canonical, map-free provenance document. Neither
	// field may contain credentials or rendered subscription URIs.
	SourceVersion  string          `json:"source_version,omitempty"`
	SourceManifest json.RawMessage `json:"source_manifest,omitempty"`
	// Userinfo is the provider's Subscription-Userinfo header, passed through to
	// the client so its traffic display stays truthful. Empty when the provider
	// sent none.
	Userinfo  string    `json:"userinfo,omitempty"`
	FetchedAt time.Time `json:"fetched_at"`
	// FetchError records why the most recent refresh failed while this snapshot
	// stayed in service. A snapshot with a non-empty FetchError is still served -
	// that is the point - but the operator needs to see that it is stale.
	FetchError    string    `json:"fetch_error,omitempty"`
	LastAttemptAt time.Time `json:"last_attempt_at,omitempty"`
	// Stale is explicit in v2. It is independent of FetchError so public serving
	// code never has to infer whether preserved last-good content is current.
	Stale bool `json:"stale"`

	persistedSchemaVersion int
	needsRewrite           bool
}

// UnmarshalJSON performs the only supported in-memory schema migration. The
// durable store remains responsible for staging and atomically rewriting v1
// records after every record has decrypted and validated.
func (s *SubscriptionSnapshot) UnmarshalJSON(raw []byte) error {
	type wire SubscriptionSnapshot
	var decoded wire
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	persistedVersion := decoded.SchemaVersion
	switch persistedVersion {
	case 1:
		decoded.SchemaVersion = SubscriptionSnapshotSchemaVersion
		decoded.Stale = decoded.FetchError != ""
	case SubscriptionSnapshotSchemaVersion:
	default:
		return fmt.Errorf("unsupported subscription snapshot schema version %d", decoded.SchemaVersion)
	}
	*s = SubscriptionSnapshot(decoded)
	s.persistedSchemaVersion = persistedVersion
	s.needsRewrite = persistedVersion != SubscriptionSnapshotSchemaVersion
	return nil
}

func (s SubscriptionSnapshot) PersistedSchemaVersion() int { return s.persistedSchemaVersion }

func (s SubscriptionSnapshot) NeedsRewrite() bool { return s.needsRewrite }

func (s SubscriptionSnapshot) Clone() SubscriptionSnapshot {
	out := s
	out.SourceManifest = append(json.RawMessage(nil), s.SourceManifest...)
	return out
}

// SnapshotKey is the storage key for one subscription's snapshot.
func SnapshotKey(pluginID, subscriptionID string) string {
	return pluginID + "/" + subscriptionID
}
