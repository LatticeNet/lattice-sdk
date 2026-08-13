package model

import (
	"bytes"
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
	if len(raw) == 0 || len(raw) > MaxSubscriptionResponseBytes {
		return fmt.Errorf("invalid subscription snapshot size")
	}
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return err
	}
	type wire struct {
		SchemaVersion  int             `json:"schema_version"`
		PluginID       string          `json:"plugin_id"`
		SubscriptionID string          `json:"subscription_id"`
		Raw            string          `json:"raw"`
		SourceVersion  string          `json:"source_version"`
		SourceManifest json.RawMessage `json:"source_manifest"`
		Userinfo       string          `json:"userinfo"`
		FetchedAt      time.Time       `json:"fetched_at"`
		FetchError     string          `json:"fetch_error"`
		LastAttemptAt  time.Time       `json:"last_attempt_at"`
		Stale          bool            `json:"stale"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var decoded wire
	if err := decoder.Decode(&decoded); err != nil {
		return err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	if len(decoded.Raw) > MaxSubscriptionRawBytes {
		return fmt.Errorf("subscription snapshot raw content exceeds byte limit")
	}
	persistedVersion := decoded.SchemaVersion
	switch persistedVersion {
	case 1:
		for _, v2Field := range []string{"source_version", "source_manifest", "stale"} {
			if _, exists := fields[v2Field]; exists {
				return fmt.Errorf("subscription snapshot v1 contains v2-only field %q", v2Field)
			}
		}
		if len(decoded.SourceManifest) != 0 || decoded.SourceVersion != "" {
			return fmt.Errorf("subscription snapshot v1 contains provenance")
		}
		decoded.SchemaVersion = SubscriptionSnapshotSchemaVersion
		decoded.Stale = decoded.FetchError != ""
	case SubscriptionSnapshotSchemaVersion:
		if decoded.SourceVersion == "" || len(decoded.SourceManifest) == 0 || bytes.Equal(decoded.SourceManifest, []byte("null")) {
			return fmt.Errorf("subscription snapshot v2 requires paired provenance")
		}
		if _, err := DecodeSubscriptionSourceManifest(decoded.SourceManifest); err != nil {
			return fmt.Errorf("invalid subscription snapshot source manifest: %w", err)
		}
		if want := SubscriptionSourceVersion(decoded.SourceManifest); decoded.SourceVersion != want {
			return fmt.Errorf("subscription snapshot source version mismatch")
		}
	default:
		return fmt.Errorf("unsupported subscription snapshot schema version %d", decoded.SchemaVersion)
	}
	*s = SubscriptionSnapshot{
		SchemaVersion: decoded.SchemaVersion, PluginID: decoded.PluginID, SubscriptionID: decoded.SubscriptionID,
		Raw: decoded.Raw, SourceVersion: decoded.SourceVersion, SourceManifest: append(json.RawMessage(nil), decoded.SourceManifest...),
		Userinfo: decoded.Userinfo, FetchedAt: decoded.FetchedAt, FetchError: decoded.FetchError,
		LastAttemptAt: decoded.LastAttemptAt, Stale: decoded.Stale,
	}
	s.persistedSchemaVersion = persistedVersion
	s.needsRewrite = persistedVersion != SubscriptionSnapshotSchemaVersion
	return nil
}

func (s SubscriptionSnapshot) PersistedSchemaVersion() int { return s.persistedSchemaVersion }

func (s SubscriptionSnapshot) NeedsRewrite() bool { return s.needsRewrite }

func (s SubscriptionSnapshot) Clone() SubscriptionSnapshot {
	out := s
	if s.SourceManifest != nil {
		out.SourceManifest = append(make(json.RawMessage, 0, len(s.SourceManifest)), s.SourceManifest...)
	}
	return out
}

// SnapshotKey is the storage key for one subscription's snapshot.
func SnapshotKey(pluginID, subscriptionID string) string {
	return pluginID + "/" + subscriptionID
}
