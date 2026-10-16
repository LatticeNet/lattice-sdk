package model

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/LatticeNet/lattice-sdk/strictjson"
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
	// The document bound is MaxSubscriptionSnapshotBytes, not the response
	// bound: a Raw at MaxSubscriptionRawBytes, escaped or sealed, is larger
	// than the response bound once it sits inside the record.
	if len(raw) == 0 {
		return fmt.Errorf("invalid subscription snapshot size")
	}
	if len(raw) > MaxSubscriptionSnapshotBytes {
		return fmt.Errorf("subscription snapshot encodes to %d bytes, over the %d-byte bound that a render request can carry", len(raw), MaxSubscriptionSnapshotBytes)
	}
	decoded, fields, fast := decodeSnapshotWireFast(raw)
	if !fast {
		if err := rejectDuplicateJSONFields(raw); err != nil {
			return err
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.DisallowUnknownFields()
		decoded = snapshotWire{}
		if err := decoder.Decode(&decoded); err != nil {
			return err
		}
		if err := requireJSONEOF(decoder); err != nil {
			return err
		}
		fields = nil
		if err := json.Unmarshal(raw, &fields); err != nil {
			return err
		}
	}
	if len(decoded.Raw) > MaxSubscriptionRawBytes && !strings.HasPrefix(decoded.Raw, "lat$") {
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
		_, sourceVersionPresent := fields["source_version"]
		_, sourceManifestPresent := fields["source_manifest"]
		if sourceVersionPresent != sourceManifestPresent {
			return fmt.Errorf("subscription snapshot v2 requires paired provenance fields")
		}
		if !sourceVersionPresent {
			break
		}
		if decoded.SourceVersion == "" || len(decoded.SourceManifest) == 0 || bytes.Equal(decoded.SourceManifest, []byte("null")) {
			return fmt.Errorf("subscription snapshot v2 provenance fields must be nonempty")
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

// snapshotWire is a snapshot as it is encoded.
type snapshotWire struct {
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

// decodeSnapshotWireFast is UnmarshalJSON's strict decode for the plain
// case: a snapshot strictjson reads in one pass whose members are named
// exactly as snapshotWire's, decoded member by member, with the member map
// the checks below read built from the same pass. A snapshot carries a raw
// of up to several MiB, which the strict decode and the member map each
// scanned again. ok is false for anything else, and the caller runs the
// strict decode, which decides and words every error.
func decodeSnapshotWireFast(raw []byte) (snapshotWire, map[string]json.RawMessage, bool) {
	members, ok := strictjson.Fields(raw)
	if !ok {
		return snapshotWire{}, nil, false
	}
	var w snapshotWire
	fields := make(map[string]json.RawMessage, len(members))
	for _, f := range members {
		var target any
		switch f.Key {
		case "schema_version":
			target = &w.SchemaVersion
		case "plugin_id":
			target = &w.PluginID
		case "subscription_id":
			target = &w.SubscriptionID
		case "raw":
			target = &w.Raw
		case "source_version":
			target = &w.SourceVersion
		case "source_manifest":
			w.SourceManifest = append(json.RawMessage(nil), f.Value...)
		case "userinfo":
			target = &w.Userinfo
		case "fetched_at":
			target = &w.FetchedAt
		case "fetch_error":
			target = &w.FetchError
		case "last_attempt_at":
			target = &w.LastAttemptAt
		case "stale":
			target = &w.Stale
		default:
			return snapshotWire{}, nil, false
		}
		if str, isString := target.(*string); isString {
			if !strictjson.StringInto(f.Value, str) {
				return snapshotWire{}, nil, false
			}
		} else if target != nil && json.Unmarshal(f.Value, target) != nil {
			return snapshotWire{}, nil, false
		}
		fields[f.Key] = f.Value
	}
	return w, fields, true
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
