package model

import "time"

// SubscriptionSnapshotSchemaVersion is the current record shape.
const SubscriptionSnapshotSchemaVersion = 1

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
}

// SnapshotKey is the storage key for one subscription's snapshot.
func SnapshotKey(pluginID, subscriptionID string) string {
	return pluginID + "/" + subscriptionID
}
