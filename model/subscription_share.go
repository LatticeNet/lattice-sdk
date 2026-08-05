package model

import (
	"encoding/json"
	"time"
)

// SubscriptionShareSchemaVersion is the current record shape. Readers must
// tolerate a higher value rather than refuse the record: migrations are additive
// only, so a newer record is readable, and Extra preserves what this version does
// not name.
const SubscriptionShareSchemaVersion = 1

const (
	// ShareSourceCoreProxyUser renders from a proxy user the core already owns.
	ShareSourceCoreProxyUser = "core.proxy_user"
	// ShareSourcePlugin asks a plugin to produce the body. The plugin never sees
	// the share's token and never owns the route.
	ShareSourcePlugin = "plugin"
)

// ShareSource names where a share's content comes from. Exactly one kind is set,
// and the fields that do not belong to that kind stay empty.
type ShareSource struct {
	Kind           string `json:"kind"`
	PluginID       string `json:"plugin_id,omitempty"`
	SubscriptionID string `json:"subscription_id,omitempty"`
	ProxyUserID    string `json:"proxy_user_id,omitempty"`
}

// SubscriptionShare is one publicly reachable subscription URL. Token is the only
// secret; Slug is a label that reaches reverse-proxy logs and client screenshots
// and is never relied on for authorization.
type SubscriptionShare struct {
	ID            string      `json:"id"`
	SchemaVersion int         `json:"schema_version"`
	Slug          string      `json:"slug"`
	Token         string      `json:"token"`
	Source        ShareSource `json:"source"`
	DefaultFormat string      `json:"default_format,omitempty"`
	Enabled       bool        `json:"enabled"`
	CreatedAt     time.Time   `json:"created_at"`
	UpdatedAt     time.Time   `json:"updated_at"`
	RotatedAt     *time.Time  `json:"rotated_at,omitempty"`
	ExpiresAt     *time.Time  `json:"expires_at,omitempty"`

	// Extra holds fields written by a newer schema version. It exists so a
	// rollback cannot silently delete data this version cannot interpret.
	Extra map[string]json.RawMessage `json:"-"`
}

// subscriptionShareKnownFields is the set Extra must never contain. It is derived
// from the struct tags above and kept beside them so adding a field without
// updating this list is a visible omission rather than a silent shadowing bug.
var subscriptionShareKnownFields = []string{
	"id", "schema_version", "slug", "token", "source",
	"default_format", "enabled", "created_at", "updated_at",
	"rotated_at", "expires_at",
}

type subscriptionShareAlias SubscriptionShare

// UnmarshalJSON decodes the named fields and keeps everything else in Extra.
func (s *SubscriptionShare) UnmarshalJSON(data []byte) error {
	var alias subscriptionShareAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*s = SubscriptionShare(alias)

	var all map[string]json.RawMessage
	if err := json.Unmarshal(data, &all); err != nil {
		return err
	}
	for _, known := range subscriptionShareKnownFields {
		delete(all, known)
	}
	if len(all) > 0 {
		s.Extra = all
	}
	return nil
}

// MarshalJSON re-emits the unknown fields alongside the named ones. A known field
// always wins over a same-named Extra entry: the caller's edit must not be
// shadowed by whatever an older decode happened to stash.
func (s SubscriptionShare) MarshalJSON() ([]byte, error) {
	base, err := json.Marshal(subscriptionShareAlias(s))
	if err != nil {
		return nil, err
	}
	if len(s.Extra) == 0 {
		return base, nil
	}
	var merged map[string]json.RawMessage
	if err := json.Unmarshal(base, &merged); err != nil {
		return nil, err
	}
	for k, v := range s.Extra {
		if _, taken := merged[k]; taken {
			continue
		}
		if isSubscriptionShareKnownField(k) {
			continue
		}
		merged[k] = v
	}
	return json.Marshal(merged)
}

func isSubscriptionShareKnownField(name string) bool {
	for _, known := range subscriptionShareKnownFields {
		if known == name {
			return true
		}
	}
	return false
}
