package model

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
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
	// IdentityID names the identity a plugin share serves when its record is
	// fleet-bound (design 28): the record selects lines and names nobody, and
	// the core binds this identity's credentials into the plugin's plan before
	// convert produces the document. Empty for every other share. It belongs
	// to the plugin kind only.
	//
	// ShareSource keeps no unknown fields, so a server built before this
	// field drops it when it rewrites the share.
	IdentityID string `json:"identity_id,omitempty"`
}

// Values of ShareIcon.Fit.
const (
	// ShareIconFitContain scales the whole image inside the icon box.
	ShareIconFitContain = "contain"
	// ShareIconFitCover fills the icon box and crops what overflows.
	ShareIconFitCover = "cover"
)

// Bounds of the operator fields a share carries.
const (
	// MaxShareDisplayNameBytes bounds SubscriptionShare.DisplayName.
	MaxShareDisplayNameBytes = 256
	// MaxShareRemarkBytes bounds SubscriptionShare.Remark.
	MaxShareRemarkBytes = 4 << 10
	// MaxShareTags bounds how many tags a share carries, and MaxShareTagBytes
	// bounds each tag.
	MaxShareTags     = 32
	MaxShareTagBytes = 64
	// MaxShareOrder bounds SubscriptionShare.Order, which is never negative.
	// It is far inside the integers a browser holds exactly.
	MaxShareOrder = 1<<31 - 1
	// MaxShareIconDataURLBytes bounds an icon given as a data URL. An https
	// icon URL is bounded like a provider web page URL, at
	// MaxSubscriptionResponseHeaderBytes.
	MaxShareIconDataURLBytes = 64 << 10
)

// shareIconColor is a lowercase CSS hex colour, the form a browser's colour
// input produces.
var shareIconColor = regexp.MustCompile(`^#[0-9a-f]{6}$`)

// shareIconDataTypes are the image types an icon data URL may carry. SVG is
// left out because an SVG document can carry script.
var shareIconDataTypes = map[string]bool{"image/png": true, "image/jpeg": true, "image/gif": true, "image/webp": true}

// ShareIcon is how the console draws a share: an image, an optional tint and
// how the image fits its box. The core stores it and never fetches URL.
type ShareIcon struct {
	// URL is the image the console shows for the share: an https URL that
	// passes the rule of a provider web page URL, or a base64 data URL of a
	// PNG, JPEG, GIF or WebP image.
	URL string `json:"url"`
	// Color tints a monochrome image, as a lowercase CSS hex colour such as
	// "#3b82f6". Empty keeps the image's own colours.
	Color string `json:"color,omitempty"`
	// Fit is ShareIconFitContain or ShareIconFitCover. Empty means contain.
	Fit string `json:"fit,omitempty"`
}

// Validate checks an icon's URL, colour and fit. An https URL must pass
// ValidateSubscriptionWebPageURL's rule, so the console never loads an image
// from a private address, a local name or a URL with userinfo. A data URL is
// at most MaxShareIconDataURLBytes, names an allowed image type and carries
// standard base64.
func (i ShareIcon) Validate() error {
	if body, ok := strings.CutPrefix(i.URL, "data:"); ok {
		if len(i.URL) > MaxShareIconDataURLBytes {
			return fmt.Errorf("icon data url exceeds %d bytes", MaxShareIconDataURLBytes)
		}
		mediaType, payload, ok := strings.Cut(body, ";base64,")
		if !ok || !shareIconDataTypes[mediaType] || payload == "" {
			return errors.New("icon data url must be a base64 png, jpeg, gif or webp image")
		}
		if _, err := base64.StdEncoding.DecodeString(payload); err != nil {
			return errors.New("icon data url does not carry standard base64")
		}
	} else if err := validatePublicHTTPSURL("icon url", i.URL); err != nil {
		return err
	}
	if i.Color != "" && !shareIconColor.MatchString(i.Color) {
		return errors.New("icon color must be a lowercase #rrggbb colour")
	}
	switch i.Fit {
	case "", ShareIconFitContain, ShareIconFitCover:
	default:
		return fmt.Errorf("icon fit %q is not contain or cover", i.Fit)
	}
	return nil
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

	// DisplayName is the operator's name for the share. Unlike Slug it never
	// reaches a URL.
	DisplayName string `json:"display_name,omitempty"`
	// Remark is the operator's free-form note on the share.
	Remark string `json:"remark,omitempty"`
	// Icon is how the console draws the share. Nil draws the default.
	Icon *ShareIcon `json:"icon,omitempty"`
	// Tags group and filter shares in the console.
	Tags []string `json:"tags,omitempty"`
	// Order is the share's position in the operator's manual order. Shares
	// with equal Order sort by CreatedAt.
	Order int `json:"order,omitempty"`
	// ArchivedAt is when the share moved to the recycle bin. An archived
	// share is not served; restoring it clears ArchivedAt and keeps the same
	// token, and purging deletes the share.
	ArchivedAt *time.Time `json:"archived_at,omitempty"`

	// Extra holds fields written by a newer schema version. It exists so a
	// rollback cannot silently delete data this version cannot interpret.
	Extra map[string]json.RawMessage `json:"-"`
}

// ValidateOperatorFields checks the fields an operator sets on a share
// beside its source and slug: the display name, remark, icon, tags and
// order, and that only a plugin source names an identity. The core calls it
// when a share is created or edited. Decoding never calls it, so a stored
// share stays readable whatever these fields hold. The id, slug, token and
// the rest of the source are the core's to check, as before.
func (s SubscriptionShare) ValidateOperatorFields() error {
	if len(s.DisplayName) > MaxShareDisplayNameBytes || strings.ContainsFunc(s.DisplayName, unicode.IsControl) {
		return fmt.Errorf("share display_name must be at most %d bytes with no control character", MaxShareDisplayNameBytes)
	}
	if len(s.Remark) > MaxShareRemarkBytes || strings.ContainsFunc(s.Remark, func(r rune) bool {
		return unicode.IsControl(r) && r != '\n' && r != '\t'
	}) {
		return fmt.Errorf("share remark must be at most %d bytes with no control character but newline and tab", MaxShareRemarkBytes)
	}
	if s.Icon != nil {
		if err := s.Icon.Validate(); err != nil {
			return fmt.Errorf("share icon: %w", err)
		}
	}
	if len(s.Tags) > MaxShareTags {
		return fmt.Errorf("share has more than %d tags", MaxShareTags)
	}
	seen := make(map[string]struct{}, len(s.Tags))
	for _, tag := range s.Tags {
		if tag == "" || tag != strings.TrimSpace(tag) || len(tag) > MaxShareTagBytes || strings.ContainsFunc(tag, unicode.IsControl) {
			return fmt.Errorf("share tag %q must be 1 to %d trimmed bytes with no control character", tag, MaxShareTagBytes)
		}
		if _, dup := seen[tag]; dup {
			return fmt.Errorf("share carries tag %q twice", tag)
		}
		seen[tag] = struct{}{}
	}
	if s.Order < 0 || s.Order > MaxShareOrder {
		return fmt.Errorf("share order must be 0 to %d", MaxShareOrder)
	}
	if s.Source.IdentityID != "" {
		if s.Source.Kind != ShareSourcePlugin {
			return errors.New("only a plugin source names an identity")
		}
		if !validCatalogueID(s.Source.IdentityID) {
			return errors.New("share source identity_id is invalid")
		}
	}
	return nil
}

// subscriptionShareKnownFields is the set Extra must never contain. It is derived
// from the struct tags above and kept beside them so adding a field without
// updating this list is a visible omission rather than a silent shadowing bug.
var subscriptionShareKnownFields = []string{
	"id", "schema_version", "slug", "token", "source",
	"default_format", "enabled", "created_at", "updated_at",
	"rotated_at", "expires_at",
	"display_name", "remark", "icon", "tags", "order", "archived_at",
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
