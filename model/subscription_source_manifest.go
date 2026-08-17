package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"unicode"
)

const (
	SubscriptionSourceManifestSchemaV1 = "lattice.subscription-source-manifest.v1"
	SubscriptionSourceRendererV1       = "vpn-core-graph-v1"
	MaxSubscriptionSourceRoots         = 2_048
	MaxSubscriptionSourceVisits        = 10_000
	MaxSubscriptionURIBytes            = 4 << 10
	MaxSubscriptionSourceManifestBytes = 1 << 20
	MaxSubscriptionRawBytes            = 1 << 20
	MaxSubscriptionResponseBytes       = 4 << 20
)

type SubscriptionSourceManifestV1 struct {
	Schema     string                             `json:"schema"`
	Renderer   string                             `json:"renderer"`
	Identity   SubscriptionSourceManifestIdentity `json:"identity"`
	EntryRoots []string                           `json:"entry_roots"`
	Entries    []SubscriptionSourceManifestEntry  `json:"entries"`
}

type SubscriptionSourceManifestIdentity struct {
	ID         string `json:"id"`
	Generation uint64 `json:"generation"`
}

type SubscriptionSourceManifestEntry struct {
	Root     string                             `json:"root"`
	Endpoint SubscriptionSourceManifestEndpoint `json:"endpoint"`
	Path     []SubscriptionSourceManifestEdge   `json:"path"`
	Terminal SubscriptionSourceManifestTerminal `json:"terminal"`
}

type SubscriptionSourceManifestEndpoint struct {
	LineUUID    string   `json:"line_uuid"`
	NodeID      string   `json:"node_id"`
	Label       string   `json:"label"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	SNI         string   `json:"sni"`
	Fingerprint string   `json:"fingerprint"`
	ALPN        []string `json:"alpn"`
	PublicKey   string   `json:"public_key"`
	ShortID     string   `json:"short_id"`
	Flow        string   `json:"flow"`
}

type SubscriptionSourceManifestEdge struct {
	Source              string `json:"source"`
	Target              string `json:"target"`
	Generation          uint64 `json:"generation"`
	ObservationRevision uint64 `json:"observation_revision"`
	Status              string `json:"status"`
}

type SubscriptionSourceManifestTerminal struct {
	LineUUID            string `json:"line_uuid"`
	Generation          uint64 `json:"generation"`
	ObservationRevision uint64 `json:"observation_revision"`
	Status              string `json:"status"`
}

var subscriptionSourceUUIDv4 = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func CanonicalSubscriptionSourceManifest(manifest SubscriptionSourceManifestV1) ([]byte, string, error) {
	manifest = manifest.Clone()
	if err := manifest.Validate(); err != nil {
		return nil, "", err
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		return nil, "", err
	}
	if len(raw) > MaxSubscriptionSourceManifestBytes {
		return nil, "", errors.New("subscription source manifest exceeds byte limit")
	}
	return raw, SubscriptionSourceVersion(raw), nil
}

func SubscriptionSourceVersion(canonical []byte) string {
	digest := sha256.Sum256(canonical)
	return "sv1:" + hex.EncodeToString(digest[:])
}

func DecodeSubscriptionSourceManifest(raw []byte) (SubscriptionSourceManifestV1, error) {
	if len(raw) == 0 || len(raw) > MaxSubscriptionSourceManifestBytes {
		return SubscriptionSourceManifestV1{}, errors.New("invalid subscription source manifest size")
	}
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return SubscriptionSourceManifestV1{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var manifest SubscriptionSourceManifestV1
	if err := decoder.Decode(&manifest); err != nil {
		return SubscriptionSourceManifestV1{}, err
	}
	if err := requireJSONEOF(decoder); err != nil {
		return SubscriptionSourceManifestV1{}, err
	}
	canonical, _, err := CanonicalSubscriptionSourceManifest(manifest)
	if err != nil {
		return SubscriptionSourceManifestV1{}, err
	}
	if !bytes.Equal(raw, canonical) {
		return SubscriptionSourceManifestV1{}, errors.New("subscription source manifest is not canonical")
	}
	return manifest.Clone(), nil
}

func (m SubscriptionSourceManifestV1) Clone() SubscriptionSourceManifestV1 {
	out := m
	out.EntryRoots = append(make([]string, 0, len(m.EntryRoots)), m.EntryRoots...)
	out.Entries = append(make([]SubscriptionSourceManifestEntry, 0, len(m.Entries)), m.Entries...)
	for i := range out.Entries {
		out.Entries[i].Endpoint.ALPN = append(make([]string, 0, len(m.Entries[i].Endpoint.ALPN)), m.Entries[i].Endpoint.ALPN...)
		out.Entries[i].Path = append(make([]SubscriptionSourceManifestEdge, 0, len(m.Entries[i].Path)), m.Entries[i].Path...)
	}
	return out
}

func (m SubscriptionSourceManifestV1) Validate() error {
	if m.Schema != SubscriptionSourceManifestSchemaV1 || m.Renderer != SubscriptionSourceRendererV1 || m.Identity.Generation == 0 {
		return errors.New("invalid subscription source manifest header")
	}
	if err := validateSubscriptionText("identity id", m.Identity.ID, true); err != nil {
		return err
	}
	if m.EntryRoots == nil || m.Entries == nil || len(m.EntryRoots) == 0 || len(m.EntryRoots) > MaxSubscriptionSourceRoots || len(m.EntryRoots) != len(m.Entries) {
		return errors.New("invalid subscription source manifest roots")
	}
	seenRoots := make(map[string]struct{}, len(m.EntryRoots))
	visits := 0
	for i, root := range m.EntryRoots {
		if !subscriptionSourceUUIDv4.MatchString(root) {
			return errors.New("invalid subscription source root")
		}
		if _, ok := seenRoots[root]; ok {
			return errors.New("duplicate subscription source root")
		}
		seenRoots[root] = struct{}{}
		entry := m.Entries[i]
		if entry.Root != root || entry.Endpoint.LineUUID != root || entry.Endpoint.ALPN == nil || entry.Path == nil {
			return errors.New("subscription source root binding mismatch")
		}
		if err := validateSubscriptionEndpoint(entry.Endpoint); err != nil {
			return err
		}
		visits++
		if visits > MaxSubscriptionSourceVisits {
			return errors.New("subscription source manifest exceeds visited-line limit")
		}
		visited := map[string]struct{}{root: {}}
		current := root
		for _, edge := range entry.Path {
			visits++
			if visits > MaxSubscriptionSourceVisits || edge.Source != current || !subscriptionSourceUUIDv4.MatchString(edge.Target) || edge.Generation == 0 || edge.ObservationRevision == 0 || edge.Status != "converged" {
				return errors.New("invalid subscription source path")
			}
			if _, exists := visited[edge.Target]; exists {
				return errors.New("subscription source path contains a cycle")
			}
			visited[edge.Target] = struct{}{}
			current = edge.Target
		}
		terminal := entry.Terminal
		if terminal.LineUUID != current || !subscriptionSourceUUIDv4.MatchString(terminal.LineUUID) || terminal.Generation == 0 || terminal.ObservationRevision == 0 || terminal.Status != "converged" {
			return errors.New("invalid subscription source terminal")
		}
	}
	return nil
}

func validateSubscriptionEndpoint(endpoint SubscriptionSourceManifestEndpoint) error {
	if endpoint.Port < 1 || endpoint.Port > 65535 {
		return errors.New("invalid subscription source endpoint")
	}
	for name, value := range map[string]string{
		"node id": endpoint.NodeID, "label": endpoint.Label, "host": endpoint.Host, "sni": endpoint.SNI,
		"fingerprint": endpoint.Fingerprint, "public key": endpoint.PublicKey, "short id": endpoint.ShortID, "flow": endpoint.Flow,
	} {
		if err := validateSubscriptionText(name, value, true); err != nil {
			return err
		}
	}
	if !validSubscriptionHost(endpoint.Host) || !validSubscriptionHost(endpoint.SNI) {
		return errors.New("invalid subscription source host or sni")
	}
	if endpoint.Fingerprint != "chrome" {
		return errors.New("unsupported subscription source fingerprint")
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(endpoint.PublicKey)
	if err != nil || len(publicKey) != 32 || base64.RawURLEncoding.EncodeToString(publicKey) != endpoint.PublicKey {
		return errors.New("invalid subscription source public key")
	}
	if len(endpoint.ShortID) < 2 || len(endpoint.ShortID) > 16 || len(endpoint.ShortID)%2 != 0 || endpoint.ShortID != strings.ToLower(endpoint.ShortID) {
		return errors.New("invalid subscription source short id")
	}
	if _, err := hex.DecodeString(endpoint.ShortID); err != nil {
		return errors.New("invalid subscription source short id")
	}
	if endpoint.Flow != "xtls-rprx-vision" {
		return errors.New("unsupported subscription source flow")
	}
	allowedALPN := map[string]struct{}{"h2": {}, "http/1.1": {}}
	seenALPN := make(map[string]struct{}, len(endpoint.ALPN))
	for _, value := range endpoint.ALPN {
		if err := validateSubscriptionText("alpn", value, true); err != nil {
			return err
		}
		if _, ok := allowedALPN[value]; !ok {
			return errors.New("unsupported subscription source ALPN")
		}
		if _, exists := seenALPN[value]; exists {
			return errors.New("duplicate subscription source ALPN")
		}
		seenALPN[value] = struct{}{}
	}
	return nil
}

func validateSubscriptionText(name, value string, required bool) error {
	if (required && value == "") || value != strings.TrimSpace(value) || len(value) > MaxSubscriptionURIBytes || strings.ContainsFunc(value, unicode.IsControl) {
		return fmt.Errorf("invalid subscription source %s", name)
	}
	upper := strings.ToUpper(value)
	if strings.Contains(value, "://") || strings.Contains(upper, "PRIVATE KEY") || strings.HasPrefix(value, "lat$") {
		return fmt.Errorf("sensitive subscription source %s", name)
	}
	return nil
}

func validSubscriptionHost(value string) bool {
	if ip := net.ParseIP(value); ip != nil {
		return ip.String() == value
	}
	if len(value) == 0 || len(value) > 253 || value != strings.ToLower(value) || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func rejectDuplicateJSONFields(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid JSON object key")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
	}
	_, err = decoder.Token()
	return err
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("trailing JSON value")
}
