package model

import (
	"bytes"
	"strings"
	"testing"
)

func validSubscriptionSourceManifest() SubscriptionSourceManifestV1 {
	root := "11111111-1111-4111-8111-111111111111"
	target := "22222222-2222-4222-8222-222222222222"
	return SubscriptionSourceManifestV1{
		Schema: SubscriptionSourceManifestSchemaV1, Renderer: "vpn-core-graph-v1",
		Identity:   SubscriptionSourceManifestIdentity{ID: "identity", Generation: 7},
		EntryRoots: []string{root}, Entries: []SubscriptionSourceManifestEntry{{Root: root,
			Endpoint: SubscriptionSourceManifestEndpoint{LineUUID: root, NodeID: "node-a", Label: "entry", Host: "entry.example.com", Port: 443,
				SNI: "entry.example.com", Fingerprint: "chrome", ALPN: []string{"h2"}, PublicKey: strings.Repeat("A", 43), ShortID: "0123456789abcdef", Flow: "xtls-rprx-vision"},
			Path:     []SubscriptionSourceManifestEdge{{Source: root, Target: target, Generation: 3, ObservationRevision: 4, Status: "converged"}},
			Terminal: SubscriptionSourceManifestTerminal{LineUUID: target, Generation: 5, ObservationRevision: 6, Status: "converged"},
		}},
	}
}

func TestSubscriptionSourceManifestCanonicalRoundTripAndVersion(t *testing.T) {
	manifest := validSubscriptionSourceManifest()
	raw, version, err := CanonicalSubscriptionSourceManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(version, "sv1:") || version != SubscriptionSourceVersion(raw) {
		t.Fatalf("version = %q", version)
	}
	back, err := DecodeSubscriptionSourceManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := CanonicalSubscriptionSourceManifest(back)
	if err != nil || !bytes.Equal(raw, second) {
		t.Fatalf("canonical round trip changed bytes: %v\n%s\n%s", err, raw, second)
	}
	back.EntryRoots[0] = "mutated"
	back.Entries[0].Endpoint.ALPN[0] = "mutated"
	if manifest.EntryRoots[0] == "mutated" || manifest.Entries[0].Endpoint.ALPN[0] == "mutated" {
		t.Fatal("decode/clone aliased caller data")
	}
}

func TestSubscriptionSourceManifestStrictDecoderRejectsHostileShapes(t *testing.T) {
	raw, _, err := CanonicalSubscriptionSourceManifest(validSubscriptionSourceManifest())
	if err != nil {
		t.Fatal(err)
	}
	for name, hostile := range map[string][]byte{
		"unknown":   bytes.Replace(raw, []byte(`"renderer":`), []byte(`"unknown":1,"renderer":`), 1),
		"duplicate": bytes.Replace(raw, []byte(`"renderer":`), []byte(`"schema":"duplicate","renderer":`), 1),
		"trailing":  append(append([]byte(nil), raw...), []byte(` {}`)...),
		"uri":       bytes.Replace(raw, []byte(`"entry.example.com"`), []byte(`"vless://credential"`), 1),
		"private":   bytes.Replace(raw, []byte(`"entry"`), []byte(`"-----BEGIN PRIVATE KEY-----"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeSubscriptionSourceManifest(hostile); err == nil {
				t.Fatal("hostile manifest accepted")
			}
		})
	}
}

func TestSubscriptionSourceManifestRejectsBoundsAndBrokenGraph(t *testing.T) {
	for name, mutate := range map[string]func(*SubscriptionSourceManifestV1){
		"nil roots": func(m *SubscriptionSourceManifestV1) { m.EntryRoots = nil },
		"duplicate roots": func(m *SubscriptionSourceManifestV1) {
			m.EntryRoots = append(m.EntryRoots, m.EntryRoots[0])
			m.Entries = append(m.Entries, m.Entries[0])
		},
		"root mismatch": func(m *SubscriptionSourceManifestV1) { m.Entries[0].Root = "22222222-2222-4222-8222-222222222222" },
		"broken path": func(m *SubscriptionSourceManifestV1) {
			m.Entries[0].Path[0].Source = "22222222-2222-4222-8222-222222222222"
		},
		"bad status": func(m *SubscriptionSourceManifestV1) { m.Entries[0].Terminal.Status = "drifted" },
		"empty flow": func(m *SubscriptionSourceManifestV1) { m.Entries[0].Endpoint.Flow = "" },
	} {
		t.Run(name, func(t *testing.T) {
			manifest := validSubscriptionSourceManifest()
			mutate(&manifest)
			if _, _, err := CanonicalSubscriptionSourceManifest(manifest); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
}
