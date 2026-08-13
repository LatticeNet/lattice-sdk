package model

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func validSubscriptionSourceManifest() SubscriptionSourceManifestV1 {
	root := "11111111-1111-4111-8111-111111111111"
	target := "22222222-2222-4222-8222-222222222222"
	return SubscriptionSourceManifestV1{
		Schema: SubscriptionSourceManifestSchemaV1, Renderer: SubscriptionSourceRendererV1,
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

func TestSubscriptionSourceManifestPreservesRequiredEmptyArrays(t *testing.T) {
	manifest := validSubscriptionSourceManifest()
	manifest.Entries[0].Endpoint.ALPN = []string{}
	manifest.Entries[0].Path = []SubscriptionSourceManifestEdge{}
	manifest.Entries[0].Terminal.LineUUID = manifest.EntryRoots[0]

	raw, _, err := CanonicalSubscriptionSourceManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"alpn":[]`)) || !bytes.Contains(raw, []byte(`"path":[]`)) {
		t.Fatalf("required empty arrays encoded as null: %s", raw)
	}
	clone := manifest.Clone()
	if clone.Entries[0].Endpoint.ALPN == nil || clone.Entries[0].Path == nil {
		t.Fatal("clone changed required empty arrays to nil")
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
		"bad status":     func(m *SubscriptionSourceManifestV1) { m.Entries[0].Terminal.Status = "drifted" },
		"empty flow":     func(m *SubscriptionSourceManifestV1) { m.Entries[0].Endpoint.Flow = "" },
		"wrong renderer": func(m *SubscriptionSourceManifestV1) { m.Renderer = "vpn-core-graph-v2" },
		"root cycle": func(m *SubscriptionSourceManifestV1) {
			root := m.EntryRoots[0]
			m.Entries[0].Path = append(m.Entries[0].Path,
				SubscriptionSourceManifestEdge{Source: m.Entries[0].Path[0].Target, Target: root, Generation: 5, ObservationRevision: 6, Status: "converged"})
			m.Entries[0].Terminal.LineUUID = root
		},
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

func TestSubscriptionSourceManifestCountsVisitedLinesAndEnforcesValueBounds(t *testing.T) {
	manifest := validSubscriptionSourceManifest()
	root := manifest.EntryRoots[0]
	manifest.Entries[0].Path = make([]SubscriptionSourceManifestEdge, MaxSubscriptionSourceVisits)
	current := root
	for i := range manifest.Entries[0].Path {
		target := fmt.Sprintf("%08x-0000-4000-8000-%012x", i+3, i+3)
		manifest.Entries[0].Path[i] = SubscriptionSourceManifestEdge{
			Source: current, Target: target, Generation: 1, ObservationRevision: 1, Status: "converged",
		}
		current = target
	}
	manifest.Entries[0].Terminal.LineUUID = current
	if _, _, err := CanonicalSubscriptionSourceManifest(manifest); err == nil {
		t.Fatal("root plus 10,000 path targets exceeded visited-line limit but was accepted")
	}

	manifest = validSubscriptionSourceManifest()
	manifest.Entries[0].Endpoint.Host = strings.Repeat("h", MaxSubscriptionURIBytes+1)
	if _, _, err := CanonicalSubscriptionSourceManifest(manifest); err == nil {
		t.Fatal("oversized renderer input accepted")
	}
}

func TestSubscriptionSourceManifestRejectsUnsafeTextInEveryRendererField(t *testing.T) {
	setters := map[string]func(*SubscriptionSourceManifestV1, string){
		"identity id": func(m *SubscriptionSourceManifestV1, value string) { m.Identity.ID = value },
		"node id":     func(m *SubscriptionSourceManifestV1, value string) { m.Entries[0].Endpoint.NodeID = value },
		"label":       func(m *SubscriptionSourceManifestV1, value string) { m.Entries[0].Endpoint.Label = value },
		"host":        func(m *SubscriptionSourceManifestV1, value string) { m.Entries[0].Endpoint.Host = value },
		"sni":         func(m *SubscriptionSourceManifestV1, value string) { m.Entries[0].Endpoint.SNI = value },
		"fingerprint": func(m *SubscriptionSourceManifestV1, value string) { m.Entries[0].Endpoint.Fingerprint = value },
		"public key":  func(m *SubscriptionSourceManifestV1, value string) { m.Entries[0].Endpoint.PublicKey = value },
		"short id":    func(m *SubscriptionSourceManifestV1, value string) { m.Entries[0].Endpoint.ShortID = value },
		"flow":        func(m *SubscriptionSourceManifestV1, value string) { m.Entries[0].Endpoint.Flow = value },
	}
	hostile := map[string]string{
		"leading whitespace":  " unsafe",
		"trailing whitespace": "unsafe ",
		"control":             "unsafe\nvalue",
		"uri":                 "vless://credential",
		"private key":         "-----begin private key-----",
		"envelope":            "lat$credential",
	}
	for field, set := range setters {
		for shape, value := range hostile {
			t.Run(field+"/"+shape, func(t *testing.T) {
				manifest := validSubscriptionSourceManifest()
				set(&manifest, value)
				if _, _, err := CanonicalSubscriptionSourceManifest(manifest); err == nil {
					t.Fatal("unsafe renderer input accepted")
				}
			})
		}
	}
	for shape, value := range hostile {
		t.Run("alpn/"+shape, func(t *testing.T) {
			manifest := validSubscriptionSourceManifest()
			manifest.Entries[0].Endpoint.ALPN = []string{value}
			if _, _, err := CanonicalSubscriptionSourceManifest(manifest); err == nil {
				t.Fatal("unsafe ALPN accepted")
			}
		})
	}
}

func TestSubscriptionSourceManifestEnforcesExactEndpointSemantics(t *testing.T) {
	for name, mutate := range map[string]func(*SubscriptionSourceManifestV1){
		"uppercase host":   func(m *SubscriptionSourceManifestV1) { m.Entries[0].Endpoint.Host = "Entry.example.com" },
		"leading host dot": func(m *SubscriptionSourceManifestV1) { m.Entries[0].Endpoint.Host = ".entry.example.com" },
		"trailing sni dot": func(m *SubscriptionSourceManifestV1) { m.Entries[0].Endpoint.SNI = "entry.example.com." },
		"empty dns label":  func(m *SubscriptionSourceManifestV1) { m.Entries[0].Endpoint.Host = "entry..example.com" },
		"long dns label": func(m *SubscriptionSourceManifestV1) {
			m.Entries[0].Endpoint.Host = strings.Repeat("a", 64) + ".example"
		},
		"unsafe host delimiter": func(m *SubscriptionSourceManifestV1) { m.Entries[0].Endpoint.Host = "entry.example.com/path" },
		"fingerprint":           func(m *SubscriptionSourceManifestV1) { m.Entries[0].Endpoint.Fingerprint = "firefox" },
		"public key encoding":   func(m *SubscriptionSourceManifestV1) { m.Entries[0].Endpoint.PublicKey = strings.Repeat("A", 42) },
		"short id uppercase":    func(m *SubscriptionSourceManifestV1) { m.Entries[0].Endpoint.ShortID = "ABCDEF" },
		"short id odd":          func(m *SubscriptionSourceManifestV1) { m.Entries[0].Endpoint.ShortID = "abc" },
		"short id too short":    func(m *SubscriptionSourceManifestV1) { m.Entries[0].Endpoint.ShortID = "" },
		"flow":                  func(m *SubscriptionSourceManifestV1) { m.Entries[0].Endpoint.Flow = "" },
		"alpn unsupported":      func(m *SubscriptionSourceManifestV1) { m.Entries[0].Endpoint.ALPN = []string{"h3"} },
		"alpn duplicate":        func(m *SubscriptionSourceManifestV1) { m.Entries[0].Endpoint.ALPN = []string{"h2", "h2"} },
	} {
		t.Run(name, func(t *testing.T) {
			manifest := validSubscriptionSourceManifest()
			mutate(&manifest)
			if _, _, err := CanonicalSubscriptionSourceManifest(manifest); err == nil {
				t.Fatal("invalid endpoint semantics accepted")
			}
		})
	}
}

func TestSubscriptionSourceManifestAcceptsCanonicalDNSIPAndEmptyALPN(t *testing.T) {
	for _, host := range []string{"entry.example.com", "192.0.2.10", "2001:db8::1"} {
		t.Run(host, func(t *testing.T) {
			manifest := validSubscriptionSourceManifest()
			manifest.Entries[0].Endpoint.Host = host
			manifest.Entries[0].Endpoint.SNI = host
			manifest.Entries[0].Endpoint.ALPN = []string{}
			raw, _, err := CanonicalSubscriptionSourceManifest(manifest)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(raw, []byte(`"alpn":[]`)) {
				t.Fatalf("empty ALPN is not canonical: %s", raw)
			}
			if _, err := DecodeSubscriptionSourceManifest(raw); err != nil {
				t.Fatalf("canonical endpoint did not round trip: %v", err)
			}
		})
	}
}
