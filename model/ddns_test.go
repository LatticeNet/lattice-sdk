package model

import (
	"encoding/json"
	"strings"
	"testing"
)

// A profile stored before comments existed has neither field. It must decode
// to the empty mode, which the server treats as the default template, and it
// must encode back without inventing the fields.
func TestDDNSProfileWithoutCommentFieldsDecodesUnchanged(t *testing.T) {
	old := `{"id":"ddns_1","name":"home","node_id":"n1","provider":"cloudflare","domains":["a.example.com"],"enable_ipv4":true,"enable_ipv6":false,"max_retries":3,"ttl":60,"created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}`
	var p DDNSProfile
	if err := json.Unmarshal([]byte(old), &p); err != nil {
		t.Fatal(err)
	}
	if p.CommentMode != "" || p.RecordComment != "" {
		t.Fatalf("old profile decoded with comment fields: %+v", p)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "comment_mode") || strings.Contains(string(raw), "record_comment") {
		t.Fatalf("empty comment fields were serialized: %s", raw)
	}
}

func TestDDNSProfileCommentFieldsRoundTrip(t *testing.T) {
	in := DDNSProfile{ID: "ddns_1", CommentMode: DDNSCommentCustom, RecordComment: "Lattice #node# #ip#"}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"comment_mode":"custom"`) || !strings.Contains(string(raw), `"record_comment":"Lattice #node# #ip#"`) {
		t.Fatalf("comment fields missing from JSON: %s", raw)
	}
	var out DDNSProfile
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.CommentMode != in.CommentMode || out.RecordComment != in.RecordComment {
		t.Fatalf("round trip lost comment fields: %+v", out)
	}
}

// A profile stored before record types existed decodes with an empty type,
// which the server treats as the address type, and encodes back without the
// new fields.
func TestDDNSProfileWithoutRecordTypeDecodesUnchanged(t *testing.T) {
	old := `{"id":"ddns_1","name":"home","node_id":"n1","provider":"cloudflare","domains":["a.example.com"],"enable_ipv4":true,"enable_ipv6":false,"max_retries":3,"ttl":60,"last_ipv4":"203.0.113.7","created_at":"2026-01-01T00:00:00Z","updated_at":"2026-01-01T00:00:00Z"}`
	var p DDNSProfile
	if err := json.Unmarshal([]byte(old), &p); err != nil {
		t.Fatal(err)
	}
	if p.RecordType != "" || p.CNAMETarget != "" || p.LastTarget != "" {
		t.Fatalf("old profile decoded with record type fields: %+v", p)
	}
	if p.LastIPv4 != "203.0.113.7" || !p.EnableIPv4 {
		t.Fatalf("old profile lost its address fields: %+v", p)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"record_type", "cname_target", "last_target"} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("empty %s was serialized: %s", key, raw)
		}
	}
}

func TestDDNSProfileCNAMEFieldsRoundTrip(t *testing.T) {
	in := DDNSProfile{ID: "ddns_1", RecordType: DDNSRecordCNAME, CNAMETarget: "nat-us-28tz.aproxy.top", LastTarget: "nat-us-28tz.aproxy.top"}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"record_type":"cname"`, `"cname_target":"nat-us-28tz.aproxy.top"`, `"last_target":"nat-us-28tz.aproxy.top"`} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("%s missing from JSON: %s", want, raw)
		}
	}
	var out DDNSProfile
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	if out.RecordType != in.RecordType || out.CNAMETarget != in.CNAMETarget || out.LastTarget != in.LastTarget {
		t.Fatalf("round trip lost record type fields: %+v", out)
	}
}
