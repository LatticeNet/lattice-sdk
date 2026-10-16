package strictjson

import (
	"encoding/json"
	"testing"
)

func sameAsUnmarshal(t *testing.T, raw []byte) {
	t.Helper()
	got, ok := String(raw)
	var want string
	err := json.Unmarshal(raw, &want)
	if ok && (err != nil || got != want) {
		t.Fatalf("String(%q) = %q; json.Unmarshal %q, %v", raw, got, want, err)
	}
	if !ok && err == nil && len(raw) > 0 && raw[0] == '"' && raw[len(raw)-1] == '"' {
		t.Fatalf("String refuses %q, which json.Unmarshal decodes to %q", raw, want)
	}
}

var stringCorpus = []string{
	`""`, `"plain"`, `"a\"b\\c\/d\be\ff\ng\rh\ti"`, `"Aé中"`, `"😀"`, `"\ud800"`, `"\udc00x"`, `"\ud800A"`,
	`"\ud800\ud800"`, `"􏿿"`, "\"\xff\xfe\"", "\"é中\"", "\"a\tb\"", `"\x"`, `"\u12"`, `"\u12g4"`, `"\'"`, `"a"b"`, `"abc`, `abc"`,
	`"`, `""x`, "\"\x7f\"", "\"\xed\xa0\x80\"", `"{\"version\":2,\"rows\":[{\"line_uuid\":\"a\"}]}"`,
}

func TestStringIsJSONUnmarshal(t *testing.T) {
	for _, raw := range stringCorpus {
		sameAsUnmarshal(t, []byte(raw))
	}
}

func FuzzStringIsJSONUnmarshal(f *testing.F) {
	for _, raw := range stringCorpus {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		sameAsUnmarshal(t, raw)
	})
}

func BenchmarkStringEscapedDocument(b *testing.B) {
	doc := []byte(`{"version":2,"kind":"sub","rows":[`)
	for i := 0; i < 1000; i++ {
		doc = append(doc, `{"line_uuid":"581ff4e6-e0a4-4f5c-9d2a-0b0c0d0e0f10","label":"Tokyo 01","template":{"protocol":"vless","host":"203.0.113.1","port":443}},`...)
	}
	doc = append(doc, `{}]}`...)
	raw, _ := json.Marshal(string(doc))
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := String(raw); !ok {
			b.Fatal("refused")
		}
	}
}

func BenchmarkUnmarshalEscapedDocument(b *testing.B) {
	doc := []byte(`{"version":2,"kind":"sub","rows":[`)
	for i := 0; i < 1000; i++ {
		doc = append(doc, `{"line_uuid":"581ff4e6-e0a4-4f5c-9d2a-0b0c0d0e0f10","label":"Tokyo 01","template":{"protocol":"vless","host":"203.0.113.1","port":443}},`...)
	}
	doc = append(doc, `{}]}`...)
	raw, _ := json.Marshal(string(doc))
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			b.Fatal("refused")
		}
	}
}

func TestStringIntoIsJSONUnmarshal(t *testing.T) {
	for _, raw := range append(stringCorpus, `null`, `1`, `{}`, `nul`) {
		got, want := "prior", "prior"
		ok := StringInto([]byte(raw), &got)
		err := json.Unmarshal([]byte(raw), &want)
		if ok && (err != nil || got != want) {
			t.Fatalf("StringInto(%q) = %q; json.Unmarshal %q, %v", raw, got, want, err)
		}
	}
}
