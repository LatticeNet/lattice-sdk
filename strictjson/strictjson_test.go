package strictjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// specification is the check Valid stands in front of: encoding/json's
// Decoder walked token by token, a duplicate decoded key in any object
// refused, and nothing but whitespace after the one value. It is the walk the
// SDK's strict decoders ran before Valid existed, and they still run it
// whenever Valid answers false.
func specification(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := map[string]struct{}{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return err
				}
				key, ok := k.(string)
				if !ok {
					return errors.New("non-string key")
				}
				if _, dup := seen[key]; dup {
					return fmt.Errorf("duplicate %q", key)
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for dec.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		}
		_, err = dec.Token()
		return err
	}
	if err := walk(); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("trailing data")
	}
	return nil
}

func depthOf(raw []byte) int {
	depth, deepest := 0, 0
	inString, escaped := false, false
	for _, c := range raw {
		switch {
		case escaped:
			escaped = false
		case inString && c == '\\':
			escaped = true
		case c == '"':
			inString = !inString
		case !inString && (c == '{' || c == '['):
			depth++
			deepest = max(deepest, depth)
		case !inString && (c == '}' || c == ']'):
			depth--
		}
	}
	return deepest
}

var cases = []string{
	`{}`, `[]`, `""`, `0`, `-0`, `1.5e-3`, `true`, `false`, `null`, ` {"a" : [1, 2, {"b": null}] } `,
	`{"a":1,"a":2}`, `{"a":1,"a":2}`, `{"a":{"b":1,"b":2}}`, `[{"x":1},{"x":1}]`, `{"a":{"x":1},"b":{"x":1}}`,
	`{"aé":1,"aé":2}`, "{\"a\xff\":1,\"a\xfe\":2}", "{\"\xff\":1}", "\"\xc3\x28\"", `{"":1,"":2}`, `{"":1}`,
	`{"a":1}x`, `{"a":1} {}`, `{"a":1,}`, `[1,]`, `[,1]`, `{,}`, `{"a"}`, `{"a":}`, `{a:1}`, `{'a':1}`, `01`, `1.`, `.5`,
	`1e`, `1e+`, `-`, `--1`, `+1`, `1E5`, `1e05`, `0.0e-0`, `tru`, `nul`, `"\x"`, `"\u12"`, `"\u12g4"`, "\"a\tb\"", "\"\x7f\"",
	`"\ud800"`, `"\/\b\f\n\r\t\"\\"`, ``, ` `, `[`, `{`, `"`, `{"a":1`, `[1 2]`, `{"a":1 "b":2}`, `[] []`, "\xef\xbb\xbf{}",
	`{"\ud800":1,"\udfff":2}`, `{"\ud800":1,"\ufffd":2}`, "{\"\xff\":1,\"\\ufffd\":2}", `{"\uD834\uDD1E":1,"\ud834\udd1e":2}`,
	`1E700`, `-1e309`, `1e-400`, `123456789012345678901234567890`, `0.0000000000000000000000000001`, `[1e400]`, `{"a":1e999}`,
	`{"A":1,"a":2}`, `{"a":[{"a":1,"b":{"a":2,"a":3}}]}`, `[[[[[[[[[[]]]]]]]]]]`, `{"a":"}","a":"]"}`, `{"a":"\"","b":"\\"}`,
}

func TestValidAgreesWithTheSpecification(t *testing.T) {
	for _, c := range cases {
		check(t, []byte(c))
	}
}

func TestValidSeesDuplicatesPastTheLinearKeyRun(t *testing.T) {
	var b strings.Builder
	b.WriteByte('{')
	for i := 0; i < 3*linearKeys; i++ {
		fmt.Fprintf(&b, `"k%d":%d,`, i, i)
	}
	ok := b.String() + `"last":0}`
	if !Valid([]byte(ok)) {
		t.Fatal("an object of distinct keys past the linear run is refused")
	}
	for _, dup := range []string{"k0", fmt.Sprintf("k%d", linearKeys-1), fmt.Sprintf("k%d", linearKeys), fmt.Sprintf("k%d", 2*linearKeys)} {
		if raw := b.String() + `"` + dup + `":0}`; Valid([]byte(raw)) {
			t.Fatalf("a repeat of %s after %d keys is admitted", dup, 3*linearKeys)
		}
		if raw := strings.Replace(b.String(), `"k1":1`, `"k1":1,"k1":1`, 1) + `"last":0}`; Valid([]byte(raw)) {
			t.Fatalf("an early repeat in a long object is admitted")
		}
	}
}

func TestCompactAdmitsOnlyWhatJSONCompactLeavesAlone(t *testing.T) {
	for raw, want := range map[string]bool{
		`{"a":[1,{"b":"x y"}]}`: true, `{"a": 1}`: false, ` {}`: false, `{} `: false, "[1,\n2]": false, `"a b"`: true,
		`{"a":1,"a":2}`: false, `{"a":"<&>"}`: true,
	} {
		if got := Compact([]byte(raw)); got != want {
			t.Fatalf("Compact(%q) = %v, want %v", raw, got, want)
		}
	}
}

func TestValidRefusesNestingPastMaxDepthWithoutAdmittingIt(t *testing.T) {
	at := []byte(strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth))
	if !Valid(at) {
		t.Fatal("nesting at MaxDepth is refused")
	}
	past := []byte(strings.Repeat(`{"a":`, MaxDepth+1) + "1" + strings.Repeat("}", MaxDepth+1))
	if Valid(past) {
		t.Fatal("nesting past MaxDepth is admitted")
	}
	if err := specification(past); err != nil {
		t.Fatalf("the specification refuses what the callers' fallback must still admit: %v", err)
	}
}

func TestFieldsAnswersTheTopLevelMembersAsEncodingJSONDecodesThem(t *testing.T) {
	raw := []byte(` {"a" : [1, {"a":2}], "\u0062":"x", "c\u00e9":null, "d":{"e":{}} } `)
	fields, ok := Fields(raw)
	if !ok {
		t.Fatal("Fields refuses a valid object")
	}
	var want map[string]json.RawMessage
	if err := json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if len(fields) != len(want) {
		t.Fatalf("Fields answers %d members, encoding/json %d", len(fields), len(want))
	}
	order := []string{"a", "b", "c\u00e9", "d"}
	for i, f := range fields {
		if f.Key != order[i] || string(f.Value) != string(want[f.Key]) {
			t.Fatalf("member %d is %q=%s, want %q=%s", i, f.Key, f.Value, order[i], want[order[i]])
		}
	}
	for _, refused := range []string{`[]`, `"x"`, `{"a":1,"a":2}`, `{"a":{"b":1,"b":1}}`, `{"a":1} x`, `{"a":}`} {
		if _, ok := Fields([]byte(refused)); ok {
			t.Fatalf("Fields admits %s", refused)
		}
	}
}

func check(t *testing.T, raw []byte) {
	t.Helper()
	if fields, ok := Fields(raw); ok {
		var want map[string]json.RawMessage
		if err := json.Unmarshal(raw, &want); err != nil || len(want) != len(fields) {
			t.Fatalf("Fields admits %q with %d members; encoding/json answers %d, %v", raw, len(fields), len(want), err)
		}
		for _, f := range fields {
			if string(want[f.Key]) != string(f.Value) {
				t.Fatalf("Fields answers %q=%s in %q; encoding/json %s", f.Key, f.Value, raw, want[f.Key])
			}
		}
	}
	if Compact(raw) {
		var compacted bytes.Buffer
		if err := json.Compact(&compacted, raw); err != nil || !bytes.Equal(compacted.Bytes(), raw) {
			t.Fatalf("Compact admits %q, which json.Compact makes %q (%v)", raw, compacted.Bytes(), err)
		}
		if !Valid(raw) {
			t.Fatalf("Compact admits %q, which Valid refuses", raw)
		}
	}
	got, spec := Valid(raw), specification(raw)
	if got && spec != nil {
		t.Fatalf("Valid admits %q, which the specification refuses: %v", raw, spec)
	}
	if !got && spec == nil && depthOf(raw) <= MaxDepth {
		t.Fatalf("Valid refuses %q, which the specification admits", raw)
	}
}

func FuzzValidAgreesWithTheSpecification(f *testing.F) {
	for _, c := range cases {
		f.Add([]byte(c))
	}
	f.Add([]byte(`{"kind":"nodes","nodes":[{"line_uuid":"581ff4e6-e0a4-4f5c-9d2a-0b0c0d0e0f10","placeholders":{"uuid":"LATTICE-SYN-x"},"node":{"name":"a","type":"vless","port":443,"reality-opts":{"public-key":"k"}}}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		check(t, raw)
	})
}

func BenchmarkValidPlanShape(b *testing.B) {
	var buf bytes.Buffer
	buf.WriteString(`{"kind":"nodes","nodes":[`)
	for i := 0; i < 1000; i++ {
		if i > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf, `{"line_uuid":"581ff4e6-e0a4-4f5c-9d2a-%012d","placeholders":{"uuid":"LATTICE-SYN-581ff4e6-e0a4-4f5c-9d2a-%012d-uuid-0123456789abcdef0123456789abcdef"},"node":{"name":"Node %d","type":"vless","server":"45.10.0.%d","port":443,"uuid":"x","tls":true,"servername":"www.example.com","network":"tcp","udp":true,"client-fingerprint":"chrome","reality-opts":{"public-key":"q8r5kKy9VQ6c5xHkC2x3l7m1ZtLwJ9dXQvW3p2H0aB4","short-id":"0a1b"},"line_uuid":"581ff4e6-e0a4-4f5c-9d2a-%012d","addresses":["45.10.0.%d","2001:db8::%x"],"geo":{"country":"JP","city":"Tokyo"},"tags":["edge","premium"],"chain":{"role":"single"}}}`, i, i, i, i%256, i, i%256, i)
	}
	buf.WriteString(`]}`)
	raw := buf.Bytes()
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		if !Valid(raw) {
			b.Fatal("refused")
		}
	}
}

func BenchmarkSpecificationPlanShape(b *testing.B) {
	var buf bytes.Buffer
	buf.WriteString(`{"nodes":[`)
	for i := 0; i < 1000; i++ {
		if i > 0 {
			buf.WriteByte(',')
		}
		fmt.Fprintf(&buf, `{"name":"Node %d","type":"vless","server":"45.10.0.%d","port":443,"reality-opts":{"public-key":"k","short-id":"0a1b"},"addresses":["45.10.0.%d"],"tags":["edge"]}`, i, i%256, i%256)
	}
	buf.WriteString(`]}`)
	raw := buf.Bytes()
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		if specification(raw) != nil {
			b.Fatal("refused")
		}
	}
}
