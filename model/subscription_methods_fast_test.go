package model

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func strictConvertDecode(raw []byte) (ConvertRequest, error) {
	if err := rejectDuplicateJSONFields(raw); err != nil {
		return ConvertRequest{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var req ConvertRequest
	if err := decoder.Decode(&req); err != nil {
		return ConvertRequest{}, err
	}
	return req, requireJSONEOF(decoder)
}

func sameConvertDecode(t *testing.T, raw []byte) {
	t.Helper()
	fast, ok := decodeConvertRequestFast(raw)
	if !ok {
		return
	}
	want, err := strictConvertDecode(raw)
	if err != nil {
		t.Fatalf("the fast decode admits %q, which the strict decode refuses: %v", raw, err)
	}
	if !reflect.DeepEqual(fast, want) {
		t.Fatalf("convert request %q: fast %+v, strict %+v", raw, fast, want)
	}
}

var convertCorpus = []string{
	`{"target":"sing-box","nodes":[{"name":"a","uuid":"x"},{"name":"b"}],"options":{"x":true},"format":"plain"}`,
	`{"target":"URI","uris":["vless://a"],"raw":""}`, `{"target":"t","nodes":[]}`, `{"target":"t","nodes":null}`,
	`{"target":"t","document":{"text":"proxies:","nodes":[{"a":1}]}}`, `{"target":"t","document":{"text":"x","extra":1}}`,
	`{"target":"t","response_chain":[{"name":"n","source":"s","enabled":true}]}`, `{"target":"t","response_chain":[{"source":"s","x":1}]}`,
	`{"target":"t","extra":1}`, `{"Target":"t"}`, `{"target":"t","nodes":[{"a":1,"a":2}]}`, `{"target":1}`, `{"target":"t"} {}`, `[]`,
}

func TestDecodeConvertRequestFastAgreesWithTheStrictDecode(t *testing.T) {
	for _, raw := range convertCorpus {
		sameConvertDecode(t, []byte(raw))
	}
	if _, ok := decodeConvertRequestFast([]byte(convertCorpus[0])); !ok {
		t.Fatal("a plain convert request does not take the fast path")
	}
}

func FuzzDecodeConvertRequestFastAgreesWithTheStrictDecode(f *testing.F) {
	for _, raw := range convertCorpus {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		sameConvertDecode(t, raw)
	})
}

// EncodeConvertRequest splices canonical nodes into json.Marshal's encoding
// of the rest; the bytes and the verdict must be json.Marshal's and
// Validate's.
func sameConvertEncode(t *testing.T, r ConvertRequest) {
	t.Helper()
	got, gotErr := EncodeConvertRequest(r)
	var want []byte
	wantErr := r.Validate()
	if wantErr == nil {
		want, wantErr = json.Marshal(r)
		if wantErr == nil && len(want) > MaxConvertRequestBytes {
			wantErr = errText2("too large")
		}
	}
	if (gotErr == nil) != (wantErr == nil) || gotErr != nil && wantErr.Error() != "too large" && gotErr.Error() != wantErr.Error() {
		t.Fatalf("convert request %+v: error %v, Validate and json.Marshal %v", r, gotErr, wantErr)
	}
	if gotErr == nil && !bytes.Equal(got, want) {
		t.Fatalf("convert request:\n%s\njson.Marshal\n%s", got, want)
	}
}

type errText2 string

func (e errText2) Error() string { return string(e) }

func TestEncodeConvertRequestIsValidateAndJSONMarshal(t *testing.T) {
	nodes := []json.RawMessage{json.RawMessage(`{"name":"a","uuid":"x"}`), json.RawMessage(`{"name":"b <c>"}`), json.RawMessage(`{ "name":"c"}`),
		json.RawMessage(`["x"]`), json.RawMessage(`{"a":1,"a":2}`), json.RawMessage("{\"n\":\" \"}")}
	for _, node := range nodes {
		for _, r := range []ConvertRequest{
			{Target: "sing-box", Nodes: []json.RawMessage{json.RawMessage(`{"name":"z"}`), node}, Options: map[string]bool{"x": true}, Format: "plain"},
			{Target: "", Nodes: []json.RawMessage{node}},
			{Target: "URI", Nodes: []json.RawMessage{node}, ResponseChain: []ResponseTransformerStep{{Source: "s", Enabled: true}}},
			{Target: "URI", Nodes: []json.RawMessage{node}, ResponseChain: []ResponseTransformerStep{{Name: "empty"}}},
			{Target: "URI", Nodes: []json.RawMessage{node}, Raw: "x"},
		} {
			sameConvertEncode(t, r)
		}
	}
	if _, spliced, err := encodeConvertRequestSpliced(ConvertRequest{Target: "URI", Nodes: []json.RawMessage{nodes[0], json.RawMessage(`{"k":1}`)}}); err != nil || !spliced {
		t.Fatalf("canonical nodes take the plain path: %v, %v", spliced, err)
	}
}

func FuzzEncodeConvertRequestIsValidateAndJSONMarshal(f *testing.F) {
	f.Add([]byte(`{"name":"a"}`), "sing-box", "plain")
	f.Add([]byte(` {"a" : "<"} `), "", "")
	f.Fuzz(func(t *testing.T, node []byte, target, format string) {
		sameConvertEncode(t, ConvertRequest{Target: target, Format: format, Nodes: []json.RawMessage{node, json.RawMessage(`{"k":1}`)}})
	})
}

func samePlanDecode(t *testing.T, raw []byte) {
	t.Helper()
	fast, ok := decodeSelectionPlanFast(raw)
	if !ok {
		return
	}
	if err := rejectDuplicateJSONFields(raw); err != nil {
		t.Fatalf("plan %q: the fast decode admits a duplicate key: %v", raw, err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var want SelectionPlan
	if err := decoder.Decode(&want); err != nil {
		t.Fatalf("plan %q: the fast decode admits what the strict decode refuses: %v", raw, err)
	}
	if !reflect.DeepEqual(fast, want) {
		t.Fatalf("plan %q: fast %+v, strict %+v", raw, fast, want)
	}
}

var planCorpus = []string{
	`{"kind":"nodes","nodes":[{"line_uuid":"a","placeholders":{"uuid":"p"},"node":{"name":"x"}},{"provider":true,"node":{}}],"selection":{"catalogue_version":"v","line_uuids":["a"]},"policy":{"ddns_dial":true}}`,
	`{"kind":"nodes","nodes":null}`, `{"kind":"nodes","nodes":[]}`, `{"kind":"document","document":"d","nodes":[{"node":{"a":1}}]}`,
	`{"kind":"nodes","nodes":[{"node":{},"x":1}]}`, `{"kind":"nodes","selection":{"catalogue_version":"v","x":1}}`, `{"kind":"nodes","Nodes":[]}`,
	`{"kind":"nodes","nodes":[{"node":{"a":1,"a":2}}]}`, `{"kind":"nodes","response_chain":[{"source":"s","enabled":true}]}`, `{"kind":"nodes","policy":null}`,
}

func TestDecodeSelectionPlanFastAgreesWithTheStrictDecode(t *testing.T) {
	for _, raw := range planCorpus {
		samePlanDecode(t, []byte(raw))
	}
	if _, ok := decodeSelectionPlanFast([]byte(planCorpus[0])); !ok {
		t.Fatal("a plain plan does not take the fast path")
	}
}

func FuzzDecodeSelectionPlanFastAgreesWithTheStrictDecode(f *testing.F) {
	for _, raw := range planCorpus {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		samePlanDecode(t, raw)
	})
}
