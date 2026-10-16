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
