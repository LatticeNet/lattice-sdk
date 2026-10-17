package plugin

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// The fast decodes may decline any frame, but a frame they decode must be
// one the encoding/json decode they stand in front of admits, decoded to the
// same value.
func sameAsStrict(t *testing.T, raw []byte) {
	t.Helper()
	if fast, ok := decodeInvokeV2Fast(raw); ok {
		var want invokeV2Frame
		if err := strictDecodeFrame(raw, &want); err != nil {
			t.Fatalf("invoke %q: the fast decode admits what strictDecodeFrame refuses: %v", raw, err)
		}
		if !reflect.DeepEqual(fast, want) {
			t.Fatalf("invoke %q: fast %+v, strict %+v", raw, fast, want)
		}
	}
	if fast, ok := decodeHostResponseFast(raw); ok {
		var want strictHostResponseEnvelope
		if err := strictDecodeFrame(raw, &want); err != nil {
			t.Fatalf("host_response %q: the fast decode admits what strictDecodeFrame refuses: %v", raw, err)
		}
		if !reflect.DeepEqual(fast, want) {
			t.Fatalf("host_response %q: fast %+v, strict %+v", raw, fast, want)
		}
	}
	if fast, ok := callPayloadFast(raw); ok {
		var want CallPayload
		if err := json.Unmarshal(raw, &want); err != nil {
			t.Fatalf("call payload %q: the fast decode admits what json.Unmarshal refuses: %v", raw, err)
		}
		want.Payload = append(json.RawMessage(nil), want.Payload...)
		if !reflect.DeepEqual(fast, want) {
			t.Fatalf("call payload %q: fast %+v, json.Unmarshal %+v", raw, fast, want)
		}
	}
}

var fastFrameCorpus = []string{
	`{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"1","request":{"action":"call","payload":{"service":"s","method":"m","payload":{"x":[1,2]}}}}`,
	`{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"1","request":{"action":"call","service":"s","method":"m","payload":null}}`,
	`{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"1","request":null}`,
	`{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"1"}`,
	`{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"1","request":{"action":"call","x":1}}`,
	`{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"1","request":{"Action":"call"}}`,
	`{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"1","request":{"action":1}}`,
	`{"protocol":"2","kind":"invoke","generation":1,"invocation_id":"1","request":{}}`,
	`{"protocol":2,"kind":"invoke","generation":1.5,"invocation_id":"1","request":{}}`,
	`{"protocol":2,"protocol":2,"kind":"invoke","generation":1,"invocation_id":"1","request":{}}`,
	`{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"1","request":{"payload":{"a":1,"a":2}}}`,
	`{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"1","request":{}} {}`,
	`{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"1","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{"rows":[]}}}`,
	`{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"1","host_call_id":"h1","host_response":{"id":"h1","ok":false,"error":"no"}}`,
	`{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"1","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":null,"extra":1}}`,
	`{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"1","host_call_id":"h1","host_response":[]}`,
	`{"protocol":2,"kind":"host_response","generation":"1","invocation_id":"1","host_call_id":"h1","host_response":{}}`,
	`{"service":"s","method":"m","payload":{"k":"v"}}`, `{"service":"s","method":"m"}`, `{"service":"s","payload":null}`,
	`{"service":1}`, `{"Service":"s"}`, `{"service":"s","other":1}`, `{"service":"s","service":"t"}`, `[]`, `null`, `{}`, ``,
	"{\"service\":\"\xff\"}", `{"service":"s"}`, `{"service":"s"}`,
}

func TestFastFrameDecodesAgreeWithTheStrictDecodes(t *testing.T) {
	for _, raw := range fastFrameCorpus {
		sameAsStrict(t, []byte(raw))
	}
	// The plain frames the runtime exchanges take the fast path.
	if _, ok := decodeInvokeV2Fast([]byte(fastFrameCorpus[0])); !ok {
		t.Fatal("a plain invoke frame does not take the fast path")
	}
	if _, ok := decodeHostResponseFast([]byte(fastFrameCorpus[12])); !ok {
		t.Fatal("a plain host_response frame does not take the fast path")
	}
	if _, ok := callPayloadFast([]byte(fastFrameCorpus[17])); !ok {
		t.Fatal("a plain call payload does not take the fast path")
	}
}

func FuzzFastFrameDecodesAgreeWithTheStrictDecodes(f *testing.F) {
	for _, raw := range fastFrameCorpus {
		f.Add([]byte(raw))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		sameAsStrict(t, raw)
	})
}

// BenchmarkDecodeLargeInvoke decodes a render request carrying a 900 KB
// snapshot: the invoke frame, then its call payload.
func BenchmarkDecodeLargeInvoke(b *testing.B) {
	var rows bytes.Buffer
	for i := 0; i < 1000; i++ {
		fmt.Fprintf(&rows, `{\"line_uuid\":\"581ff4e6-e0a4-4f5c-9d2a-%012d\",\"label\":\"Tokyo %d\",\"template\":{\"protocol\":\"vless\",\"host\":\"203.0.113.%d\",\"port\":443,\"params\":{\"security\":\"reality\",\"sni\":\"www.example.com\",\"pbk\":\"q8r5kKy9VQ6c5xHkC2x3l7m1ZtLwJ9dXQvW3p2H0aB4\"}},\"geo\":{\"country\":\"JP\"},\"tags\":[\"edge\"]},`, i, i, i%250)
	}
	payload := `{"service":"latticenet.sub-store/subscription","method":"render","payload":{"format":"plain","raw":"{\"rows\":[` + strings.TrimSuffix(rows.String(), ",") + `]}","subscription_id":"fleet-1000"}}`
	raw := []byte(`{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"1","request":{"action":"call","payload":` + payload + `}}`)
	b.SetBytes(int64(len(raw)))
	b.ReportAllocs()
	for b.Loop() {
		frame, err := decodeInvokeV2(raw, 1, len(raw))
		if err != nil {
			b.Fatal(err)
		}
		if _, err := frame.Request.CallPayload(); err != nil {
			b.Fatal(err)
		}
	}
}

// sameInvokeResultFrame fails when the spliced frame differs from what
// json.NewEncoder writes for the same response.
func sameInvokeResultFrame(t *testing.T, resp Response) {
	t.Helper()
	var want bytes.Buffer
	if err := json.NewEncoder(&want).Encode(invokeResultFrame{2, "invoke_result", 7, "12", resp}); err != nil {
		if _, ok := appendInvokeResultFrame(nil, 7, "12", resp); ok {
			t.Fatalf("the spliced frame admits a result encoding/json refuses: %q", resp.Result)
		}
		return
	}
	got, ok := appendInvokeResultFrame(nil, 7, "12", resp)
	if ok && !bytes.Equal(got, want.Bytes()) {
		t.Fatalf("spliced frame\n%s\nencoding/json\n%s", got, want.Bytes())
	}
}

func TestInvokeResultFrameIsWhatEncodingJSONWrites(t *testing.T) {
	results := []string{``, `{}`, `{"plan":{"kind":"nodes","nodes":[{"a":1}]},"content":"x y"}`, `{"a": 1}`, `{"a":"<b>"}`,
		"{\"a\":\"\u2028\"}", `[1,2]`, `"text"`, `null`, `{"a":1,"a":2}`, `{"a":`, "{\"a\":\"\xff\"}"}
	for _, result := range results {
		for _, resp := range []Response{
			{OK: true, Result: json.RawMessage(result)},
			{OK: true, Result: json.RawMessage(result), Message: "m & <n>", Warnings: []string{"w1", "w\u2029"}},
			{OK: false, Error: "denied", Plan: "p"},
			{OK: true, Result: json.RawMessage(result), Plan: "plan", Message: "", Error: "", Warnings: []string{}},
		} {
			sameInvokeResultFrame(t, resp)
		}
	}
	if _, ok := appendInvokeResultFrame(nil, 7, "12", Response{OK: true, Result: json.RawMessage(results[2])}); !ok {
		t.Fatal("a compact result does not take the spliced path")
	}
}

func FuzzInvokeResultFrameIsWhatEncodingJSONWrites(f *testing.F) {
	f.Add([]byte(`{"plan":{"kind":"nodes"}}`), "m", "", "w")
	f.Add([]byte(`{"a": "<"}`), "", "e", "")
	f.Fuzz(func(t *testing.T, result []byte, message, errText, warning string) {
		resp := Response{OK: errText == "", Result: result, Message: message, Error: errText}
		if warning != "" {
			resp.Warnings = []string{warning}
		}
		sameInvokeResultFrame(t, resp)
	})
}
