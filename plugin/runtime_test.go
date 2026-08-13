package plugin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestV2SessionRejectsStaleDuplicateAndLate(t *testing.T) {
	s := NewV2Session(7)
	if err := s.Accept("invoke", 7, "i1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Accept("invoke", 7, "i1"); err == nil {
		t.Fatal("duplicate invoke accepted")
	}
	s = NewV2Session(7)
	if err := s.Accept("invoke", 6, "i1"); err == nil {
		t.Fatal("stale generation accepted")
	}
	s = NewV2Session(7)
	if err := s.Accept("invoke", 7, "i1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Accept("invoke_ready", 7, "i1"); err == nil {
		t.Fatal("late ready accepted")
	}
}

func TestRuntimeServeFramesRequestsAndResponses(t *testing.T) {
	in := strings.NewReader(`{"action":"call","payload":{"service":"example/items","method":"list","payload":{"want":"nodes"}}}` + "\n")
	var out bytes.Buffer
	rt := NewRuntime(RuntimeOptions{In: in, Out: &out})

	err := rt.Serve(context.Background(), HandlerFunc(func(ctx context.Context, req Request, host *HostClient) Response {
		if req.Action != ActionCall {
			t.Fatalf("action = %q, want call", req.Action)
		}
		call, err := req.CallPayload()
		if err != nil {
			return ErrorResponse(err)
		}
		if call.Service != "example/items" || call.Method != "list" || string(call.Payload) != `{"want":"nodes"}` {
			t.Fatalf("call payload = %+v raw=%s", call, call.Payload)
		}
		return ResultResponse(map[string]any{"ok": true}, "listed")
	}))
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}

	var resp Response
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		t.Fatalf("decode response: %v output=%s", err, out.String())
	}
	if !resp.OK || resp.Message != "listed" || string(resp.Result) != `{"ok":true}` {
		t.Fatalf("unexpected response: %+v raw=%s", resp, resp.Result)
	}
}

func TestHostClientRoundTripThroughResponseFD(t *testing.T) {
	respR, respW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer respW.Close()
	t.Setenv(hostResponseFDEnvironmentKey, strconv.Itoa(int(respR.Fd())))

	_, err = respW.WriteString(`{"host_response":{"id":"h1","ok":true,"result":{"links":["a","b"]}}}` + "\n")
	if err != nil {
		t.Fatalf("write host response: %v", err)
	}

	var out bytes.Buffer
	host, closeHost := NewHostClientFromEnv(&out)
	defer closeHost()

	raw, err := host.RPCCall(context.Background(), "latticenet.vpn-core/nodes", "export", map[string]string{"user_id": "u1"})
	if err != nil {
		t.Fatalf("RPCCall: %v", err)
	}
	if string(raw) != `{"links":["a","b"]}` {
		t.Fatalf("rpc result = %s", raw)
	}

	var env hostCallEnvelope
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &env); err != nil {
		t.Fatalf("decode host call: %v output=%s", err, out.String())
	}
	if env.HostCall.ID != "h1" || env.HostCall.Method != HostMethodRPCCall {
		t.Fatalf("host call envelope = %+v", env.HostCall)
	}
	params, ok := env.HostCall.Params.(map[string]any)
	if !ok {
		t.Fatalf("params type = %T", env.HostCall.Params)
	}
	if params["service"] != "latticenet.vpn-core/nodes" || params["method"] != "export" {
		t.Fatalf("rpc params = %+v", params)
	}
}

func TestHostClientTypedMethods(t *testing.T) {
	responses := strings.Join([]string{
		`{"host_response":{"id":"h1","ok":true,"result":{"status_code":200,"body_base64":"` + base64.StdEncoding.EncodeToString([]byte("public")) + `"}}}`,
		`{"host_response":{"id":"h2","ok":true,"result":{"status_code":201,"header":{"X-Test":"1"},"body_base64":"` + base64.StdEncoding.EncodeToString([]byte("created")) + `"}}}`,
		`{"host_response":{"id":"h3","ok":true,"result":{"ok":true,"value_base64":"` + base64.StdEncoding.EncodeToString([]byte("stored")) + `"}}}`,
		`{"host_response":{"id":"h4","ok":true,"result":{}}}`,
		`{"host_response":{"id":"h5","ok":true,"result":{}}}`,
		`{"host_response":{"id":"h6","ok":true,"result":{"ok":true,"value_base64":"` + base64.StdEncoding.EncodeToString([]byte("secret")) + `"}}}`,
		`{"host_response":{"id":"h7","ok":true,"result":{}}}`,
		`{"host_response":{"id":"h8","ok":true,"result":{}}}`,
		`{"host_response":{"id":"h9","ok":true,"result":{}}}`,
	}, "\n") + "\n"
	var out bytes.Buffer
	host := NewHostClient(HostClientOptions{Output: &out, Responses: strings.NewReader(responses)})

	publicResp, err := host.HTTPDo(context.Background(), HTTPRequest{
		Method: "GET",
		URL:    "https://example.com/sub",
	})
	if err != nil {
		t.Fatalf("HTTPDo: %v", err)
	}
	if publicResp.StatusCode != 200 || string(publicResp.Body) != "public" {
		t.Fatalf("public http response = %+v body=%q", publicResp, publicResp.Body)
	}
	httpResp, err := host.HTTPOperatorDo(context.Background(), HTTPRequest{
		Method: "POST",
		URL:    "https://127.0.0.1/sub",
		Header: map[string]string{"Content-Type": "application/json"},
		Body:   []byte(`{"ok":true}`),
	})
	if err != nil {
		t.Fatalf("HTTPOperatorDo: %v", err)
	}
	if httpResp.StatusCode != 201 || string(httpResp.Body) != "created" || httpResp.Header["X-Test"] != "1" {
		t.Fatalf("http response = %+v body=%q", httpResp, httpResp.Body)
	}
	value, ok, err := host.KVGet(context.Background(), "state")
	if err != nil || !ok || string(value) != "stored" {
		t.Fatalf("KVGet: value=%q ok=%v err=%v", value, ok, err)
	}
	if err := host.KVPut(context.Background(), "state", []byte("next")); err != nil {
		t.Fatalf("KVPut: %v", err)
	}
	if err := host.NotifySend(context.Background(), "done", "conversion complete"); err != nil {
		t.Fatalf("NotifySend: %v", err)
	}
	secret, ok, err := host.SecretGetString(context.Background(), "endpoint")
	if err != nil || !ok || secret != "secret" {
		t.Fatalf("SecretGetString: value=%q ok=%v err=%v", secret, ok, err)
	}
	if err := host.SecretPutString(context.Background(), "endpoint", "next-secret"); err != nil {
		t.Fatalf("SecretPutString: %v", err)
	}
	if err := host.SecretDelete(context.Background(), "endpoint"); err != nil {
		t.Fatalf("SecretDelete: %v", err)
	}
	if err := host.LogWrite(context.Background(), LogEntry{Level: "info", Message: "done", Fields: map[string]string{"phase": "test"}}); err != nil {
		t.Fatalf("LogWrite: %v", err)
	}

	for _, method := range []string{
		HostMethodHTTPDo,
		HostMethodHTTPOperatorDo,
		HostMethodKVGet,
		HostMethodKVPut,
		HostMethodNotifySend,
		HostMethodSecretGet,
		HostMethodSecretPut,
		HostMethodSecretDelete,
		HostMethodLogWrite,
	} {
		if !strings.Contains(out.String(), `"method":"`+method+`"`) {
			t.Fatalf("missing host call method %s in output:\n%s", method, out.String())
		}
	}
}

func TestHostClientSurfacesHostResponseFailure(t *testing.T) {
	host := NewHostClient(HostClientOptions{
		Output:    io.Discard,
		Responses: strings.NewReader(`{"host_response":{"id":"h1","ok":false,"error":"permission denied"}}` + "\n"),
	})
	if _, _, err := host.KVGet(context.Background(), "state"); err == nil || !strings.Contains(err.Error(), "kv.get: permission denied") {
		t.Fatalf("expected host error to include method and message, got %v", err)
	}
}

func TestManifestTypesPreserveStringAndTypedInterfaceMethods(t *testing.T) {
	manifest, err := DecodeManifest([]byte(`{
		"schema":"lattice.plugin.manifest.v2",
		"id":"example.plugin",
		"name":"Example",
		"type":"system",
		"capabilities":["rpc:call"],
		"version":"0.1.0-alpha.1",
		"bundle":{"format":"tar+gzip","digest_sha256":"abc"},
		"runtime":{"protocol":"stdio-json-v1","entrypoints":{"linux/amd64":"bin/plugin"}},
		"compatibility":{"server":">=0.2.0","dashboard_host":">=0.2.0","runtime_protocol":"stdio-json-v1"},
		"min_server":">=0.3.0",
		"interfaces":[
			{"service":"example.plugin/legacy","methods":["list"],"scopes":["proxy:read"]},
			{"service":"example.plugin/items","methods":[{"name":"convert","effect":"write","scopes":["substore:admin"],"operator_target_fields":["base_url"],"budget":{"timeout_ms":10000,"stdout_bytes":2097152,"stderr_bytes":65536,"host_calls":0}}],"backing":"runtime"}
		]
	}`))
	if err != nil {
		t.Fatalf("DecodeManifest: %v", err)
	}
	if manifest.MinServer != ">=0.3.0" {
		t.Fatalf("min_server = %q", manifest.MinServer)
	}
	legacy, ok := manifest.InterfaceFor("example.plugin/legacy")
	if !ok || legacy.TypedMethods() {
		t.Fatalf("legacy interface = %+v ok=%v", legacy, ok)
	}
	if scopes, ok := legacy.EffectiveMethodScopes("list"); !ok || len(scopes) != 1 || scopes[0] != "proxy:read" {
		t.Fatalf("legacy scopes = %+v ok=%v", scopes, ok)
	}
	typed, ok := manifest.InterfaceFor("example.plugin/items")
	if !ok || !typed.TypedMethods() || typed.EffectiveBacking() != BackingRuntime {
		t.Fatalf("typed interface = %+v ok=%v", typed, ok)
	}
	method, ok := typed.MethodContract("convert")
	if !ok || method.Budget == nil || method.Budget.StdoutBytes != 2<<20 || len(method.OperatorTargetFields) != 1 {
		t.Fatalf("method contract = %+v ok=%v", method, ok)
	}

	raw, err := json.Marshal(manifest.Interfaces)
	if err != nil {
		t.Fatalf("marshal interfaces: %v", err)
	}
	if !strings.Contains(string(raw), `"methods":["list"]`) {
		t.Fatalf("string methods did not round-trip: %s", raw)
	}
	if !strings.Contains(string(raw), `"budget":{"timeout_ms":10000,"stdout_bytes":2097152,"stderr_bytes":65536,"host_calls":0}`) {
		t.Fatalf("typed budget did not round-trip: %s", raw)
	}
}

func TestRuntimeProtocolStdioJSONV2StrictFrames(t *testing.T) {
	for _, proto := range []string{"stdio-json-v2"} {
		if proto == RuntimeProtocolStdioJSONV1 {
			t.Fatal("v2 must not alias v1")
		}
	}
}

func TestServeV2RejectsReusedInvocationWithoutDispatch(t *testing.T) {
	input := strings.NewReader(`{"protocol":2,"kind":"invoke","generation":9,"invocation_id":"same","request":{"method":"x"}}
{"protocol":2,"kind":"invoke","generation":9,"invocation_id":"same","request":{"method":"x"}}
`)
	var out bytes.Buffer
	calls := 0
	rt := &Runtime{In: input, Out: &out}
	err := rt.ServeV2(context.Background(), HandlerFunc(func(context.Context, Request, *HostClient) Response {
		calls++
		return Response{OK: true}
	}), 9)
	if err == nil || !strings.Contains(err.Error(), "duplicate invocation_id") {
		t.Fatalf("expected duplicate rejection, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("duplicate dispatched %d times", calls)
	}
}

func TestServeV2RejectsDuplicateJSONKeys(t *testing.T) {
	var out bytes.Buffer
	rt := &Runtime{In: strings.NewReader(`{"protocol":2,"protocol":2,"kind":"invoke","generation":1,"invocation_id":"i","request":{}}
`), Out: &out}
	if err := rt.ServeV2(context.Background(), HandlerFunc(func(context.Context, Request, *HostClient) Response { t.Fatal("dispatched"); return Response{} }), 1); err == nil {
		t.Fatal("duplicate frame accepted")
	}
}

func TestStrictHostCallUsesOuterCorrelationOnly(t *testing.T) {
	var out bytes.Buffer
	h := NewInvocationHostClient(HostClientOptions{Output: &out, Responses: io.NopCloser(strings.NewReader(`{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}}
`))}, 1, "i")
	if _, _, err := h.KVGet(context.Background(), "k"); err != nil {
		t.Fatalf("canonical response rejected: %v", err)
	}
	line := out.String()
	if strings.Contains(line, `"generation":1,"invocation_id":"i","method"`) {
		t.Fatalf("nested correlation duplicated: %s", line)
	}
}

func TestStrictHostResponseRejectsWrongOuterCorrelation(t *testing.T) {
	h := NewInvocationHostClient(HostClientOptions{Output: io.Discard, Responses: io.NopCloser(strings.NewReader(`{"protocol":2,"kind":"host_response","generation":2,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}}
`))}, 1, "i")
	if _, _, err := h.KVGet(context.Background(), "k"); err == nil {
		t.Fatal("wrong outer generation accepted")
	}
}

func TestStrictHostRejectsNonClosableReaderWithoutOutput(t *testing.T) {
	var out bytes.Buffer
	h := NewInvocationHostClient(HostClientOptions{Output: &out, Responses: strings.NewReader(`{}`)}, 1, "i")
	if _, _, err := h.KVGet(context.Background(), "k"); err == nil {
		t.Fatal("nonclosable strict host accepted")
	}
	if out.Len() != 0 {
		t.Fatal("nonclosable strict host emitted bytes")
	}
}

func TestStrictHostResponseHostileMatrix(t *testing.T) {
	base := `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}}`
	for _, raw := range []string{
		`{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_call_id":"h2","host_response":{"id":"h1","ok":true,"result":{}}}`,
		`{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","extra":1,"host_response":{"id":"h1","ok":true,"result":{}}}`,
		`{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true}}`,
		base + ` {}`,
	} {
		var env strictHostResponseEnvelope
		if err := strictDecodeFrame([]byte(raw), &env); err == nil && env.HostResponse.OK != nil && env.HostResponse.Result != nil {
			t.Fatalf("hostile response accepted: %s", raw)
		}
	}
}

func TestStrictHostCallHostileActual(t *testing.T) {
	cases := []struct{ name, raw string }{
		{"duplicate_root", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_call_id":"h2","host_response":{"id":"h1","ok":true,"result":{}}}`},
		{"unknown_root", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","x":1,"host_response":{"id":"h1","ok":true,"result":{}}}`},
		{"missing_nested_result", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true}}`},
		{"wrong_generation", `{"protocol":2,"kind":"host_response","generation":2,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}}`},
		{"missing_protocol", `{"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}}`},
		{"missing_kind", `{"protocol":2,"generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}}`},
		{"missing_generation", `{"protocol":2,"kind":"host_response","invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}}`},
		{"missing_invocation", `{"protocol":2,"kind":"host_response","generation":1,"host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}}`},
		{"missing_call_id", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_response":{"id":"h1","ok":true,"result":{}}}`},
		{"wrong_call_id", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"bad","host_response":{"id":"h1","ok":true,"result":{}}}`},
		{"missing_nested_id", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"ok":true,"result":{}}}`},
		{"null_nested_ok", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":null,"result":{}}}`},
		{"unknown_nested", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{},"x":1}}`},
		{"duplicate_nested", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","id":"h1","ok":true,"result":{}}}`},
		{"missing_host_response", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1"}`},
		{"null_host_response", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":null}`},
		{"missing_nested_ok", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","result":{}}}`},
		{"wrong_invocation", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"wrong","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}}`},
		{"wrong_nested_id", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"wrong","ok":true,"result":{}}}`},
		{"union_result_error", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":false,"error":"x","result":{}}}`},
		{"failure_result_present", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":false,"error":"x","result":{}}}`},
		{"success_result_null", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":null}}`},
		{"success_error_null", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{},"error":null}}`},
		{"success_error_nonempty", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{},"error":"bad"}}`},
		{"failure_error_empty", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":false,"error":""}}`},
		{"failure_error_null", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":false,"error":null}}`},
		{"failure_error_nonstring", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":false,"error":3}}`},
		{"failure_result_null", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":false,"error":"x","result":null}}`},
		{"null_protocol", `{"protocol":null,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}}`},
		{"null_kind", `{"protocol":2,"kind":null,"generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}}`},
		{"null_generation", `{"protocol":2,"kind":"host_response","generation":null,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}}`},
		{"null_invocation", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":null,"host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}}`},
		{"null_call_id", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":null,"host_response":{"id":"h1","ok":true,"result":{}}}`},
		{"null_nested_id", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":null,"ok":true,"result":{}}}`},
		{"missing_failure_error", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":false}}`},
		{"wrong_protocol", `{"protocol":1,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}}`},
		{"wrong_kind", `{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}}`},
		{"trailing", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}} trailing`},
		{"oversize", `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{"x":"` + strings.Repeat("x", DefaultMaxHostResponseBytes) + `"}}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) { assertHostCallRejected(t, tc.raw) })
	}
}

func assertHostCallRejected(t *testing.T, raw string) {
	t.Helper()
	var out bytes.Buffer
	h := NewInvocationHostClient(HostClientOptions{Output: &out, Responses: io.NopCloser(strings.NewReader(raw + "\n"))}, 1, "i")
	if _, _, err := h.KVGet(context.Background(), "k"); err == nil {
		t.Fatal("hostile response accepted")
	}
	if out.Len() == 0 {
		t.Fatal("expected attempted call")
	}
}

func TestStrictHostCallErrorWithoutResult(t *testing.T) {
	h := NewInvocationHostClient(HostClientOptions{Output: io.Discard, Responses: io.NopCloser(strings.NewReader(`{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":false,"error":"denied"}}
`))}, 1, "i")
	if _, _, err := h.KVGet(context.Background(), "k"); err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("error=%v", err)
	}
}

func TestV1HostCallWireExact(t *testing.T) {
	var out bytes.Buffer
	h := NewHostClient(HostClientOptions{Output: &out, Responses: strings.NewReader(`{"host_response":{"id":"h1","ok":true,"result":{}}}
`)})
	if _, _, err := h.KVGet(context.Background(), "k"); err != nil {
		t.Fatal(err)
	}
	want := `{"host_call":{"id":"h1","method":"kv.get","params":{"key":"k"}}}` + "\n"
	if out.String() != want {
		t.Fatalf("v1 wire=%q want %q", out.String(), want)
	}
}

func TestCancelledHostCallAbortsAndLateCallIsSilent(t *testing.T) {
	out := &lockedTestWriter{call: make(chan struct{}, 1)}
	pr, pw := io.Pipe()
	h := NewInvocationHostClient(HostClientOptions{Output: out, Responses: pr}, 1, "i")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, _, err := h.KVGet(ctx, "k"); done <- err }()
	<-out.call
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancelled call hung")
	}
	h.Expire()
	before := out.Len()
	if _, _, err := h.KVGet(context.Background(), "late"); err == nil {
		t.Fatal("late call accepted")
	}
	if out.Len() != before {
		t.Fatal("late call emitted bytes")
	}
	_ = pw.Close()
}

func TestCancelAfterHostWritePoisonsAndPreventsReuse(t *testing.T) {
	pr, _ := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	out := &cancelAfterWriteWriter{cancel: cancel}
	h := NewInvocationHostClient(HostClientOptions{Output: out, Responses: pr}, 1, "i")
	if _, _, err := h.KVGet(ctx, "k"); err == nil {
		t.Fatal("cancelled call succeeded")
	}
	before := out.Len()
	if _, _, err := h.KVGet(context.Background(), "late"); err == nil {
		t.Fatal("poisoned transport reused")
	}
	if out.Len() != before {
		t.Fatal("late call emitted")
	}
}

func TestCanonicalV2GoldenFrames(t *testing.T) {
	b, err := os.ReadFile("testdata/stdio-json-v2-runtime-ready.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 7 {
		t.Fatalf("golden lines=%d", len(lines))
	}
	if strings.Contains(string(b), `"generation":7,"invocation_id":"inv-1","method"`) {
		t.Fatal("nested correlation in golden")
	}
	if !strings.Contains(lines[2], `"kind":"host_call"`) || !strings.Contains(lines[3], `"kind":"host_response"`) {
		t.Fatal("missing host frames")
	}
}

func TestRuntimeGoldenHasExactLifecycleKinds(t *testing.T) {
	var out bytes.Buffer
	var stderr bytes.Buffer
	rt := &Runtime{In: strings.NewReader(`{"protocol":2,"kind":"invoke","generation":7,"invocation_id":"inv-1","request":{}}
`), Out: &out, Err: &stderr}
	if err := rt.ServeV2(context.Background(), HandlerFunc(func(context.Context, Request, *HostClient) Response { return Response{OK: true} }), 7); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 || !strings.Contains(lines[0], `"runtime_ready"`) || !strings.Contains(lines[1], `"invoke_result"`) || !strings.Contains(lines[2], `"stderr_complete"`) || !strings.Contains(lines[3], `"invoke_ready"`) {
		t.Fatalf("lifecycle=%q", out.String())
	}
	if stderr.String() != StderrCompleteMarkerPrefix+"7 inv-1\n" {
		t.Fatalf("stderr marker=%q", stderr.String())
	}
}

func TestRuntimeGoldenExactLifecycleOutput(t *testing.T) {
	golden, err := os.ReadFile("testdata/stdio-json-v2-runtime-ready.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(golden)), "\n")
	if len(lines) < 6 {
		t.Fatal("short golden")
	}
	var out bytes.Buffer
	in := strings.NewReader(lines[1] + "\n")
	rt := &Runtime{In: in, Out: &out}
	if err := rt.ServeV2(context.Background(), HandlerFunc(func(context.Context, Request, *HostClient) Response { return Response{OK: true} }), 7); err != nil {
		t.Fatal(err)
	}
	want := lines[0] + "\n" + lines[4] + "\n" + lines[5] + "\n" + lines[6] + "\n"
	if out.String() != want {
		t.Fatalf("generated lifecycle=%q want=%q", out.String(), want)
	}
}

func TestRuntimeGoldenHostKVExact(t *testing.T) {
	g, err := os.ReadFile("testdata/stdio-json-v2-runtime-ready.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(g)), "\n")
	pr, pw := io.Pipe()
	var out bytes.Buffer
	host := NewHostClient(HostClientOptions{Output: &out, Responses: pr})
	rt := &Runtime{In: strings.NewReader(lines[1] + "\n"), Out: &out, Host: host}
	done := make(chan error, 1)
	callErr := make(chan error, 1)
	go func() {
		done <- rt.ServeV2(context.Background(), HandlerFunc(func(ctx context.Context, _ Request, h *HostClient) Response {
			_, err := h.Call(ctx, "kv.get", map[string]any{"key": "k"})
			callErr <- err
			return Response{OK: true}
		}), 7)
	}()
	_, _ = io.WriteString(pw, lines[3]+"\n")
	if err := <-callErr; err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(got) != 5 || strings.Join(got, "\n")+"\n" != lines[0]+"\n"+lines[2]+"\n"+lines[4]+"\n"+lines[5]+"\n"+lines[6]+"\n" {
		t.Fatalf("unexpected output %q", out.String())
	}
}

func TestServeV2NonclosableHostFailsFacadeClosed(t *testing.T) {
	var out bytes.Buffer
	h := NewHostClient(HostClientOptions{Output: &out, Responses: strings.NewReader(`{}`)})
	rt := &Runtime{In: strings.NewReader(`{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"i","request":{}}
`), Out: &out, Host: h}
	if err := rt.ServeV2(context.Background(), HandlerFunc(func(ctx context.Context, _ Request, host *HostClient) Response {
		if _, _, err := host.KVGet(ctx, "k"); err == nil {
			t.Fatal("nonclosable host accepted")
		}
		return Response{OK: true}
	}), 1); err != nil {
		t.Fatal(err)
	}
}

func TestServeV2RejectsMismatchedHostOutput(t *testing.T) {
	var hostOut, runtimeOut bytes.Buffer
	h := NewHostClient(HostClientOptions{Output: &hostOut, Responses: io.NopCloser(strings.NewReader(`{}\n`))})
	rt := &Runtime{In: strings.NewReader(`{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"i","request":{}}\n`), Out: &runtimeOut, Host: h}
	if err := rt.ServeV2(context.Background(), HandlerFunc(func(context.Context, Request, *HostClient) Response { return Response{OK: true} }), 1); err == nil {
		t.Fatal("mismatched host output accepted")
	}
	if runtimeOut.Len() != 0 {
		t.Fatalf("runtime_ready emitted before mismatch rejection: %q", runtimeOut.String())
	}
}

func TestHostClientQueuedCancelDoesNotPoisonActiveExchange(t *testing.T) {
	pr, pw := io.Pipe()
	out := lockedTestWriter{call: make(chan struct{})}
	h := NewInvocationHostClient(HostClientOptions{Output: &out, Responses: pr}, 1, "inv")
	aDone := make(chan error, 1)
	go func() { _, err := h.Call(context.Background(), "kv.get", map[string]any{"key": "a"}); aDone <- err }()
	select {
	case <-out.call:
	case <-time.After(time.Second):
		t.Fatal("first host_call not emitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	bDone := make(chan error, 1)
	go func() { _, err := h.Call(ctx, "kv.get", map[string]any{"key": "b"}); bDone <- err }()
	cancel()
	if err := <-bDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("queued call error=%v", err)
	}
	before := out.Len()
	_, _ = io.WriteString(pw, `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"inv","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{"value":"a"}}}`+"\n")
	if err := <-aDone; err != nil {
		t.Fatalf("active call failed after queued cancel: %v", err)
	}
	h.Expire()
	if _, err := h.Call(context.Background(), "kv.get", map[string]any{"key": "late"}); !errors.Is(err, ErrHostClientExpired) {
		t.Fatalf("late call error=%v", err)
	}
	if out.Len() != before {
		t.Fatalf("late call emitted bytes: before=%d after=%d", before, out.Len())
	}
}

func TestNewInvocationHostClientRejectsZeroCorrelation(t *testing.T) {
	for _, tc := range []struct {
		gen uint64
		id  string
	}{{0, "inv"}, {1, ""}} {
		pr, _ := io.Pipe()
		var out bytes.Buffer
		h := NewInvocationHostClient(HostClientOptions{Output: &out, Responses: pr}, tc.gen, tc.id)
		if h.Available() {
			t.Fatalf("zero correlation accepted: gen=%d id=%q", tc.gen, tc.id)
		}
		if _, err := h.Call(context.Background(), "kv.get", map[string]any{"key": "k"}); err == nil {
			t.Fatal("zero correlation call unexpectedly succeeded")
		}
		if out.Len() != 0 {
			t.Fatalf("zero correlation emitted %d bytes", out.Len())
		}
	}
}

func TestDecodeInvokeV2HostileMatrix(t *testing.T) {
	base := `{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"i","request":{}}`
	for _, tc := range []struct{ name, raw string }{
		{"unknown", `{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"i","request":{},"x":1}`},
		{"missing", `{"protocol":2,"kind":"invoke","generation":1,"request":{}}`},
		{"null", `{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"i","request":null}`},
		{"trailing", base + ` {}`},
		{"wrong_generation", `{"protocol":2,"kind":"invoke","generation":2,"invocation_id":"i","request":{}}`},
		{"wrong_protocol", `{"protocol":1,"kind":"invoke","generation":1,"invocation_id":"i","request":{}}`},
		{"wrong_kind", `{"protocol":2,"kind":"ready","generation":1,"invocation_id":"i","request":{}}`},
		{"zero_generation", `{"protocol":2,"kind":"invoke","generation":0,"invocation_id":"i","request":{}}`},
		{"nested_duplicate", `{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"i","request":{"x":1,"x":2}}`},
		{"duplicate", `{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"i","invocation_id":"j","request":{}}`},
		{"oversize", `{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"i","request":{"blob":"` + strings.Repeat("x", DefaultMaxRequestBytes) + `"}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeInvokeV2([]byte(tc.raw), 1); err == nil {
				t.Fatal("accepted hostile frame")
			}
		})
	}
}

func TestServeV2AllowsNilHost(t *testing.T) {
	var out bytes.Buffer
	rt := &Runtime{In: strings.NewReader(`{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"i","request":{}}
`), Out: &out}
	if err := rt.ServeV2(context.Background(), HandlerFunc(func(_ context.Context, _ Request, host *HostClient) Response {
		if host == nil {
			t.Fatal("expected fail-closed host facade")
		}
		if _, _, err := host.KVGet(context.Background(), "x"); err == nil {
			t.Fatal("nil transport should fail closed")
		}
		return Response{OK: true}
	}), 1); err != nil {
		t.Fatal(err)
	}
}

func TestServeV2TwoInvocationsReuseRuntimeTransport(t *testing.T) {
	input := strings.NewReader(`{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"a","request":{}}
{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"b","request":{}}
`)
	var out bytes.Buffer
	pr, pw := io.Pipe()
	host := NewHostClient(HostClientOptions{Output: &out, Responses: pr})
	rt := &Runtime{In: input, Out: &out, Host: host}
	if err := rt.ServeV2(context.Background(), HandlerFunc(func(context.Context, Request, *HostClient) Response { return Response{OK: true} }), 1); err != nil {
		t.Fatal(err)
	}
	if strings.Count(out.String(), `"kind":"invoke_ready"`) != 2 {
		t.Fatalf("ready count=%d", strings.Count(out.String(), `"kind":"invoke_ready"`))
	}
	_ = pw.Close()
}

type lockedTestWriter struct {
	mu   sync.Mutex
	b    bytes.Buffer
	call chan struct{}
	once sync.Once
}

type cancelAfterWriteWriter struct {
	mu     sync.Mutex
	b      bytes.Buffer
	cancel context.CancelFunc
	once   sync.Once
}

func (w *cancelAfterWriteWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	n, _ := w.b.Write(p)
	w.mu.Unlock()
	w.once.Do(w.cancel)
	return n, nil
}
func (w *cancelAfterWriteWriter) Len() int { w.mu.Lock(); defer w.mu.Unlock(); return w.b.Len() }

func (w *lockedTestWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, _ := w.b.Write(p)
	if bytes.Contains(p, []byte(`"kind":"host_call"`)) {
		w.once.Do(func() { close(w.call) })
	}
	return n, nil
}
func (w *lockedTestWriter) Snapshot() string { w.mu.Lock(); defer w.mu.Unlock(); return w.b.String() }
func (w *lockedTestWriter) Len() int         { w.mu.Lock(); defer w.mu.Unlock(); return w.b.Len() }

func TestServeV2HostCallResponsePrecedesReady(t *testing.T) {
	input := strings.NewReader(`{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"a","request":{}}
`)
	out := &lockedTestWriter{call: make(chan struct{}, 1)}
	pr, pw := io.Pipe()
	host := NewHostClient(HostClientOptions{Output: out, Responses: pr})
	started := make(chan struct{})
	done := make(chan error, 1)
	rt := &Runtime{In: input, Out: out, Host: host}
	go func() {
		done <- rt.ServeV2(context.Background(), HandlerFunc(func(ctx context.Context, _ Request, h *HostClient) Response {
			close(started)
			_, _, err := h.KVGet(ctx, "k")
			return Response{OK: err == nil}
		}), 1)
	}()
	<-started
	<-out.call
	if snap := out.Snapshot(); strings.Contains(snap, `"kind":"invoke_result"`) || strings.Contains(snap, `"kind":"invoke_ready"`) {
		t.Fatal("terminal frame emitted before response")
	}
	select {
	case <-done:
		t.Fatal("runtime completed before response")
	default:
	}
	if _, err := io.WriteString(pw, `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"a","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}}`+"\n"); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	snap := out.Snapshot()
	if strings.Index(snap, `"kind":"invoke_result"`) > strings.Index(snap, `"kind":"invoke_ready"`) {
		t.Fatal("ready preceded result")
	}
}

func TestServeV2SpawnedCallBlocksReadyAndRevokesFacade(t *testing.T) {
	input := strings.NewReader(`{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"a","request":{}}
`)
	out := &lockedTestWriter{call: make(chan struct{}, 1)}
	pr, pw := io.Pipe()
	host := NewHostClient(HostClientOptions{Output: out, Responses: pr})
	var captured *HostClient
	done := make(chan error, 1)
	rt := &Runtime{In: input, Out: out, Host: host}
	go func() {
		done <- rt.ServeV2(context.Background(), HandlerFunc(func(ctx context.Context, _ Request, h *HostClient) Response {
			captured = h
			go func() { _, _, _ = h.KVGet(ctx, "k") }()
			<-out.call
			return Response{OK: true}
		}), 1)
	}()
	<-out.call
	snap := out.Snapshot()
	if strings.Contains(snap, `"invoke_result"`) || strings.Contains(snap, `"invoke_ready"`) {
		t.Fatal("terminal output before response")
	}
	_, _ = io.WriteString(pw, `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"a","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}}`+"\n")
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	snap = out.Snapshot()
	if strings.Index(snap, `"invoke_result"`) > strings.Index(snap, `"invoke_ready"`) {
		t.Fatal("ready before result")
	}
	before := out.Len()
	if _, _, err := captured.KVGet(context.Background(), "late"); err == nil {
		t.Fatal("late facade accepted")
	}
	if out.Len() != before {
		t.Fatal("late facade emitted")
	}
}

func FuzzV2Session(f *testing.F) {
	f.Add("invoke", uint64(1), "i")
	f.Add("invoke_result", uint64(1), "i")
	f.Fuzz(func(t *testing.T, kind string, generation uint64, invocation string) {
		s := NewV2Session(1)
		_ = s.Accept(kind, generation, invocation)
	})
}

func FuzzStrictV2Decoder(f *testing.F) {
	f.Add([]byte(`{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"i","request":{}}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		frame, err := decodeInvokeV2(raw, 1)
		if err == nil && (frame.Protocol != 2 || frame.Kind != "invoke" || frame.Generation != 1 || frame.InvocationID == "" || frame.Request == nil) {
			t.Fatalf("semantic decoder accepted invalid frame")
		}
	})
}

func FuzzStrictHostResponseValidation(f *testing.F) {
	valid := []byte(`{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":{}}}`)
	f.Add(valid)
	f.Add([]byte(`{"":0,"":1}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		const maxFuzzPayloadBytes = DefaultMaxHostResponseBytes / 4
		payload := json.RawMessage(`{"x":1}`)
		var semantic any
		if len(raw) <= maxFuzzPayloadBytes && json.Valid(raw) && json.Unmarshal(raw, &semantic) == nil {
			canonical, err := json.Marshal(semantic)
			if err != nil {
				t.Fatal(err)
			}
			if len(canonical) <= maxFuzzPayloadBytes {
				payload = json.RawMessage(canonical)
			}
		}
		base := string(payload)
		for _, hostile := range []string{
			`{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","protocol":2,"host_response":{"id":"h1","ok":true,"result":` + base + `}}`,
			`{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","unknown":1,"host_response":{"id":"h1","ok":true,"result":` + base + `}}`,
			`{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":` + base + `,"unknown":1}}`,
			`{"protocol":null,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":` + base + `}}`,
			`{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"wrong","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":` + base + `}}`,
			`{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"wrong","ok":true,"result":` + base + `}}`,
			`{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":false}}`,
		} {
			assertHostCallRejected(t, hostile)
		}
		var out bytes.Buffer
		success := `{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":` + string(payload) + `}}` + "\n"
		h := NewInvocationHostClient(HostClientOptions{Output: &out, Responses: io.NopCloser(strings.NewReader(success))}, 1, "i")
		result, err := h.Call(context.Background(), "kv.get", map[string]any{"key": "k"})
		if err != nil {
			t.Fatalf("canonical success rejected: %v", err)
		}
		if !bytes.Equal(result, payload) {
			t.Fatalf("result=%s want=%s", result, payload)
		}
		if len(result) == 0 || out.Len() == 0 {
			t.Fatal("successful strict response lacked result or host_call")
		}
	})
}

func TestStrictHostResponseFuzzSeeds(t *testing.T) {
	for _, raw := range []string{`{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"i","host_call_id":"h1","host_response":{"id":"h1","ok":false}}`, `{"protocol":null}`} {
		pr := io.NopCloser(strings.NewReader(raw + "\n"))
		h := NewInvocationHostClient(HostClientOptions{Output: io.Discard, Responses: pr}, 1, "i")
		if _, err := h.Call(context.Background(), "kv.get", map[string]any{"key": "k"}); err == nil {
			t.Fatalf("hostile seed accepted: %s", raw)
		}
	}
}
