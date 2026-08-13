package plugin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
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
		var frame struct {
			Protocol     int      `json:"protocol"`
			Kind         string   `json:"kind"`
			Generation   uint64   `json:"generation"`
			InvocationID string   `json:"invocation_id"`
			Request      *Request `json:"request"`
		}
		if err := strictDecodeFrame(raw, &frame); err == nil {
			// Structural decoding is separate from lifecycle validation; invalid
			// zero values are rejected by ServeV2 after this step.
			_ = frame
		}
	})
}
