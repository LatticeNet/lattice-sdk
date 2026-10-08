package model

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestSubscriptionMethodNewFieldWireNames(t *testing.T) {
	fetched := time.Date(2026, 10, 8, 3, 0, 0, 0, time.UTC)
	fetch := FetchReply{Raw: "vless://x", Userinfo: "upload=1; download=2; total=3", Flow: &SubscriptionFlow{
		Userinfo: "upload=1; download=2; total=3", WebPageURL: "https://provider.example/account", PlanName: "Pro 200G", FetchedAt: fetched,
	}}
	if got, want := mustJSON(t, fetch), `{"raw":"vless://x","userinfo":"upload=1; download=2; total=3",`+
		`"flow":{"userinfo":"upload=1; download=2; total=3","web_page_url":"https://provider.example/account","plan_name":"Pro 200G","fetched_at":"2026-10-08T03:00:00Z"}}`; got != want {
		t.Fatalf("fetch reply encodes as\n %s\nwant %s", got, want)
	}
	if err := fetch.Validate(); err != nil {
		t.Fatalf("fetch reply refused: %v", err)
	}

	render := RenderReply{ContentType: "application/json", Plan: &SelectionPlan{Kind: SelectionPlanKindNodes, Nodes: []SelectionPlanNode{}}}
	if got, want := mustJSON(t, render), `{"content":"","content_type":"application/json","plan":{"kind":"nodes","nodes":[]}}`; got != want {
		t.Fatalf("render reply with a plan encodes as\n %s\nwant %s", got, want)
	}

	p := testPlaceholder(catalogueLineA, "uuid")
	convert := ConvertRequest{Target: "ClashMeta", Document: &ConvertDocument{Content: "uuid: " + p, Substitutions: map[string]string{p: "c7f3e2a1-9b8d-4c6e-a5f4-3b2a1c0d9e8f"}},
		ResponseChain: []ResponseTransformerStep{{Source: "$content"}}}
	if got, want := mustJSON(t, convert), `{"target":"ClashMeta","document":{"content":"uuid: `+p+`","substitutions":{"`+p+`":"c7f3e2a1-9b8d-4c6e-a5f4-3b2a1c0d9e8f"}},`+
		`"response_chain":[{"source":"$content","enabled":false}]}`; got != want {
		t.Fatalf("convert request encodes as\n %s\nwant %s", got, want)
	}
	nodes := ConvertRequest{Target: "sing-box", Nodes: []json.RawMessage{json.RawMessage(`{"type":"vless"}`)}}
	if got, want := mustJSON(t, nodes), `{"target":"sing-box","nodes":[{"type":"vless"}]}`; got != want {
		t.Fatalf("convert request with nodes encodes as %s", got)
	}

	reply := ConvertReply{Content: "{}", ContentType: "application/json", Target: "sing-box", NodeCount: 1,
		Headers: map[string]string{"plan-name": "Pro"}, Log: []ConvertLogEntry{{Level: ConvertLogInfo, Message: "renamed 3 nodes"}}}
	if got, want := mustJSON(t, reply), `{"content":"{}","content_type":"application/json","target":"sing-box","node_count":1,`+
		`"headers":{"plan-name":"Pro"},"log":[{"level":"info","message":"renamed 3 nodes"}]}`; got != want {
		t.Fatalf("convert reply encodes as\n %s\nwant %s", got, want)
	}
	if err := reply.Validate(); err != nil {
		t.Fatalf("convert reply refused: %v", err)
	}
}

func TestFetchReplyRawBound(t *testing.T) {
	if err := (FetchReply{Raw: strings.Repeat("r", MaxSubscriptionRawBytes)}).Validate(); err != nil {
		t.Fatalf("raw at the bound refused: %v", err)
	}
	if err := (FetchReply{Raw: strings.Repeat("r", MaxSubscriptionRawBytes+1)}).Validate(); err == nil {
		t.Fatal("raw one byte over the bound accepted")
	}
	if err := (FetchReply{}).Validate(); err == nil {
		t.Fatal("empty fetch accepted; an empty raw is a failed fetch")
	}
	for name, flow := range map[string]SubscriptionFlow{
		"http page":       {WebPageURL: "http://provider.example/"},
		"userinfo crlf":   {Userinfo: "upload=1\r\nX-Evil: 1"},
		"userinfo length": {Userinfo: strings.Repeat("u", MaxSubscriptionUserinfoBytes+1)},
		"plan name crlf":  {PlanName: "Pro\nX-Evil: 1"},
	} {
		if err := (FetchReply{Raw: "x", Flow: &flow}).Validate(); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if err := (SubscriptionFlow{Userinfo: strings.Repeat("u", MaxSubscriptionUserinfoBytes)}).Validate(); err != nil {
		t.Fatalf("userinfo at the bound refused: %v", err)
	}
}

func TestSubscriptionWebPageURLChecks(t *testing.T) {
	long := func(n int) string {
		prefix := "https://provider.example/"
		return prefix + strings.Repeat("p", n-len(prefix))
	}
	accepted := []string{
		"https://provider.example/account?tab=usage", "https://203.0.113.30/", "https://[2001:db8::1]:8443/", long(MaxSubscriptionResponseHeaderBytes),
	}
	refused := []string{
		"http://provider.example/", "https://user:pw@provider.example/", "https://user@provider.example/", "javascript:alert(1)",
		"https:provider.example", "//provider.example/", "https://10.0.0.1/", "https://192.168.1.1/", "https://172.16.0.1/",
		"https://127.0.0.1/", "https://[::1]/", "https://[fe80::1]/", "https://169.254.169.254/", "https://100.64.0.1/",
		"https://0.0.0.0/", "https://[::ffff:10.0.0.1]/", "https://[fd00::1]/", "https://224.0.0.1/",
		"https://localhost/", "https://router.local/", "https://db.internal/", "https://intranet/", "https://a.localhost/",
		"https://127.1/", "https://10.1.1/", "https://0x7f.1/", "https://0x7f000001/", "https://017700000001.1/",
		"https://[64:ff9b::a00:1]/", "https://[64:ff9b:1::a00:1]/",
		"https://provider.example/ a", "https://provider.example/\r\nX: y", long(MaxSubscriptionResponseHeaderBytes + 1),
	}
	for _, value := range accepted {
		if err := ValidateSubscriptionWebPageURL(value); err != nil {
			t.Fatalf("%q refused: %v", value, err)
		}
	}
	for _, value := range refused {
		if err := ValidateSubscriptionWebPageURL(value); err == nil {
			t.Fatalf("%q accepted", value)
		}
	}
}

func TestSubscriptionResponseHeaderAllowList(t *testing.T) {
	accepted := map[string]string{
		"Content-Disposition":     `attachment; filename="team"`,
		"profile-update-interval": "1",
		"Profile-Update-Interval": "168",
		"profile-web-page-url":    "https://provider.example/",
		"PLAN-NAME":               strings.Repeat("p", MaxSubscriptionResponseHeaderBytes),
	}
	for name, value := range accepted {
		if err := ValidateSubscriptionResponseHeader(name, value); err != nil {
			t.Fatalf("%s: %q refused: %v", name, value, err)
		}
	}
	refused := []struct{ name, value string }{
		{"subscription-userinfo", "upload=0"}, {"content-type", "text/html"}, {"location", "https://x.example/"},
		{"set-cookie", "a=b"}, {"status", "200"},
		{"profile-update-interval", "0"}, {"profile-update-interval", "169"}, {"profile-update-interval", "2h"},
		{"profile-web-page-url", "http://provider.example/"},
		{"plan-name", ""}, {"plan-name", "Pro\r\nSet-Cookie: a=b"}, {"plan-name", strings.Repeat("p", MaxSubscriptionResponseHeaderBytes+1)},
		{"content-disposition", "attachment\n"},
	}
	for _, h := range refused {
		if err := ValidateSubscriptionResponseHeader(h.name, h.value); err == nil {
			t.Fatalf("%s: %q accepted", h.name, h.value)
		}
	}
}

func TestRenderReplyCarriesADocumentOrAPlan(t *testing.T) {
	plan := &SelectionPlan{Kind: SelectionPlanKindNodes}
	if err := (RenderReply{Content: "x"}).Validate(); err != nil {
		t.Fatalf("document reply refused: %v", err)
	}
	if err := (RenderReply{Plan: plan}).Validate(); err != nil {
		t.Fatalf("plan reply refused: %v", err)
	}
	if err := (RenderReply{}).Validate(); err == nil {
		t.Fatal("empty reply accepted")
	}
	if err := (RenderReply{Content: "x", Plan: plan}).Validate(); err == nil {
		t.Fatal("reply with both a document and a plan accepted")
	}
	if err := (RenderReply{Plan: &SelectionPlan{Kind: "graph"}}).Validate(); err == nil {
		t.Fatal("reply with an invalid plan accepted")
	}
}

func TestConvertRequestInputs(t *testing.T) {
	p := testPlaceholder(catalogueLineA, "uuid")
	node := json.RawMessage(`{"type":"vless"}`)
	cases := []struct {
		name     string
		req      ConvertRequest
		accepted bool
	}{
		{"uris", ConvertRequest{URIs: []string{"vless://a"}, Target: "URI"}, true},
		{"raw", ConvertRequest{Raw: "x", Target: "URI"}, true},
		{"nodes", ConvertRequest{Nodes: []json.RawMessage{node}, Target: "sing-box"}, true},
		{"document without target", ConvertRequest{Document: &ConvertDocument{Content: "uuid: " + p, Substitutions: map[string]string{p: "real"}}}, true},
		{"no input", ConvertRequest{Target: "URI"}, false},
		{"two inputs", ConvertRequest{URIs: []string{"vless://a"}, Nodes: []json.RawMessage{node}, Target: "URI"}, false},
		{"node not an object", ConvertRequest{Nodes: []json.RawMessage{json.RawMessage(`"vless://a"`)}, Target: "URI"}, false},
		{"empty document", ConvertRequest{Document: &ConvertDocument{}}, false},
		{"substitution key not a placeholder", ConvertRequest{Document: &ConvertDocument{Content: "x", Substitutions: map[string]string{"uuid": "real"}}}, false},
		{"empty credential", ConvertRequest{Document: &ConvertDocument{Content: "x", Substitutions: map[string]string{p: ""}}}, false},
		{"credential with a newline", ConvertRequest{Document: &ConvertDocument{Content: "x", Substitutions: map[string]string{p: "real\n  - name: injected"}}}, false},
	}
	for _, c := range cases {
		if err := c.req.Validate(); (err == nil) != c.accepted {
			t.Fatalf("%s: Validate() = %v, want accepted=%v", c.name, err, c.accepted)
		}
	}
	at := ConvertRequest{Target: "URI"}
	for i := 0; i < MaxSubscriptionRecordNodes; i++ {
		at.Nodes = append(at.Nodes, node)
	}
	if err := at.Validate(); err != nil {
		t.Fatalf("convert at %d nodes refused: %v", MaxSubscriptionRecordNodes, err)
	}
	at.Nodes = append(at.Nodes, node)
	if err := at.Validate(); err == nil {
		t.Fatal("convert one node over the bound accepted")
	}
}

func TestResponseChainBounds(t *testing.T) {
	steps := func(n int) []ResponseTransformerStep {
		out := make([]ResponseTransformerStep, n)
		for i := range out {
			out[i] = ResponseTransformerStep{Name: fmt.Sprintf("s%d", i), Source: "$content", Enabled: true}
		}
		return out
	}
	if err := ValidateResponseChain(steps(MaxResponseChainSteps)); err != nil {
		t.Fatalf("%d steps refused: %v", MaxResponseChainSteps, err)
	}
	if err := ValidateResponseChain(steps(MaxResponseChainSteps + 1)); err == nil {
		t.Fatal("one step over the bound accepted")
	}
	// Name, source and arguments together, summed over the steps.
	args := json.RawMessage(`{"k":"v"}`)
	sized := func(total int) []ResponseTransformerStep {
		first := ResponseTransformerStep{Name: "head", Source: strings.Repeat("a", 1000), Arguments: args}
		used := len(first.Name) + len(first.Source) + len(first.Arguments)
		return []ResponseTransformerStep{first, {Source: strings.Repeat("b", total-used)}}
	}
	if err := ValidateResponseChain(sized(MaxResponseChainBytes)); err != nil {
		t.Fatalf("chain at %d bytes refused: %v", MaxResponseChainBytes, err)
	}
	if err := ValidateResponseChain(sized(MaxResponseChainBytes + 1)); err == nil {
		t.Fatal("chain one byte over the bound accepted")
	}
	for name, step := range map[string]ResponseTransformerStep{
		"no source":      {Name: "x"},
		"array args":     {Source: "x", Arguments: json.RawMessage(`["a"]`)},
		"broken args":    {Source: "x", Arguments: json.RawMessage(`{"a":`)},
		"long name":      {Name: strings.Repeat("n", MaxResponseStepNameBytes+1), Source: "x"},
		"name with crlf": {Name: "a\r\nb", Source: "x"},
	} {
		if err := ValidateResponseChain([]ResponseTransformerStep{step}); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if err := ValidateResponseChain([]ResponseTransformerStep{{Name: strings.Repeat("n", MaxResponseStepNameBytes), Source: "x"}}); err != nil {
		t.Fatalf("name at the bound refused: %v", err)
	}
}

func TestConvertRequestEncodedSizeAtTheBound(t *testing.T) {
	req := func(n int) ConvertRequest { return ConvertRequest{Raw: strings.Repeat("r", n), Target: "URI"} }
	overhead := len(mustJSON(t, req(1))) - 1
	raw, err := EncodeConvertRequest(req(MaxConvertRequestBytes - overhead))
	if err != nil || len(raw) != MaxConvertRequestBytes {
		t.Fatalf("request at the bound: %d bytes, %v", len(raw), err)
	}
	if _, err := DecodeConvertRequest(raw); err != nil {
		t.Fatalf("request at the bound did not decode: %v", err)
	}
	if _, err := EncodeConvertRequest(req(MaxConvertRequestBytes - overhead + 1)); err == nil {
		t.Fatal("request one byte over the bound encoded")
	}
	if _, err := DecodeConvertRequest([]byte(mustJSON(t, req(MaxConvertRequestBytes-overhead+1)))); err == nil {
		t.Fatal("request one byte over the bound decoded")
	}
	for name, raw := range map[string]string{
		"duplicate nested key": `{"target":"URI","nodes":[{"server":"a","server":"b"}]}`,
		"unknown field":        `{"target":"URI","uris":["a"],"operators":[]}`,
		"trailing data":        `{"target":"URI","uris":["a"]} x`,
	} {
		if _, err := DecodeConvertRequest([]byte(raw)); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	if MaxConvertRequestBytes > MaxSubscriptionRequestBytes || MaxSelectionPlanBytes > MaxSubscriptionRequestBytes {
		t.Fatal("a convert request or a plan may exceed the subscription request bound")
	}
	if MaxSubscriptionRequestBytes != 8<<20 {
		t.Fatalf("MaxSubscriptionRequestBytes = %d, want 8 MiB", MaxSubscriptionRequestBytes)
	}
}

func TestConvertReplyLogLevels(t *testing.T) {
	if err := (ConvertReply{Content: "x", Log: []ConvertLogEntry{{Level: ConvertLogError, Message: "m"}}}).Validate(); err != nil {
		t.Fatalf("error log refused: %v", err)
	}
	if err := (ConvertReply{Content: "x", Log: []ConvertLogEntry{{Level: "debug"}}}).Validate(); err == nil {
		t.Fatal("unknown log level accepted")
	}
	if err := (ConvertReply{}).Validate(); err == nil {
		t.Fatal("empty convert reply accepted")
	}
}
