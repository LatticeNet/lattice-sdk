package plugin

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

const (
	HostMethodRPCCall        = "rpc.call"
	HostMethodHTTPDo         = "http.do"
	HostMethodHTTPOperatorDo = "http.operator.do"
	HostMethodKVGet          = "kv.get"
	HostMethodKVPut          = "kv.put"
	HostMethodNotifySend     = "notify.send"
	HostMethodLogWrite       = "log.write"
	HostMethodSecretGet      = "secret.get"
	HostMethodSecretPut      = "secret.put"
	HostMethodSecretDelete   = "secret.delete"
	// DefaultMaxHostResponsePayloadBytes is the maximum decoded
	// host_response.result payload.
	DefaultMaxHostResponsePayloadBytes = 4 << 20
	// DefaultMaxHostResponseBytes is the compatibility alias used by
	// HostClientOptions.MaxResponseBytes.
	DefaultMaxHostResponseBytes = DefaultMaxHostResponsePayloadBytes
	// DefaultMaxHostResponseFrameOverheadBytes independently bounds the
	// correlation envelope around a maximum result payload.
	DefaultMaxHostResponseFrameOverheadBytes = 4 << 10
	// DefaultMaxHostResponseFrameBytes excludes the JSONL delimiter.
	DefaultMaxHostResponseFrameBytes = DefaultMaxHostResponseBytes + DefaultMaxHostResponseFrameOverheadBytes
	defaultHostResponseFD            = 3
	hostResponseFDEnvironmentKey     = "LATTICE_HOST_RESPONSE_FD"
)

var ErrHostUnavailable = errors.New("host response fd unavailable")

type HostClient struct {
	output           io.Writer
	responses        *bufio.Scanner
	transport        *hostTransport
	maxResponseBytes int
	maxFrameBytes    int

	leaseMu      sync.Mutex
	pending      sync.WaitGroup
	generation   uint64
	invocationID string
	expired      atomic.Bool
	strict       bool
}

type hostTransport struct {
	output    io.Writer
	responses *bufio.Scanner
	writeMu   sync.Mutex
	exchange  chan struct{}
	nextID    uint64
	closer    io.Closer
	poisoned  atomic.Bool
}

var ErrHostClientExpired = errors.New("invocation host client expired")

type HostClientOptions struct {
	Output           io.Writer
	Responses        io.Reader
	MaxResponseBytes int
}

func NewHostClient(opts HostClientOptions) *HostClient {
	maxResponseBytes := opts.MaxResponseBytes
	if maxResponseBytes <= 0 {
		maxResponseBytes = DefaultMaxHostResponseBytes
	}
	client := &HostClient{
		output:           opts.Output,
		maxResponseBytes: maxResponseBytes,
		maxFrameBytes:    hostResponseFrameLimit(maxResponseBytes),
	}
	if opts.Responses != nil {
		scanner := bufio.NewScanner(opts.Responses)
		scanner.Buffer(make([]byte, 0, 64*1024), scannerCapacity(client.maxFrameBytes))
		client.responses = scanner
	}
	var closer io.Closer
	if c, ok := opts.Responses.(io.Closer); ok {
		closer = c
	}
	client.transport = &hostTransport{output: client.output, responses: client.responses, closer: closer, exchange: make(chan struct{}, 1)}
	client.transport.exchange <- struct{}{}
	return client
}

// NewInvocationHostClient creates a lease-scoped facade. Expire it before the
// worker emits invoke_ready so late plugin calls cannot reach the host.
func NewInvocationHostClient(opts HostClientOptions, generation uint64, invocationID string) *HostClient {
	c := NewHostClient(opts)
	if generation == 0 || !validInvocationID(invocationID) {
		c.output = nil
		c.responses = nil
		c.transport = nil
	}
	if _, ok := opts.Responses.(io.Closer); !ok {
		c.output = nil
		c.responses = nil
		c.transport = nil
	}
	c.generation, c.invocationID = generation, invocationID
	c.strict = true
	return c
}

func (c *HostClient) scoped(generation uint64, invocationID string) *HostClient {
	if c == nil {
		return nil
	}
	return &HostClient{output: c.output, responses: c.responses, transport: c.transport, maxResponseBytes: c.maxResponseBytes, maxFrameBytes: c.maxFrameBytes, generation: generation, invocationID: invocationID, strict: true}
}

func (c *HostClient) scopedTransport(t *hostTransport, generation uint64, invocationID string) *HostClient {
	if c == nil {
		return nil
	}
	if t == nil || t.closer == nil {
		return &HostClient{generation: generation, invocationID: invocationID, strict: true}
	}
	return &HostClient{output: t.output, responses: t.responses, transport: t, maxResponseBytes: c.maxResponseBytes, maxFrameBytes: c.maxFrameBytes, generation: generation, invocationID: invocationID, strict: true}
}

func hostResponseFrameLimit(payloadLimit int) int {
	if payloadLimit <= 0 {
		payloadLimit = DefaultMaxHostResponseBytes
	}
	const overhead = DefaultMaxHostResponseFrameOverheadBytes
	maxInt := int(^uint(0) >> 1)
	if payloadLimit > maxInt-overhead {
		return maxInt
	}
	return payloadLimit + overhead
}

func scannerCapacity(frameLimit int) int {
	maxInt := int(^uint(0) >> 1)
	if frameLimit >= maxInt {
		return maxInt
	}
	return frameLimit + 1
}

func validInvocationID(id string) bool {
	n, err := strconv.ParseInt(id, 10, 64)
	return err == nil && n > 0 && strconv.FormatInt(n, 10) == id
}

func validHostCallID(id string) bool {
	if len(id) < 2 || id[0] != 'h' {
		return false
	}
	n, err := strconv.ParseUint(id[1:], 10, 64)
	return err == nil && n > 0 && "h"+strconv.FormatUint(n, 10) == id
}

func (c *HostClient) Expire() {
	if c != nil {
		c.leaseMu.Lock()
		c.expired.Store(true)
		c.leaseMu.Unlock()
		c.pending.Wait()
	}
}

// Abort revokes admission and poisons the shared response transport to unblock
// a stalled call. It is terminal; normal completion uses Expire.
func (c *HostClient) Abort() {
	if c == nil {
		return
	}
	c.leaseMu.Lock()
	c.expired.Store(true)
	c.leaseMu.Unlock()
	if c.transport != nil {
		c.transport.poisoned.Store(true)
	}
	if c.transport != nil && c.transport.closer != nil {
		_ = c.transport.closer.Close()
	}
}

func NewHostClientFromEnv(output io.Writer) (*HostClient, func()) {
	fd := defaultHostResponseFD
	raw := strings.TrimSpace(os.Getenv(hostResponseFDEnvironmentKey))
	if raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < defaultHostResponseFD {
			return NewHostClient(HostClientOptions{Output: output}), func() {}
		}
		fd = parsed
	}
	file := os.NewFile(uintptr(fd), "lattice-host-response")
	if file == nil {
		return NewHostClient(HostClientOptions{Output: output}), func() {}
	}
	return NewHostClient(HostClientOptions{Output: output, Responses: file}), func() { _ = file.Close() }
}

func (c *HostClient) Available() bool {
	return c != nil && c.output != nil && c.responses != nil
}

func (c *HostClient) Call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	if c == nil || c.output == nil || c.responses == nil {
		return nil, ErrHostUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	c.leaseMu.Lock()
	if c.expired.Load() {
		c.leaseMu.Unlock()
		return nil, ErrHostClientExpired
	}
	if c.transport != nil && c.transport.poisoned.Load() {
		c.leaseMu.Unlock()
		return nil, ErrHostClientExpired
	}
	c.pending.Add(1)
	c.leaseMu.Unlock()
	defer c.pending.Done()

	t := c.transport
	if t == nil {
		t = &hostTransport{output: c.output, responses: c.responses}
		c.transport = t
	}
	select {
	case <-t.exchange:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { t.exchange <- struct{}{} }()
	t.writeMu.Lock()
	if t.nextID == ^uint64(0) {
		t.writeMu.Unlock()
		return nil, fmt.Errorf("host call id exhausted")
	}
	t.nextID++
	id := fmt.Sprintf("h%d", t.nextID)
	if c.expired.Load() {
		t.writeMu.Unlock()
		return nil, ErrHostClientExpired
	}
	var frame any = hostCallEnvelope{HostCall: hostCall{ID: id, Method: method, Params: params}}
	if c.strict {
		if method == "" || params == nil {
			t.writeMu.Unlock()
			return nil, fmt.Errorf("invalid strict host_call payload")
		}
		frame = strictHostCallEnvelope{Protocol: 2, Kind: "host_call", Generation: c.generation, InvocationID: c.invocationID, HostCallID: id, HostCall: strictHostCallPayload{ID: id, Method: method, Params: params}}
	}
	if err := json.NewEncoder(t.output).Encode(frame); err != nil {
		t.writeMu.Unlock()
		return nil, fmt.Errorf("write host_call: %w", err)
	}
	t.writeMu.Unlock()
	if err := ctx.Err(); err != nil {
		c.Abort()
		return nil, err
	}
	type scanResult struct {
		raw []byte
		err error
	}
	results := make(chan scanResult, 1)
	go func() {
		if !t.responses.Scan() {
			if err := t.responses.Err(); err != nil {
				results <- scanResult{err: fmt.Errorf("read host_response: %w", err)}
			} else {
				results <- scanResult{err: errors.New("read host_response: eof")}
			}
			return
		}
		results <- scanResult{raw: append([]byte(nil), t.responses.Bytes()...)}
	}()
	var scanned scanResult
	select {
	case scanned = <-results:
	case <-ctx.Done():
		c.Abort()
		<-results
		return nil, ctx.Err()
	}
	if scanned.err != nil {
		return nil, scanned.err
	}
	if len(scanned.raw) > c.maxFrameBytes {
		return nil, fmt.Errorf("read host_response: frame exceeds limit")
	}
	var env hostResponseEnvelope
	if c.strict {
		var strictEnv strictHostResponseEnvelope
		if err := strictDecodeFrame(scanned.raw, &strictEnv); err != nil {
			return nil, fmt.Errorf("decode host_response: %w", err)
		}
		env.Protocol, env.Kind, env.Generation, env.InvocationID, env.HostCallID = strictEnv.Protocol, strictEnv.Kind, strictEnv.Generation, strictEnv.InvocationID, strictEnv.HostCallID
		if len(strictEnv.HostResponse.ID) == 0 || bytes.Equal(strictEnv.HostResponse.ID, []byte("null")) || len(strictEnv.HostResponse.OK) == 0 || bytes.Equal(strictEnv.HostResponse.OK, []byte("null")) {
			return nil, fmt.Errorf("decode host_response: missing required payload")
		}
		var id string
		var ok bool
		if json.Unmarshal(strictEnv.HostResponse.ID, &id) != nil || id == "" || json.Unmarshal(strictEnv.HostResponse.OK, &ok) != nil {
			return nil, fmt.Errorf("decode host_response: invalid required payload")
		}
		if ok && (len(strictEnv.HostResponse.Result) == 0 || bytes.Equal(strictEnv.HostResponse.Result, []byte("null"))) {
			return nil, fmt.Errorf("decode host_response: missing result")
		}
		if len(strictEnv.HostResponse.Result) > c.maxResponseBytes {
			return nil, fmt.Errorf("decode host_response: result exceeds payload limit")
		}
		if !ok && (len(strictEnv.HostResponse.Error) == 0 || bytes.Equal(strictEnv.HostResponse.Error, []byte("null"))) {
			return nil, fmt.Errorf("decode host_response: invalid failure")
		}
		if !ok && len(strictEnv.HostResponse.Result) > 0 {
			return nil, fmt.Errorf("decode host_response: failure result")
		}
		if !ok {
			var e string
			if json.Unmarshal(strictEnv.HostResponse.Error, &e) != nil || strings.TrimSpace(e) == "" {
				return nil, fmt.Errorf("decode host_response: invalid failure error")
			}
		}
		if ok && len(strictEnv.HostResponse.Error) > 0 {
			return nil, fmt.Errorf("decode host_response: success error")
		}
		var result json.RawMessage
		if len(strictEnv.HostResponse.Result) > 0 {
			result = strictEnv.HostResponse.Result
		}
		var errText string
		if len(strictEnv.HostResponse.Error) > 0 && !bytes.Equal(strictEnv.HostResponse.Error, []byte("null")) {
			if json.Unmarshal(strictEnv.HostResponse.Error, &errText) != nil {
				return nil, fmt.Errorf("decode host_response: invalid error")
			}
		}
		env.HostResponse = hostResponse{ID: id, OK: ok, Result: result, Error: errText}
	} else if err := json.Unmarshal(scanned.raw, &env); err != nil {
		return nil, fmt.Errorf("decode host_response: %w", err)
	}
	if len(env.HostResponse.Result) > c.maxResponseBytes {
		return nil, fmt.Errorf("decode host_response: result exceeds payload limit")
	}
	if !validHostCallID(env.HostResponse.ID) || (env.HostResponse.HostCallID != "" && !validHostCallID(env.HostResponse.HostCallID)) {
		return nil, fmt.Errorf("decode host_response: invalid host call id")
	}
	if env.HostResponse.ID != id {
		return nil, fmt.Errorf("host_response id mismatch: got %q want %q", env.HostResponse.ID, id)
	}
	if env.HostResponse.HostCallID != "" && env.HostResponse.HostCallID != id {
		return nil, fmt.Errorf("host_response host_call_id mismatch: got %q want %q", env.HostResponse.HostCallID, id)
	}
	if c.strict && (env.Protocol != 2 || env.Kind != "host_response" || env.HostCallID != id || env.Generation != c.generation || env.InvocationID != c.invocationID || !validInvocationID(env.InvocationID) || !validHostCallID(env.HostCallID)) {
		return nil, fmt.Errorf("host_response correlation mismatch")
	}
	if !env.HostResponse.OK {
		message := env.HostResponse.Error
		if message == "" {
			message = "host call failed"
		}
		return nil, fmt.Errorf("%s: %s", method, message)
	}
	return append(json.RawMessage(nil), env.HostResponse.Result...), nil
}

type strictHostCallEnvelope struct {
	Protocol     uint64                `json:"protocol"`
	Kind         string                `json:"kind"`
	Generation   uint64                `json:"generation"`
	InvocationID string                `json:"invocation_id"`
	HostCallID   string                `json:"host_call_id"`
	HostCall     strictHostCallPayload `json:"host_call"`
}
type strictHostCallPayload struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Params any    `json:"params"`
}

func strictDecodeFrame(raw []byte, dst any) error {
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("trailing frame data")
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	var walk func() error
	walk = func() error {
		t, err := dec.Token()
		if err != nil {
			return err
		}
		switch d := t.(type) {
		case json.Delim:
			if d == '{' {
				seen := map[string]bool{}
				for dec.More() {
					k, err := dec.Token()
					if err != nil {
						return err
					}
					key := k.(string)
					if seen[key] {
						return fmt.Errorf("duplicate JSON field %q", key)
					}
					seen[key] = true
					if err := walk(); err != nil {
						return err
					}
				}
				_, err = dec.Token()
				return err
			}
			if d == '[' {
				for dec.More() {
					if err := walk(); err != nil {
						return err
					}
				}
				_, err = dec.Token()
				return err
			}
		}
		return nil
	}
	if err := walk(); err != nil {
		return err
	}
	return nil
}

type hostCallEnvelope struct {
	Protocol     uint64   `json:"protocol,omitempty"`
	Kind         string   `json:"kind,omitempty"`
	Generation   uint64   `json:"generation,omitempty"`
	InvocationID string   `json:"invocation_id,omitempty"`
	HostCallID   string   `json:"host_call_id,omitempty"`
	HostCall     hostCall `json:"host_call"`
}

type hostCall struct {
	ID           string `json:"id"`
	HostCallID   string `json:"host_call_id,omitempty"`
	Generation   uint64 `json:"generation,omitempty"`
	InvocationID string `json:"invocation_id,omitempty"`
	Method       string `json:"method"`
	Params       any    `json:"params,omitempty"`
}

type hostResponseEnvelope struct {
	Protocol     uint64       `json:"protocol,omitempty"`
	Kind         string       `json:"kind,omitempty"`
	Generation   uint64       `json:"generation,omitempty"`
	InvocationID string       `json:"invocation_id,omitempty"`
	HostCallID   string       `json:"host_call_id,omitempty"`
	HostResponse hostResponse `json:"host_response"`
}

type strictHostResponseEnvelope struct {
	Protocol     uint64                    `json:"protocol"`
	Kind         string                    `json:"kind"`
	Generation   uint64                    `json:"generation"`
	InvocationID string                    `json:"invocation_id"`
	HostCallID   string                    `json:"host_call_id"`
	HostResponse strictHostResponsePayload `json:"host_response"`
}
type strictHostResponsePayload struct {
	ID     json.RawMessage `json:"id"`
	OK     json.RawMessage `json:"ok"`
	Result json.RawMessage `json:"result"`
	Error  json.RawMessage `json:"error"`
}

type hostResponse struct {
	ID           string          `json:"id"`
	HostCallID   string          `json:"host_call_id,omitempty"`
	Generation   uint64          `json:"generation,omitempty"`
	InvocationID string          `json:"invocation_id,omitempty"`
	OK           bool            `json:"ok"`
	Result       json.RawMessage `json:"result,omitempty"`
	Error        string          `json:"error,omitempty"`
}

type HTTPRequest struct {
	Method string
	URL    string
	Header map[string]string
	Body   []byte
}

type HTTPResponse struct {
	StatusCode int
	Header     map[string]string
	Body       []byte
}

func (c *HostClient) HTTPDo(ctx context.Context, req HTTPRequest) (HTTPResponse, error) {
	return c.httpDo(ctx, HostMethodHTTPDo, req)
}

func (c *HostClient) HTTPOperatorDo(ctx context.Context, req HTTPRequest) (HTTPResponse, error) {
	return c.httpDo(ctx, HostMethodHTTPOperatorDo, req)
}

func (c *HostClient) httpDo(ctx context.Context, method string, req HTTPRequest) (HTTPResponse, error) {
	params := struct {
		Method     string            `json:"method,omitempty"`
		URL        string            `json:"url"`
		Header     map[string]string `json:"header,omitempty"`
		BodyBase64 string            `json:"body_base64,omitempty"`
	}{
		Method: req.Method,
		URL:    req.URL,
		Header: cloneStringMap(req.Header),
	}
	if len(req.Body) > 0 {
		params.BodyBase64 = base64.StdEncoding.EncodeToString(req.Body)
	}
	raw, err := c.Call(ctx, method, params)
	if err != nil {
		return HTTPResponse{}, err
	}
	var out struct {
		StatusCode int               `json:"status_code"`
		Header     map[string]string `json:"header,omitempty"`
		BodyBase64 string            `json:"body_base64,omitempty"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return HTTPResponse{}, fmt.Errorf("decode %s response: %w", method, err)
	}
	body := []byte(nil)
	if out.BodyBase64 != "" {
		body, err = base64.StdEncoding.DecodeString(out.BodyBase64)
		if err != nil {
			return HTTPResponse{}, fmt.Errorf("decode %s body_base64: %w", method, err)
		}
	}
	return HTTPResponse{StatusCode: out.StatusCode, Header: cloneStringMap(out.Header), Body: body}, nil
}

func (c *HostClient) RPCCallRaw(ctx context.Context, service, method string, request json.RawMessage) (json.RawMessage, error) {
	params := struct {
		Service string          `json:"service"`
		Method  string          `json:"method"`
		Request json.RawMessage `json:"request,omitempty"`
	}{Service: service, Method: method, Request: append(json.RawMessage(nil), request...)}
	return c.Call(ctx, HostMethodRPCCall, params)
}

func (c *HostClient) RPCCall(ctx context.Context, service, method string, request any) (json.RawMessage, error) {
	raw, err := rawJSON(request)
	if err != nil {
		return nil, fmt.Errorf("encode rpc.call request: %w", err)
	}
	return c.RPCCallRaw(ctx, service, method, raw)
}

func (c *HostClient) KVGet(ctx context.Context, key string) ([]byte, bool, error) {
	raw, err := c.Call(ctx, HostMethodKVGet, struct {
		Key string `json:"key"`
	}{Key: key})
	if err != nil {
		return nil, false, err
	}
	var out struct {
		OK          bool   `json:"ok"`
		Value       string `json:"value,omitempty"`
		ValueBase64 string `json:"value_base64,omitempty"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, false, fmt.Errorf("decode kv.get response: %w", err)
	}
	if !out.OK {
		return nil, false, nil
	}
	if out.ValueBase64 != "" {
		value, err := base64.StdEncoding.DecodeString(out.ValueBase64)
		if err != nil {
			return nil, false, fmt.Errorf("decode kv.get value_base64: %w", err)
		}
		return value, true, nil
	}
	return []byte(out.Value), true, nil
}

func (c *HostClient) KVPut(ctx context.Context, key string, value []byte) error {
	_, err := c.Call(ctx, HostMethodKVPut, struct {
		Key         string `json:"key"`
		ValueBase64 string `json:"value_base64"`
	}{Key: key, ValueBase64: base64.StdEncoding.EncodeToString(value)})
	return err
}

func (c *HostClient) NotifySend(ctx context.Context, title, body string) error {
	_, err := c.Call(ctx, HostMethodNotifySend, struct {
		Title string `json:"title"`
		Body  string `json:"body"`
	}{Title: title, Body: body})
	return err
}

type LogEntry struct {
	Level   string            `json:"level"`
	Message string            `json:"message"`
	Fields  map[string]string `json:"fields,omitempty"`
}

func (c *HostClient) LogWrite(ctx context.Context, entry LogEntry) error {
	_, err := c.Call(ctx, HostMethodLogWrite, LogEntry{
		Level:   entry.Level,
		Message: entry.Message,
		Fields:  cloneStringMap(entry.Fields),
	})
	return err
}

func (c *HostClient) SecretGet(ctx context.Context, key string) ([]byte, bool, error) {
	raw, err := c.Call(ctx, HostMethodSecretGet, struct {
		Key string `json:"key"`
	}{Key: key})
	if err != nil {
		return nil, false, err
	}
	var out struct {
		OK          bool   `json:"ok"`
		ValueBase64 string `json:"value_base64,omitempty"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, false, fmt.Errorf("decode secret.get response: %w", err)
	}
	if !out.OK {
		return nil, false, nil
	}
	value, err := base64.StdEncoding.DecodeString(out.ValueBase64)
	if err != nil {
		return nil, false, fmt.Errorf("decode secret.get value_base64: %w", err)
	}
	return value, true, nil
}

func (c *HostClient) SecretGetString(ctx context.Context, key string) (string, bool, error) {
	value, ok, err := c.SecretGet(ctx, key)
	if err != nil || !ok {
		return "", ok, err
	}
	return string(value), true, nil
}

func (c *HostClient) SecretPut(ctx context.Context, key string, value []byte) error {
	_, err := c.Call(ctx, HostMethodSecretPut, struct {
		Key         string `json:"key"`
		ValueBase64 string `json:"value_base64"`
	}{Key: key, ValueBase64: base64.StdEncoding.EncodeToString(value)})
	return err
}

func (c *HostClient) SecretPutString(ctx context.Context, key, value string) error {
	return c.SecretPut(ctx, key, []byte(value))
}

func (c *HostClient) SecretDelete(ctx context.Context, key string) error {
	_, err := c.Call(ctx, HostMethodSecretDelete, struct {
		Key string `json:"key"`
	}{Key: key})
	return err
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
