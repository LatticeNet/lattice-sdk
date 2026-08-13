package plugin

import (
	"bufio"
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
)

const (
	HostMethodRPCCall            = "rpc.call"
	HostMethodHTTPDo             = "http.do"
	HostMethodHTTPOperatorDo     = "http.operator.do"
	HostMethodKVGet              = "kv.get"
	HostMethodKVPut              = "kv.put"
	HostMethodNotifySend         = "notify.send"
	HostMethodLogWrite           = "log.write"
	HostMethodSecretGet          = "secret.get"
	HostMethodSecretPut          = "secret.put"
	HostMethodSecretDelete       = "secret.delete"
	DefaultMaxHostResponseBytes  = 1 << 20
	defaultHostResponseFD        = 3
	hostResponseFDEnvironmentKey = "LATTICE_HOST_RESPONSE_FD"
)

var ErrHostUnavailable = errors.New("host response fd unavailable")

type HostClient struct {
	output           io.Writer
	responses        *bufio.Scanner
	maxResponseBytes int

	mu           sync.Mutex
	nextID       int
	generation   uint64
	invocationID string
	expired      bool
	strict       bool
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
	}
	if opts.Responses != nil {
		scanner := bufio.NewScanner(opts.Responses)
		scanner.Buffer(make([]byte, 0, 64*1024), maxResponseBytes)
		client.responses = scanner
	}
	return client
}

// NewInvocationHostClient creates a lease-scoped facade. Expire it before the
// worker emits invoke_ready so late plugin calls cannot reach the host.
func NewInvocationHostClient(opts HostClientOptions, generation uint64, invocationID string) *HostClient {
	c := NewHostClient(opts)
	c.generation, c.invocationID = generation, invocationID
	c.strict = true
	return c
}

func (c *HostClient) Expire() {
	if c != nil {
		c.mu.Lock()
		c.expired = true
		c.mu.Unlock()
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

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.expired {
		return nil, ErrHostClientExpired
	}

	c.nextID++
	id := fmt.Sprintf("h%d", c.nextID)
	if err := json.NewEncoder(c.output).Encode(hostCallEnvelope{
		HostCall: hostCall{ID: id, HostCallID: id, Generation: c.generation, InvocationID: c.invocationID, Method: method, Params: params},
	}); err != nil {
		return nil, fmt.Errorf("write host_call: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !c.responses.Scan() {
		if err := c.responses.Err(); err != nil {
			return nil, fmt.Errorf("read host_response: %w", err)
		}
		return nil, errors.New("read host_response: eof")
	}
	var env hostResponseEnvelope
	if err := json.Unmarshal(c.responses.Bytes(), &env); err != nil {
		return nil, fmt.Errorf("decode host_response: %w", err)
	}
	if env.HostResponse.ID != id {
		return nil, fmt.Errorf("host_response id mismatch: got %q want %q", env.HostResponse.ID, id)
	}
	if env.HostResponse.HostCallID != "" && env.HostResponse.HostCallID != id {
		return nil, fmt.Errorf("host_response host_call_id mismatch: got %q want %q", env.HostResponse.HostCallID, id)
	}
	if c.strict && (env.HostResponse.HostCallID == "" || env.HostResponse.Generation != c.generation || env.HostResponse.InvocationID != c.invocationID) {
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

type hostCallEnvelope struct {
	HostCall hostCall `json:"host_call"`
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
	HostResponse hostResponse `json:"host_response"`
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
