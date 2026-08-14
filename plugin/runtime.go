package plugin

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"sync"
)

const (
	ActionDescribe = "describe"
	ActionHealth   = "health"
	ActionPlan     = "plan"
	ActionCall     = "call"
	ActionExecute  = "execute"

	DefaultMaxRequestBytes = 1 << 20
	FeatureStderrFramesV1  = "stderr_frames_v1"
)

type Request struct {
	Action  string          `json:"action"`
	Service string          `json:"service,omitempty"`
	Method  string          `json:"method,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type CallPayload struct {
	Service string          `json:"service"`
	Method  string          `json:"method"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

func (r Request) CallPayload() (CallPayload, error) {
	if r.Service != "" || r.Method != "" {
		return CallPayload{
			Service: r.Service,
			Method:  r.Method,
			Payload: append(json.RawMessage(nil), r.Payload...),
		}, nil
	}
	var call CallPayload
	if len(r.Payload) == 0 {
		return CallPayload{}, nil
	}
	if err := json.Unmarshal(r.Payload, &call); err != nil {
		return CallPayload{}, fmt.Errorf("decode call payload: %w", err)
	}
	call.Payload = append(json.RawMessage(nil), call.Payload...)
	return call, nil
}

type Response struct {
	OK       bool            `json:"ok"`
	Plan     string          `json:"plan,omitempty"`
	Message  string          `json:"message,omitempty"`
	Result   json.RawMessage `json:"result,omitempty"`
	Error    string          `json:"error,omitempty"`
	Warnings []string        `json:"warnings,omitempty"`
}

func ResultResponse(result any, message string) Response {
	raw, err := rawJSON(result)
	if err != nil {
		return ErrorResponse(fmt.Errorf("encode result: %w", err))
	}
	return Response{OK: true, Result: raw, Message: message}
}

func RawResultResponse(result json.RawMessage, message string) Response {
	return Response{OK: true, Result: append(json.RawMessage(nil), result...), Message: message}
}

func MessageResponse(message string) Response {
	return Response{OK: true, Message: message}
}

func PlanResponse(plan, message string) Response {
	return Response{OK: true, Plan: plan, Message: message}
}

func ErrorResponse(err error) Response {
	if err == nil {
		return Response{OK: false, Error: "plugin call failed"}
	}
	return Response{OK: false, Error: err.Error()}
}

type Handler interface {
	HandlePluginRequest(ctx context.Context, req Request, host *HostClient) Response
}

type HandlerFunc func(ctx context.Context, req Request, host *HostClient) Response

func (f HandlerFunc) HandlePluginRequest(ctx context.Context, req Request, host *HostClient) Response {
	return f(ctx, req, host)
}

type Runtime struct {
	In              io.Reader
	Out             io.Writer
	Host            *HostClient
	MaxRequestBytes int
	closeHost       func()
	v2Transport     *hostTransport
	writeMu         sync.Mutex
}

type RuntimeOptions struct {
	In              io.Reader
	Out             io.Writer
	Host            *HostClient
	MaxRequestBytes int
	OpenHostFromEnv bool
}

type invocationStderrKey struct{}

type invocationStderr struct {
	runtime    *Runtime
	generation uint64
	invocation string
	mu         sync.Mutex
	pending    sync.WaitGroup
	expired    bool
}

// InvocationStderr returns the invocation-scoped diagnostic stream. Writes are
// serialized as correlated v2 stderr_chunk frames and rejected after the
// handler returns. Raw os.Stderr is process-scoped only and the host continuously
// drains it into bounded counters without attribution or external disclosure;
// InvocationStderr is the only invocation diagnostic channel. Use
// stdio-json-v1 when process isolation is required.
func InvocationStderr(ctx context.Context) io.Writer {
	if ctx == nil {
		return io.Discard
	}
	w, _ := ctx.Value(invocationStderrKey{}).(*invocationStderr)
	if w == nil {
		return io.Discard
	}
	return w
}

func (w *invocationStderr) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.mu.Lock()
	if w.expired {
		w.mu.Unlock()
		return 0, ErrV2Protocol
	}
	w.pending.Add(1)
	w.mu.Unlock()
	defer w.pending.Done()
	frame := struct {
		Protocol     int    `json:"protocol"`
		Kind         string `json:"kind"`
		Generation   uint64 `json:"generation"`
		InvocationID string `json:"invocation_id"`
		Data         string `json:"data"`
	}{2, "stderr_chunk", w.generation, w.invocation, base64.StdEncoding.EncodeToString(p)}
	if err := w.runtime.emitV2(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *invocationStderr) Expire() {
	w.mu.Lock()
	w.expired = true
	w.mu.Unlock()
	w.pending.Wait()
}

// V2Session validates the ordered, single-invocation stdio-json-v2 lifecycle.
// It is intentionally small and transport-agnostic so hosts can reject bad
// frames before dispatching plugin code.
type V2Session struct {
	Generation uint64
	state      string
	invocation string
}

var ErrV2Protocol = fmt.Errorf("invalid stdio-json-v2 lifecycle")

func NewV2Session(generation uint64) *V2Session {
	return &V2Session{Generation: generation, state: "ready"}
}
func (s *V2Session) Accept(kind string, generation uint64, invocation string) error {
	if s == nil || generation != s.Generation || invocation == "" {
		return ErrV2Protocol
	}
	switch s.state {
	case "ready":
		if kind != "invoke" {
			return ErrV2Protocol
		}
		s.invocation = invocation
		s.state = "invoked"
	case "invoked":
		if invocation != s.invocation {
			return ErrV2Protocol
		}
		if kind == "stderr_chunk" {
			return nil
		}
		if kind != "invoke_result" {
			return ErrV2Protocol
		}
		s.state = "result"
	case "result":
		if kind != "stderr_complete" || invocation != s.invocation {
			return ErrV2Protocol
		}
		s.state = "stderr_complete"
	case "stderr_complete":
		if kind != "invoke_ready" || invocation != s.invocation {
			return ErrV2Protocol
		}
		s.state = "ready"
		s.invocation = ""
	default:
		return ErrV2Protocol
	}
	return nil
}

// ServeV2 processes correlated pooled-worker frames. It never accepts v1
// request envelopes, allowing hosts to select v2 explicitly without a silent
// downgrade.
func (rt *Runtime) ServeV2(ctx context.Context, handler Handler, generation uint64) error {
	if rt == nil || handler == nil {
		return fmt.Errorf("plugin runtime or handler is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if generation == 0 {
		return fmt.Errorf("invalid stdio-json-v2 generation")
	}
	if rt.Host != nil && rt.Host.output != nil && rt.Out != nil && !sameWriter(rt.Host.output, rt.Out) {
		return fmt.Errorf("v2 host output mismatch")
	}
	scanner := bufio.NewScanner(rt.In)
	max := rt.MaxRequestBytes
	if max <= 0 {
		max = DefaultMaxRequestBytes
	}
	scanner.Buffer(make([]byte, 0, 64*1024), max)
	ready := struct {
		Protocol     int      `json:"protocol"`
		Kind         string   `json:"kind"`
		Generation   uint64   `json:"generation"`
		InvocationID string   `json:"invocation_id"`
		Features     []string `json:"features,omitempty"`
	}{2, "runtime_ready", generation, "runtime", []string{FeatureStderrFramesV1}}
	session := NewV2Session(generation)
	usedInvocations := make(map[string]struct{})
	var serveTransport *hostTransport
	if rt.Host != nil && rt.Host.transport != nil {
		serveTransport = &hostTransport{output: rt.Out, responses: rt.Host.transport.responses, closer: rt.Host.transport.closer}
		serveTransport.exchange = make(chan struct{}, 1)
		serveTransport.exchange <- struct{}{}
	}
	rt.v2Transport = serveTransport
	if err := rt.emitV2(ready); err != nil {
		return err
	}
	ready.Features = nil
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		frame, err := decodeInvokeV2(scanner.Bytes(), generation)
		if err != nil {
			return fmt.Errorf("invalid stdio-json-v2 frame")
		}
		if _, exists := usedInvocations[frame.InvocationID]; exists {
			return fmt.Errorf("duplicate invocation_id")
		}
		if len(usedInvocations) >= 256 {
			return fmt.Errorf("invocation limit exceeded")
		}
		usedInvocations[frame.InvocationID] = struct{}{}
		if err := session.Accept("invoke", frame.Generation, frame.InvocationID); err != nil {
			return err
		}
		invHost := NewHostClient(HostClientOptions{Output: rt.Out})
		if rt.Host != nil && serveTransport != nil {
			invHost = rt.Host.scopedTransport(serveTransport, generation, frame.InvocationID)
		}
		diagnostics := &invocationStderr{runtime: rt, generation: generation, invocation: frame.InvocationID}
		invokeCtx := context.WithValue(ctx, invocationStderrKey{}, diagnostics)
		resp := handler.HandlePluginRequest(invokeCtx, *frame.Request, invHost)
		if invHost != nil {
			invHost.Expire()
		}
		diagnostics.Expire()
		if serveTransport != nil && serveTransport.poisoned.Load() {
			return fmt.Errorf("v2 transport aborted")
		}
		if err := session.Accept("invoke_result", frame.Generation, frame.InvocationID); err != nil {
			return err
		}
		if err := session.Accept("stderr_complete", frame.Generation, frame.InvocationID); err != nil {
			return err
		}
		if err := session.Accept("invoke_ready", frame.Generation, frame.InvocationID); err != nil {
			return err
		}
		out := struct {
			Protocol     int      `json:"protocol"`
			Kind         string   `json:"kind"`
			Generation   uint64   `json:"generation"`
			InvocationID string   `json:"invocation_id"`
			Response     Response `json:"response"`
		}{2, "invoke_result", generation, frame.InvocationID, resp}
		if err := rt.emitV2(out); err != nil {
			return err
		}
		ready.InvocationID = frame.InvocationID
		ready.Kind = "stderr_complete"
		if err := rt.emitV2(ready); err != nil {
			return err
		}
		ready.InvocationID = frame.InvocationID
		ready.Kind = "invoke_ready"
		if err := rt.emitV2(ready); err != nil {
			return err
		}
	}
	return scanner.Err()
}

func sameWriter(a, b io.Writer) bool {
	va, vb := reflect.ValueOf(a), reflect.ValueOf(b)
	if !va.IsValid() || !vb.IsValid() || va.Type() != vb.Type() {
		return false
	}
	if va.Type().Comparable() {
		return va.Interface() == vb.Interface()
	}
	return false
}

func decodeInvokeV2(raw []byte, generation uint64) (struct {
	Protocol     int      `json:"protocol"`
	Kind         string   `json:"kind"`
	Generation   uint64   `json:"generation"`
	InvocationID string   `json:"invocation_id"`
	Request      *Request `json:"request"`
}, error) {
	if len(raw) > DefaultMaxRequestBytes {
		return struct {
			Protocol     int      `json:"protocol"`
			Kind         string   `json:"kind"`
			Generation   uint64   `json:"generation"`
			InvocationID string   `json:"invocation_id"`
			Request      *Request `json:"request"`
		}{}, ErrV2Protocol
	}
	var frame struct {
		Protocol     int      `json:"protocol"`
		Kind         string   `json:"kind"`
		Generation   uint64   `json:"generation"`
		InvocationID string   `json:"invocation_id"`
		Request      *Request `json:"request"`
	}
	if err := strictDecodeFrame(raw, &frame); err != nil || frame.Protocol != 2 || frame.Kind != "invoke" || frame.Generation == 0 || frame.Generation != generation || frame.InvocationID == "" || frame.Request == nil {
		return frame, ErrV2Protocol
	}
	return frame, nil
}

// emitV2 serializes terminal frames through the same transport writer used by
// host_call. This prevents terminal lifecycle frames from overtaking an
// admitted call when host and runtime share an output stream.
func (rt *Runtime) emitV2(v any) error {
	if rt.v2Transport != nil {
		t := rt.v2Transport
		t.writeMu.Lock()
		defer t.writeMu.Unlock()
		return json.NewEncoder(t.output).Encode(v)
	}
	rt.writeMu.Lock()
	defer rt.writeMu.Unlock()
	return json.NewEncoder(rt.Out).Encode(v)
}

func NewRuntime(opts RuntimeOptions) *Runtime {
	in := opts.In
	if in == nil {
		in = os.Stdin
	}
	out := opts.Out
	if out == nil {
		out = os.Stdout
	}
	maxRequestBytes := opts.MaxRequestBytes
	if maxRequestBytes <= 0 {
		maxRequestBytes = DefaultMaxRequestBytes
	}
	host := opts.Host
	closeHost := func() {}
	if host == nil && opts.OpenHostFromEnv {
		host, closeHost = NewHostClientFromEnv(out)
	}
	return &Runtime{
		In:              in,
		Out:             out,
		Host:            host,
		MaxRequestBytes: maxRequestBytes,
		closeHost:       closeHost,
	}
}

func Serve(ctx context.Context, handler Handler) error {
	rt := NewRuntime(RuntimeOptions{OpenHostFromEnv: true})
	defer rt.Close()
	return rt.Serve(ctx, handler)
}

func (rt *Runtime) Close() {
	if rt != nil && rt.closeHost != nil {
		rt.closeHost()
		rt.closeHost = nil
	}
}

func (rt *Runtime) Serve(ctx context.Context, handler Handler) error {
	if rt == nil {
		return fmt.Errorf("plugin runtime is nil")
	}
	if handler == nil {
		return fmt.Errorf("plugin handler is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	scanner := bufio.NewScanner(rt.In)
	scanner.Buffer(make([]byte, 0, 64*1024), rt.MaxRequestBytes)
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var req Request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			if writeErr := rt.WriteResponse(ErrorResponse(fmt.Errorf("invalid request: %w", err))); writeErr != nil {
				return writeErr
			}
			continue
		}
		if err := rt.WriteResponse(handler.HandlePluginRequest(ctx, req, rt.Host)); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read plugin request: %w", err)
	}
	return ctx.Err()
}

func (rt *Runtime) WriteResponse(resp Response) error {
	if rt == nil || rt.Out == nil {
		return fmt.Errorf("plugin response output is unavailable")
	}
	return json.NewEncoder(rt.Out).Encode(resp)
}
