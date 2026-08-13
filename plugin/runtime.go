package plugin

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

const (
	ActionDescribe = "describe"
	ActionHealth   = "health"
	ActionPlan     = "plan"
	ActionCall     = "call"
	ActionExecute  = "execute"

	DefaultMaxRequestBytes = 1 << 20
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
}

type RuntimeOptions struct {
	In              io.Reader
	Out             io.Writer
	Host            *HostClient
	MaxRequestBytes int
	OpenHostFromEnv bool
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
	scanner := bufio.NewScanner(rt.In)
	max := rt.MaxRequestBytes
	if max <= 0 {
		max = DefaultMaxRequestBytes
	}
	scanner.Buffer(make([]byte, 0, 64*1024), max)
	ready := struct {
		Protocol     int    `json:"protocol"`
		Kind         string `json:"kind"`
		Generation   uint64 `json:"generation"`
		InvocationID string `json:"invocation_id"`
	}{2, "runtime_ready", generation, "runtime"}
	if err := json.NewEncoder(rt.Out).Encode(ready); err != nil {
		return err
	}
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		var frame struct {
			Protocol     int     `json:"protocol"`
			Kind         string  `json:"kind"`
			Generation   uint64  `json:"generation"`
			InvocationID string  `json:"invocation_id"`
			Request      Request `json:"request"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &frame); err != nil || frame.Protocol != 2 || frame.Generation != generation || frame.Kind != "invoke" || frame.InvocationID == "" {
			return fmt.Errorf("invalid stdio-json-v2 frame")
		}
		resp := handler.HandlePluginRequest(ctx, frame.Request, rt.Host)
		out := struct {
			Protocol     int      `json:"protocol"`
			Kind         string   `json:"kind"`
			Generation   uint64   `json:"generation"`
			InvocationID string   `json:"invocation_id"`
			Response     Response `json:"response"`
		}{2, "invoke_result", generation, frame.InvocationID, resp}
		if err := json.NewEncoder(rt.Out).Encode(out); err != nil {
			return err
		}
		ready.InvocationID = frame.InvocationID
		ready.Kind = "invoke_ready"
		if err := json.NewEncoder(rt.Out).Encode(ready); err != nil {
			return err
		}
	}
	return scanner.Err()
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
