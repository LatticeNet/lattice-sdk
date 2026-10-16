package plugin

import (
	"bytes"
	"encoding/json"
	"strconv"

	"github.com/LatticeNet/lattice-sdk/strictjson"
)

// The runtime decodes three things on every invocation that can carry a
// large payload: the invoke frame, each host_response frame, and the call
// payload inside the request. Their encoding/json decodes copied and scanned
// the payload several times over (a 900 KB render request cost about 25 ms
// before the handler ran). Each decode below reads a frame's members in one
// strictjson pass, decodes every member on its own and copies a raw payload
// once, but only for the plain case: an object strictjson admits whose
// members are named exactly as the struct's, at every level the struct
// nests. Anything else returns ok false and takes the encoding/json path it
// replaces, which decides and words every error. For the plain case the two
// agree, because a member named exactly once decodes the same whether
// encoding/json reaches it through the struct or on its own; the fuzz tests
// hold them to that.

// strictMembers reads raw's members when raw is an object strictjson admits
// and every member is one of names, exactly.
func strictMembers(raw []byte, names ...string) (map[string][]byte, bool) {
	fields, ok := strictjson.Fields(raw)
	if !ok {
		return nil, false
	}
	members := make(map[string][]byte, len(fields))
	for _, f := range fields {
		known := false
		for _, name := range names {
			if f.Key == name {
				known = true
				break
			}
		}
		if !known {
			return nil, false
		}
		members[f.Key] = f.Value
	}
	return members, true
}

// decodeMembers decodes each member into the target named for it; a member
// without a target, or one that does not decode, answers false.
func decodeMembers(members map[string][]byte, targets map[string]any) bool {
	for key, value := range members {
		target, ok := targets[key]
		if !ok {
			return false
		}
		switch t := target.(type) {
		case *json.RawMessage:
			*t = append(json.RawMessage(nil), value...)
		default:
			if json.Unmarshal(value, target) != nil {
				return false
			}
		}
	}
	return true
}

type invokeV2Frame = struct {
	Protocol     int      `json:"protocol"`
	Kind         string   `json:"kind"`
	Generation   uint64   `json:"generation"`
	InvocationID string   `json:"invocation_id"`
	Request      *Request `json:"request"`
}

// decodeInvokeV2Fast is strictDecodeFrame into an invoke frame for the plain
// case.
func decodeInvokeV2Fast(raw []byte) (invokeV2Frame, bool) {
	var frame invokeV2Frame
	members, ok := strictMembers(raw, "protocol", "kind", "generation", "invocation_id", "request")
	if !ok {
		return frame, false
	}
	if request, present := members["request"]; present {
		inner, ok := strictMembers(request, "action", "service", "method", "payload")
		if !ok {
			return frame, false
		}
		frame.Request = &Request{}
		if !decodeMembers(inner, map[string]any{"action": &frame.Request.Action, "service": &frame.Request.Service,
			"method": &frame.Request.Method, "payload": &frame.Request.Payload}) {
			return frame, false
		}
		delete(members, "request")
	}
	if !decodeMembers(members, map[string]any{"protocol": &frame.Protocol, "kind": &frame.Kind,
		"generation": &frame.Generation, "invocation_id": &frame.InvocationID}) {
		return frame, false
	}
	return frame, true
}

// decodeHostResponseFast is strictDecodeFrame into a strict host_response
// envelope for the plain case.
func decodeHostResponseFast(raw []byte) (strictHostResponseEnvelope, bool) {
	var env strictHostResponseEnvelope
	members, ok := strictMembers(raw, "protocol", "kind", "generation", "invocation_id", "host_call_id", "host_response")
	if !ok {
		return env, false
	}
	if response, present := members["host_response"]; present {
		inner, ok := strictMembers(response, "id", "ok", "result", "error")
		if !ok {
			return env, false
		}
		if !decodeMembers(inner, map[string]any{"id": &env.HostResponse.ID, "ok": &env.HostResponse.OK,
			"result": &env.HostResponse.Result, "error": &env.HostResponse.Error}) {
			return env, false
		}
		delete(members, "host_response")
	}
	if !decodeMembers(members, map[string]any{"protocol": &env.Protocol, "kind": &env.Kind, "generation": &env.Generation,
		"invocation_id": &env.InvocationID, "host_call_id": &env.HostCallID}) {
		return env, false
	}
	return env, true
}

// callPayloadFast is CallPayload's json.Unmarshal for the plain case.
func callPayloadFast(raw []byte) (CallPayload, bool) {
	var call CallPayload
	members, ok := strictMembers(raw, "service", "method", "payload")
	if !ok {
		return call, false
	}
	if !decodeMembers(members, map[string]any{"service": &call.Service, "method": &call.Method, "payload": &call.Payload}) {
		return CallPayload{}, false
	}
	return call, true
}

// canonicalRawJSON reports whether raw is already what encoding/json writes
// for a json.RawMessage holding it: compact, and free of the bytes it
// escapes ('<', '>', '&', U+2028, U+2029). Those bytes cannot occur outside
// a string, so a search of the whole value is enough.
func canonicalRawJSON(raw []byte) bool {
	return strictjson.Compact(raw) && !bytes.ContainsAny(raw, "<>&") &&
		!bytes.Contains(raw, []byte("\u2028")) && !bytes.Contains(raw, []byte("\u2029"))
}

// appendJSONValue appends v as json.Marshal writes it; the values passed (a
// string, a string slice) cannot fail to encode.
func appendJSONValue(dst []byte, v any) []byte {
	raw, _ := json.Marshal(v)
	return append(dst, raw...)
}

// appendInvokeResultFrame appends the invoke_result frame, newline
// included, exactly as json.NewEncoder(w).Encode writes it for resp, but
// without the pass encoding/json spends compacting resp.Result once more: a
// render or convert result is up to several MiB that the handler's own
// json.Marshal already wrote in that form. ok is false when Result is not
// already canonical, and the caller encodes the frame.
func appendInvokeResultFrame(dst []byte, generation uint64, invocationID string, resp Response) ([]byte, bool) {
	if len(resp.Result) > 0 && !canonicalRawJSON(resp.Result) {
		return dst, false
	}
	dst = append(dst, `{"protocol":2,"kind":"invoke_result","generation":`...)
	dst = strconv.AppendUint(dst, generation, 10)
	dst = append(dst, `,"invocation_id":`...)
	dst = appendJSONValue(dst, invocationID)
	dst = append(dst, `,"response":{"ok":`...)
	dst = strconv.AppendBool(dst, resp.OK)
	if resp.Plan != "" {
		dst = appendJSONValue(append(dst, `,"plan":`...), resp.Plan)
	}
	if resp.Message != "" {
		dst = appendJSONValue(append(dst, `,"message":`...), resp.Message)
	}
	if len(resp.Result) > 0 {
		dst = append(append(dst, `,"result":`...), resp.Result...)
	}
	if resp.Error != "" {
		dst = appendJSONValue(append(dst, `,"error":`...), resp.Error)
	}
	if len(resp.Warnings) > 0 {
		dst = appendJSONValue(append(dst, `,"warnings":`...), resp.Warnings)
	}
	return append(dst, "}}\n"...), true
}
