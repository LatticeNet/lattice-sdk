package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func exactJSONPayload(size int) json.RawMessage {
	if size < 2 {
		panic("payload size must fit an object")
	}
	return json.RawMessage("{" + strings.Repeat(" ", size-2) + "}")
}

func hostResponseFrame(strict bool, result json.RawMessage) []byte {
	if strict {
		return []byte(`{"protocol":2,"kind":"host_response","generation":1,"invocation_id":"1","host_call_id":"h1","host_response":{"id":"h1","ok":true,"result":` + string(result) + `}}`)
	}
	return []byte(`{"host_response":{"id":"h1","ok":true,"result":` + string(result) + `}}`)
}

func padHostResponseFrame(frame []byte, size int) []byte {
	if len(frame) > size || len(frame) == 0 || frame[len(frame)-1] != '}' {
		panic("frame cannot be padded to requested size")
	}
	out := make([]byte, 0, size)
	out = append(out, frame[:len(frame)-1]...)
	out = append(out, bytes.Repeat([]byte(" "), size-len(frame))...)
	out = append(out, '}')
	return out
}

func callWithHostResponse(t *testing.T, strict bool, frame []byte) error {
	t.Helper()
	reader := io.Reader(strings.NewReader(string(append(frame, '\n'))))
	var closer io.ReadCloser
	if strict {
		closer = io.NopCloser(reader)
		reader = closer
	}
	var out bytes.Buffer
	var h *HostClient
	if strict {
		h = NewInvocationHostClient(HostClientOptions{Output: &out, Responses: reader}, 1, "1")
	} else {
		h = NewHostClient(HostClientOptions{Output: &out, Responses: reader})
	}
	_, err := h.Call(context.Background(), "rpc.call", map[string]any{"x": 1})
	if closer != nil {
		_ = closer.Close()
	}
	return err
}

func TestHostResponsePayloadAndFrameBoundsAreIndependent(t *testing.T) {
	for _, strict := range []bool{false, true} {
		name := "v1"
		if strict {
			name = "v2"
		}
		t.Run(name+"_payload_exact", func(t *testing.T) {
			if err := callWithHostResponse(t, strict, hostResponseFrame(strict, exactJSONPayload(DefaultMaxHostResponseBytes))); err != nil {
				t.Fatalf("exact payload rejected: %v", err)
			}
		})
		t.Run(name+"_payload_plus_one", func(t *testing.T) {
			err := callWithHostResponse(t, strict, hostResponseFrame(strict, exactJSONPayload(DefaultMaxHostResponseBytes+1)))
			if err == nil || !strings.Contains(err.Error(), "payload limit") {
				t.Fatalf("payload N+1 error=%v", err)
			}
		})
		t.Run(name+"_frame_exact", func(t *testing.T) {
			frame := padHostResponseFrame(hostResponseFrame(strict, exactJSONPayload(DefaultMaxHostResponseBytes)), DefaultMaxHostResponseFrameBytes)
			if err := callWithHostResponse(t, strict, frame); err != nil {
				t.Fatalf("exact frame rejected: %v", err)
			}
		})
		t.Run(name+"_frame_plus_one", func(t *testing.T) {
			frame := padHostResponseFrame(hostResponseFrame(strict, exactJSONPayload(DefaultMaxHostResponseBytes)), DefaultMaxHostResponseFrameBytes+1)
			err := callWithHostResponse(t, strict, frame)
			if err == nil || !strings.Contains(err.Error(), "host_response") {
				t.Fatalf("frame F+1 error=%v", err)
			}
		})
	}
}

func TestStrictCorrelationIDsAreCanonicalAndBounded(t *testing.T) {
	for _, id := range []string{"", "0", "01", "+1", "-1", "9223372036854775808", "inv"} {
		h := NewInvocationHostClient(HostClientOptions{Output: io.Discard, Responses: io.NopCloser(strings.NewReader(""))}, 1, id)
		if h.Available() {
			t.Fatalf("accepted invocation_id %q", id)
		}
	}
	for _, id := range []string{"", "h0", "h01", "H1", "h+1", "h18446744073709551616"} {
		frame := strings.Replace(string(hostResponseFrame(true, json.RawMessage(`{}`))), `"h1"`, `"`+id+`"`, 1)
		if err := callWithHostResponse(t, true, []byte(frame)); err == nil {
			t.Fatalf("accepted host call id %q", id)
		}
	}
	for _, id := range []string{"0", "01", "+1", "-1", "9223372036854775808", "inv"} {
		raw := []byte(`{"protocol":2,"kind":"invoke","generation":1,"invocation_id":"` + id + `","request":{}}`)
		if _, err := decodeInvokeV2(raw, 1); err == nil {
			t.Fatalf("decoded invocation_id %q", id)
		}
	}
}

func TestHostResponseOversizeFrameCannotDesynchronizeNextCall(t *testing.T) {
	oversize := padHostResponseFrame(hostResponseFrame(false, exactJSONPayload(DefaultMaxHostResponseBytes)), DefaultMaxHostResponseFrameBytes+1)
	valid := []byte(`{"host_response":{"id":"h2","ok":true,"result":{}}}`)
	responses := append(append(append([]byte(nil), oversize...), '\n'), valid...)
	responses = append(responses, '\n')
	var out bytes.Buffer
	h := NewHostClient(HostClientOptions{Output: &out, Responses: bytes.NewReader(responses)})
	if _, err := h.Call(context.Background(), "rpc.call", map[string]any{}); err == nil {
		t.Fatal("oversize frame accepted")
	}
	if _, err := h.Call(context.Background(), "rpc.call", map[string]any{}); err == nil {
		t.Fatal("scanner resumed after oversize frame and consumed a later response")
	}
}

func TestHostCallIDOverflowFailsBeforeEmission(t *testing.T) {
	var out bytes.Buffer
	h := NewHostClient(HostClientOptions{Output: &out, Responses: strings.NewReader("")})
	h.transport.nextID = ^uint64(0)
	if _, err := h.Call(context.Background(), "rpc.call", map[string]any{}); err == nil || !strings.Contains(err.Error(), "exhausted") {
		t.Fatalf("overflow error=%v", err)
	}
	if out.Len() != 0 {
		t.Fatalf("overflow emitted %d bytes", out.Len())
	}
}
