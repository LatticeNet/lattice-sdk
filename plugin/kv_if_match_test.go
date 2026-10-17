package plugin

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

// kvHost is a host that speaks the kv.get and kv.put wire as the
// compare-and-swap contract defines it: kv.get reports the stored value's
// sha256; a kv.put whose payload carries if_match writes only when the stored
// value's digest equals it, and an empty if_match only when the key does not
// exist; a kv.put without the field writes unconditionally. A refusal is the
// error "kv_conflict: ...".
type kvHost struct {
	mu     sync.Mutex
	store  map[string][]byte
	digest bool // report sha256 on kv.get
	puts   []map[string]json.RawMessage
}

func newKVHost(t *testing.T, digest bool) (*HostClient, *kvHost) {
	t.Helper()
	outR, outW := io.Pipe()
	respR, respW := io.Pipe()
	h := &kvHost{store: map[string][]byte{}, digest: digest}
	go func() {
		scanner := bufio.NewScanner(outR)
		scanner.Buffer(make([]byte, 0, 64<<10), 8<<20)
		for scanner.Scan() {
			var frame struct {
				HostCall struct {
					ID     string                     `json:"id"`
					Method string                     `json:"method"`
					Params map[string]json.RawMessage `json:"params"`
				} `json:"host_call"`
			}
			if err := json.Unmarshal(scanner.Bytes(), &frame); err != nil {
				return
			}
			result, failure := h.serve(frame.HostCall.Method, frame.HostCall.Params)
			resp := map[string]any{"id": frame.HostCall.ID, "ok": failure == ""}
			if failure == "" {
				resp["result"] = result
			} else {
				resp["error"] = failure
			}
			line, _ := json.Marshal(map[string]any{"host_response": resp})
			if _, err := respW.Write(append(line, '\n')); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { _ = outW.Close(); _ = respW.Close() })
	return NewHostClient(HostClientOptions{Output: outW, Responses: respR}), h
}

func (h *kvHost) serve(method string, params map[string]json.RawMessage) (any, string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	var key string
	_ = json.Unmarshal(params["key"], &key)
	switch method {
	case HostMethodKVGet:
		value, ok := h.store[key]
		if !ok {
			return map[string]any{"ok": false}, ""
		}
		out := map[string]any{"ok": true, "value_base64": base64.StdEncoding.EncodeToString(value)}
		if h.digest {
			out["sha256"] = KVValueDigest(value)
		}
		return out, ""
	case HostMethodKVPut:
		h.puts = append(h.puts, params)
		var encoded string
		_ = json.Unmarshal(params["value_base64"], &encoded)
		value, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, "kv.put value_base64: " + err.Error()
		}
		if raw, conditional := params["if_match"]; conditional {
			var ifMatch string
			_ = json.Unmarshal(raw, &ifMatch)
			stored, exists := h.store[key]
			switch {
			case ifMatch == "" && exists:
				return nil, "kv_conflict: the key exists"
			case ifMatch != "" && (!exists || KVValueDigest(stored) != ifMatch):
				return nil, "kv_conflict: the stored value changed"
			}
		}
		h.store[key] = value
		return map[string]any{}, ""
	}
	return nil, "unknown method"
}

// A conditional put with the digest the caller read writes; one with a digest
// another writer has since overtaken is refused as ErrKVConflict and leaves
// the other writer's value in place; an empty if_match is a create.
func TestKVPutIfMatchRefusesStaleDigest(t *testing.T) {
	host, kv := newKVHost(t, true)
	ctx := context.Background()

	if err := host.KVPutIfMatch(ctx, "index", []byte("v1"), ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := host.KVPutIfMatch(ctx, "index", []byte("again"), ""); !errors.Is(err, ErrKVConflict) {
		t.Fatalf("a second create must conflict, got %v", err)
	}
	value, digest, found, err := host.KVGetWithDigest(ctx, "index")
	if err != nil || !found || string(value) != "v1" || digest != KVValueDigest([]byte("v1")) {
		t.Fatalf("read: %q %q %v %v", value, digest, found, err)
	}
	// Another writer moves the value after our read.
	if err := host.KVPut(ctx, "index", []byte("v2-other")); err != nil {
		t.Fatal(err)
	}
	err = host.KVPutIfMatch(ctx, "index", []byte("v2-ours"), digest)
	if !errors.Is(err, ErrKVConflict) || !strings.Contains(err.Error(), "kv_conflict") {
		t.Fatalf("a stale digest must conflict, got %v", err)
	}
	if got, _, _ := host.KVGet(ctx, "index"); string(got) != "v2-other" {
		t.Fatalf("the refused put wrote: %q", got)
	}
	// Re-read and retry: the fresh digest writes.
	_, digest, _, err = host.KVGetWithDigest(ctx, "index")
	if err != nil {
		t.Fatal(err)
	}
	if err := host.KVPutIfMatch(ctx, "index", []byte("v3"), digest); err != nil {
		t.Fatalf("a fresh digest refused: %v", err)
	}
	if got, _, _ := host.KVGet(ctx, "index"); string(got) != "v3" {
		t.Fatalf("value = %q", got)
	}
	// A digest on a missing key conflicts too.
	if err := host.KVPutIfMatch(ctx, "missing", []byte("x"), digest); !errors.Is(err, ErrKVConflict) {
		t.Fatalf("a digest on a missing key must conflict, got %v", err)
	}
	// The wire: if_match is always present on a conditional put, empty
	// included, and absent on a plain put.
	kv.mu.Lock()
	defer kv.mu.Unlock()
	if _, ok := kv.puts[0]["if_match"]; !ok || string(kv.puts[0]["if_match"]) != `""` {
		t.Fatalf("a create must send an empty if_match: %v", kv.puts[0])
	}
	if _, ok := kv.puts[2]["if_match"]; ok {
		t.Fatalf("a plain put must not send if_match: %v", kv.puts[2])
	}
	// A malformed digest never reaches the host.
	before := len(kv.puts)
	kv.mu.Unlock()
	err = host.KVPutIfMatch(ctx, "index", []byte("x"), strings.ToUpper(digest))
	kv.mu.Lock()
	if err == nil || errors.Is(err, ErrKVConflict) || len(kv.puts) != before {
		t.Fatalf("an upper-case digest: err=%v puts=%d", err, len(kv.puts)-before)
	}
}

// kv.get reports the stored value's sha256; a missing key reports none; a
// host older than the compare-and-swap reports none for a present key; and a
// digest that does not match the value is refused.
func TestKVGetReturnsDigest(t *testing.T) {
	host, kv := newKVHost(t, true)
	ctx := context.Background()
	if _, digest, found, err := host.KVGetWithDigest(ctx, "absent"); err != nil || found || digest != "" {
		t.Fatalf("absent: %q %v %v", digest, found, err)
	}
	payload := []byte(`{"records":["a","b"]}`)
	kv.store["index"] = payload
	value, digest, found, err := host.KVGetWithDigest(ctx, "index")
	if err != nil || !found || string(value) != string(payload) {
		t.Fatalf("read: %q %v %v", value, found, err)
	}
	if digest != KVValueDigest(payload) || len(digest) != 64 || strings.ToLower(digest) != digest {
		t.Fatalf("digest = %q", digest)
	}
	// KVGet is unchanged by the digest field.
	if plain, ok, err := host.KVGet(ctx, "index"); err != nil || !ok || string(plain) != string(payload) {
		t.Fatalf("KVGet: %q %v %v", plain, ok, err)
	}

	old, oldKV := newKVHost(t, false)
	oldKV.store["index"] = payload
	if value, digest, found, err := old.KVGetWithDigest(ctx, "index"); err != nil || !found || digest != "" || string(value) != string(payload) {
		t.Fatalf("older host: %q %q %v %v", value, digest, found, err)
	}

	lying := NewHostClient(HostClientOptions{Output: io.Discard, Responses: strings.NewReader(
		`{"host_response":{"id":"h1","ok":true,"result":{"ok":true,"value_base64":"` + base64.StdEncoding.EncodeToString(payload) +
			`","sha256":"` + KVValueDigest([]byte("other")) + `"}}}` + "\n")})
	if _, _, _, err := lying.KVGetWithDigest(ctx, "index"); err == nil {
		t.Fatal("a digest that does not match the value was accepted")
	}
}
