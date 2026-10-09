package plugin

import (
	"encoding/json"
	"strings"
	"testing"
)

// goldenBudget is what lattice-sdk at 14636fd encodes for the fetch budget
// the Sub-Store manifest signs today, alone and inside its method.
const (
	goldenBudget = `{"timeout_ms":30000,"stdout_bytes":8388608,"stderr_bytes":1048576,"host_calls":78}`
	goldenMethod = `{"name":"fetch","effect":"read","scopes":["substore:admin"],"budget":` + goldenBudget + `}`
)

func TestBudgetSignedBeforeHTTPResponseBytesKeepsItsBytes(t *testing.T) {
	var budget InvokeBudgetSpec
	if err := json.Unmarshal([]byte(goldenBudget), &budget); err != nil {
		t.Fatal(err)
	}
	if budget.HTTPResponseBytes != 0 {
		t.Fatalf("old budget decoded with http_response_bytes %d", budget.HTTPResponseBytes)
	}
	raw, err := json.Marshal(budget)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != goldenBudget {
		t.Fatalf("budget bytes changed:\n got %s\nwant %s", raw, goldenBudget)
	}
	var method InterfaceMethod
	if err := json.Unmarshal([]byte(goldenMethod), &method); err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(method); string(raw) != goldenMethod {
		t.Fatalf("method bytes changed:\n got %s\nwant %s", raw, goldenMethod)
	}
	if got := ResolveInvokeBudget(&budget, DefaultInvokeBudgetSpec()).HTTPResponseBytes; got != DefaultInvokeHTTPResponseBytes {
		t.Fatalf("absent http_response_bytes resolved to %d, want the 256 KiB default", got)
	}
}

func TestBudgetHTTPResponseBytesRoundTripsAndResolves(t *testing.T) {
	in := `{"timeout_ms":30000,"stdout_bytes":8388608,"stderr_bytes":1048576,"host_calls":64,"http_response_bytes":8388608}`
	var budget InvokeBudgetSpec
	if err := json.Unmarshal([]byte(in), &budget); err != nil {
		t.Fatal(err)
	}
	if raw, _ := json.Marshal(budget); string(raw) != in {
		t.Fatalf("budget with http_response_bytes re-encoded as %s", raw)
	}
	if err := ValidateInvokeBudgetSpec(budget); err != nil {
		t.Fatalf("8 MiB budget refused: %v", err)
	}
	if got := ResolveInvokeBudget(&budget, DefaultInvokeBudgetSpec()).HTTPResponseBytes; got != 8<<20 {
		t.Fatalf("resolved http_response_bytes = %d, want 8 MiB", got)
	}
	if got := ResolveInvokeBudget(nil, DefaultInvokeBudgetSpec()).HTTPResponseBytes; got != DefaultInvokeHTTPResponseBytes {
		t.Fatalf("undeclared budget resolved http_response_bytes to %d", got)
	}
}

func TestBudgetHTTPResponseBytesBounds(t *testing.T) {
	base := InvokeBudgetSpec{TimeoutMS: 1000, StdoutBytes: 1024, StderrBytes: 1024, HostCalls: 1}
	atMax, overMax, negative := base, base, base
	atMax.HTTPResponseBytes = HostMaxInvokeHTTPResponseBytes
	overMax.HTTPResponseBytes = HostMaxInvokeHTTPResponseBytes + 1
	negative.HTTPResponseBytes = -1
	if err := ValidateInvokeBudgetSpec(atMax); err != nil {
		t.Fatalf("budget at the host maximum refused: %v", err)
	}
	if err := ValidateInvokeBudgetSpec(overMax); err == nil || !strings.Contains(err.Error(), "http_response_bytes") {
		t.Fatalf("budget one byte over the host maximum: err = %v", err)
	}
	if err := ValidateInvokeBudgetSpec(negative); err == nil {
		t.Fatal("negative http_response_bytes accepted")
	}
	if got := ResolveInvokeBudget(&overMax, DefaultInvokeBudgetSpec()).HTTPResponseBytes; got != HostMaxInvokeHTTPResponseBytes {
		t.Fatalf("over-maximum budget resolved to %d, want the clamp", got)
	}
	for _, value := range []string{"0", "-1"} {
		raw := `{"timeout_ms":1,"stdout_bytes":1,"stderr_bytes":1,"host_calls":0,"http_response_bytes":` + value + `}`
		var b InvokeBudgetSpec
		if err := json.Unmarshal([]byte(raw), &b); err == nil {
			t.Fatalf("explicit http_response_bytes %s accepted; it would re-encode as absent", value)
		}
	}
}

// The host-call ceiling is core's: a signed budget core loads must validate
// here, and one past it must not.
func TestBudgetHostCallsBoundIsCores(t *testing.T) {
	base := InvokeBudgetSpec{TimeoutMS: 1000, StdoutBytes: 1024, StderrBytes: 1024}
	atMax, overMax := base, base
	atMax.HostCalls, overMax.HostCalls = 512, 513
	if err := ValidateInvokeBudgetSpec(atMax); err != nil {
		t.Fatalf("512 host calls, which core accepts, refused: %v", err)
	}
	if err := ValidateInvokeBudgetSpec(overMax); err == nil || !strings.Contains(err.Error(), "host_calls") {
		t.Fatalf("513 host calls: err = %v", err)
	}
	if got := ResolveInvokeBudget(&overMax, DefaultInvokeBudgetSpec()).HostCalls; got != 512 {
		t.Fatalf("over-maximum host calls resolved to %d, want 512", got)
	}
}
