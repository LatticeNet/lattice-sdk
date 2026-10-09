package plugin

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const (
	DefaultInvokeTimeoutMS   = 10_000
	DefaultInvokeStdoutBytes = 1 << 20
	DefaultInvokeStderrBytes = 1 << 20
	DefaultInvokeHostCalls   = 64

	HostMaxInvokeTimeoutMS   = 30_000
	HostMaxInvokeStdoutBytes = 8 << 20
	HostMaxInvokeStderrBytes = 1 << 20
	// HostMaxInvokeHostCalls matches lattice-server's internal/plugin
	// invoke_budget.go, which is what core enforces. Core raised it from 64
	// to 512 for the store-bounded shapes of the official plugins (an export
	// reads one key per record, 256 records plus the index and Settings);
	// a manifest this helper refuses would load, and one it accepts at the
	// old cap was only a narrower subset.
	HostMaxInvokeHostCalls = 512

	// DefaultInvokeHTTPResponseBytes is the HTTP response body a host call
	// may return to a method whose budget names none.
	DefaultInvokeHTTPResponseBytes = 256 << 10
	// HostMaxInvokeHTTPResponseBytes is the most a signed budget may name.
	// Design 28 signs it for the subscription service's fetch and for an
	// artifact restore.
	HostMaxInvokeHTTPResponseBytes = 8 << 20
)

// InvokeBudgetSpec is signed method-level runtime data. Absent budgets stay
// additive on the host and resolve to the old global defaults.
type InvokeBudgetSpec struct {
	TimeoutMS   int `json:"timeout_ms"`
	StdoutBytes int `json:"stdout_bytes"`
	StderrBytes int `json:"stderr_bytes"`
	HostCalls   int `json:"host_calls"`
	// HTTPResponseBytes bounds the body of each HTTP response a host call
	// (http.do, http.operator.do) returns to this method. Optional: zero is
	// absent from the wire and resolves to DefaultInvokeHTTPResponseBytes,
	// so a budget signed before the field existed keeps its bytes and its
	// meaning. When present it must be positive.
	HTTPResponseBytes int `json:"http_response_bytes,omitempty"`
}

func (b *InvokeBudgetSpec) UnmarshalJSON(data []byte) error {
	var raw struct {
		TimeoutMS   *int `json:"timeout_ms"`
		StdoutBytes *int `json:"stdout_bytes"`
		StderrBytes *int `json:"stderr_bytes"`
		HostCalls   *int `json:"host_calls"`

		HTTPResponseBytes *int `json:"http_response_bytes"`
	}
	if err := decodeStrict(data, &raw); err != nil {
		return err
	}
	if raw.TimeoutMS == nil || raw.StdoutBytes == nil || raw.StderrBytes == nil || raw.HostCalls == nil {
		return errors.New("invoke budget requires timeout_ms, stdout_bytes, stderr_bytes and host_calls")
	}
	// An explicit zero would encode back as absent, which means the default:
	// a signed budget must mean what its bytes say, so zero is refused.
	if raw.HTTPResponseBytes != nil && *raw.HTTPResponseBytes <= 0 {
		return errors.New("invoke budget http_response_bytes must be positive when present")
	}
	*b = InvokeBudgetSpec{
		TimeoutMS:   *raw.TimeoutMS,
		StdoutBytes: *raw.StdoutBytes,
		StderrBytes: *raw.StderrBytes,
		HostCalls:   *raw.HostCalls,
	}
	if raw.HTTPResponseBytes != nil {
		b.HTTPResponseBytes = *raw.HTTPResponseBytes
	}
	return nil
}

func (b InvokeBudgetSpec) MarshalJSON() ([]byte, error) {
	type wire InvokeBudgetSpec
	return json.Marshal(wire(b))
}

func DefaultInvokeBudgetSpec() InvokeBudgetSpec {
	return InvokeBudgetSpec{
		TimeoutMS:   DefaultInvokeTimeoutMS,
		StdoutBytes: DefaultInvokeStdoutBytes,
		StderrBytes: DefaultInvokeStderrBytes,
		HostCalls:   DefaultInvokeHostCalls,
	}
}

func ValidateInvokeBudgetSpec(b InvokeBudgetSpec) error {
	if err := validateInvokeBudgetPositive(b); err != nil {
		return err
	}
	if b.TimeoutMS > HostMaxInvokeTimeoutMS {
		return fmt.Errorf("timeout_ms %d exceeds host maximum %d", b.TimeoutMS, HostMaxInvokeTimeoutMS)
	}
	if b.StdoutBytes > HostMaxInvokeStdoutBytes {
		return fmt.Errorf("stdout_bytes %d exceeds host maximum %d", b.StdoutBytes, HostMaxInvokeStdoutBytes)
	}
	if b.StderrBytes > HostMaxInvokeStderrBytes {
		return fmt.Errorf("stderr_bytes %d exceeds host maximum %d", b.StderrBytes, HostMaxInvokeStderrBytes)
	}
	if b.HostCalls > HostMaxInvokeHostCalls {
		return fmt.Errorf("host_calls %d exceeds host maximum %d", b.HostCalls, HostMaxInvokeHostCalls)
	}
	if b.HTTPResponseBytes > HostMaxInvokeHTTPResponseBytes {
		return fmt.Errorf("http_response_bytes %d exceeds host maximum %d", b.HTTPResponseBytes, HostMaxInvokeHTTPResponseBytes)
	}
	return nil
}

func validateInvokeBudgetPositive(b InvokeBudgetSpec) error {
	if b.TimeoutMS <= 0 {
		return errors.New("timeout_ms must be positive")
	}
	if b.StdoutBytes <= 0 {
		return errors.New("stdout_bytes must be positive")
	}
	if b.StderrBytes <= 0 {
		return errors.New("stderr_bytes must be positive")
	}
	if b.HostCalls < 0 {
		return errors.New("host_calls must be non-negative")
	}
	if b.HTTPResponseBytes < 0 {
		return errors.New("http_response_bytes must be non-negative")
	}
	return nil
}

// ResolvedInvokeBudget is the budget an invocation runs under, with every
// default applied and every value clamped to the host maxima.
type ResolvedInvokeBudget struct {
	Timeout     time.Duration
	StdoutBytes int
	StderrBytes int
	HostCalls   int
	// HTTPResponseBytes bounds each HTTP response body a host call returns.
	HTTPResponseBytes int
	Declared          bool
}

func ResolveInvokeBudget(spec *InvokeBudgetSpec, defaults InvokeBudgetSpec) ResolvedInvokeBudget {
	declared := spec != nil
	b := defaults
	if declared {
		b = *spec
	}
	b = clampInvokeBudget(b)
	if b.TimeoutMS <= 0 {
		b.TimeoutMS = DefaultInvokeTimeoutMS
	}
	if b.StdoutBytes <= 0 {
		b.StdoutBytes = DefaultInvokeStdoutBytes
	}
	if b.StderrBytes <= 0 {
		b.StderrBytes = DefaultInvokeStderrBytes
	}
	if b.HostCalls < 0 {
		b.HostCalls = 0
	}
	if b.HTTPResponseBytes <= 0 {
		b.HTTPResponseBytes = DefaultInvokeHTTPResponseBytes
	}
	return ResolvedInvokeBudget{
		Timeout:           time.Duration(b.TimeoutMS) * time.Millisecond,
		StdoutBytes:       b.StdoutBytes,
		StderrBytes:       b.StderrBytes,
		HostCalls:         b.HostCalls,
		HTTPResponseBytes: b.HTTPResponseBytes,
		Declared:          declared,
	}
}

func clampInvokeBudget(b InvokeBudgetSpec) InvokeBudgetSpec {
	if b.TimeoutMS > HostMaxInvokeTimeoutMS {
		b.TimeoutMS = HostMaxInvokeTimeoutMS
	}
	if b.StdoutBytes > HostMaxInvokeStdoutBytes {
		b.StdoutBytes = HostMaxInvokeStdoutBytes
	}
	if b.StderrBytes > HostMaxInvokeStderrBytes {
		b.StderrBytes = HostMaxInvokeStderrBytes
	}
	if b.HostCalls > HostMaxInvokeHostCalls {
		b.HostCalls = HostMaxInvokeHostCalls
	}
	if b.HTTPResponseBytes > HostMaxInvokeHTTPResponseBytes {
		b.HTTPResponseBytes = HostMaxInvokeHTTPResponseBytes
	}
	return b
}
