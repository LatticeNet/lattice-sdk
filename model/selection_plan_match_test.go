package model

import (
	"strings"
	"testing"
)

// isUUIDv4 and splitPlaceholderBody stand in for the regular expressions
// they replaced; these hold them to those expressions.
func sameAsTheExpressions(t *testing.T, s string) {
	t.Helper()
	if got, want := isUUIDv4(s), subscriptionSourceUUIDv4.MatchString(s); got != want {
		t.Fatalf("isUUIDv4(%q) = %v, the expression %v", s, got, want)
	}
	line, field, ok := splitPlaceholderBody(s)
	match := planPlaceholderBody.FindStringSubmatch(s)
	want := match != nil && len(match[0]) == len(s)
	if ok != want || ok && (line != match[1] || field != match[2]) {
		t.Fatalf("splitPlaceholderBody(%q) = %q, %q, %v; the expression %q", s, line, field, ok, match)
	}
}

var expressionCorpus = []string{
	"3f2b8c1e-7d4a-4e5f-9a6b-1c2d3e4f5a6b", "3F2B8C1E-7D4A-4E5F-9A6B-1C2D3E4F5A6B", "3f2b8c1e-7d4a-1e5f-9a6b-1c2d3e4f5a6b",
	"3f2b8c1e-7d4a-4e5f-ca6b-1c2d3e4f5a6b", "3f2b8c1e7d4a4e5f9a6b1c2d3e4f5a6b", "", "3f2b8c1e-7d4a-4e5f-9a6b-1c2d3e4f5a6b\n",
	"3f2b8c1e-7d4a-4e5f-9a6b-1c2d3e4f5a6b-uuid-0123456789abcdef0123456789abcdef",
	"3f2b8c1e-7d4a-4e5f-9a6b-1c2d3e4f5a6b-u-0123456789abcdef0123456789abcdef",
	"3f2b8c1e-7d4a-4e5f-9a6b-1c2d3e4f5a6b-" + strings.Repeat("f", 32) + "-0123456789abcdef0123456789abcdef",
	"3f2b8c1e-7d4a-4e5f-9a6b-1c2d3e4f5a6b-" + strings.Repeat("f", 33) + "-0123456789abcdef0123456789abcdef",
	"3f2b8c1e-7d4a-4e5f-9a6b-1c2d3e4f5a6b-private_key2-0123456789abcdef0123456789abcdef",
	"3f2b8c1e-7d4a-4e5f-9a6b-1c2d3e4f5a6b-private-key-0123456789abcdef0123456789abcdef",
	"3f2b8c1e-7d4a-4e5f-9a6b-1c2d3e4f5a6b-1uuid-0123456789abcdef0123456789abcdef",
	"3f2b8c1e-7d4a-4e5f-9a6b-1c2d3e4f5a6b-uuid-0123456789ABCDEF0123456789abcdef",
	"3f2b8c1e-7d4a-4e5f-9a6b-1c2d3e4f5a6b-uuid-0123456789abcdef0123456789abcde",
	"3f2b8c1e-7d4a-4e5f-9a6b-1c2d3e4f5a6b-uuid-0123456789abcdef0123456789abcdef0",
	"3f2b8c1e-7d4a-4e5f-9a6b-1c2d3e4f5a6b--0123456789abcdef0123456789abcdef",
	"3f2b8c1e-7d4a-4e5f-9a6b-1c2d3e4f5a6b-uuid-0123456789abcdef0123456789abcdef ",
}

func TestMatchersAgreeWithTheExpressions(t *testing.T) {
	for _, s := range expressionCorpus {
		sameAsTheExpressions(t, s)
	}
}

func FuzzMatchersAgreeWithTheExpressions(f *testing.F) {
	for _, s := range expressionCorpus {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		sameAsTheExpressions(t, s)
	})
}
