package model

import (
	"net"
	"strings"
	"testing"
	"unicode"
)

// validSubscriptionHostSpec is validSubscriptionHost as it was before the
// parse was skipped for host names: the specification the fast path is held
// to.
func validSubscriptionHostSpec(value string) bool {
	if ip := net.ParseIP(value); ip != nil {
		return ip.String() == value
	}
	if len(value) == 0 || len(value) > 253 || value != strings.ToLower(value) || strings.HasPrefix(value, ".") || strings.HasSuffix(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

var catalogueTextSeeds = []string{
	"", "a", "PRIVATE KEY", "private key", "-----BEGIN PRIVATE KEY-----", "PrIvAtE kEy", "private  key", "privatekey",
	"prıvate key", "PRİVATE KEY", "ſ", "x private ke", "tail: private key",
	"\x00", "\x1f", " ", "~", "\x7f", "\u0085", "\u009f", " ", "a​b", "abc\xff", "\xc2", "\xc2\x85",
	"1.2.3.4", "01.2.3.4", "::1", "::ffff:1.2.3.4", "2001:DB8::1", "2001:db8::1", "fe80::1%eth0", "1.2.3.4%x",
	"cafe.be", "bad.cafe", "example.com", "Example.com", "a..b", ".a", "a.", "-a.b", "a-.b", "a_b.c",
	strings.Repeat("a", 63) + ".com", strings.Repeat("a", 64) + ".com",
}

func FuzzCatalogueTextChecksAgreeWithTheirSpecification(f *testing.F) {
	for _, seed := range catalogueTextSeeds {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if got, want := containsControl(value), strings.ContainsFunc(value, unicode.IsControl); got != want {
			t.Fatalf("containsControl(%q) = %v, ContainsFunc(IsControl) = %v", value, got, want)
		}
		if got, want := containsPrivateKey(value), strings.Contains(strings.ToUpper(value), privateKeyMarker); got != want {
			t.Fatalf("containsPrivateKey(%q) = %v, Contains(ToUpper) = %v", value, got, want)
		}
		if got, want := validSubscriptionHost(value), validSubscriptionHostSpec(value); got != want {
			t.Fatalf("validSubscriptionHost(%q) = %v, specification %v", value, got, want)
		}
		if !ipLiteralBytes(value) && net.ParseIP(value) != nil {
			t.Fatalf("ipLiteralBytes(%q) = false, but net.ParseIP accepts it", value)
		}
	})
}

func TestCatalogueTextChecksAnswerTheSeeds(t *testing.T) {
	for _, value := range []string{"prıvate key", "-----BEGIN PRIVATE KEY-----", "PrIvAtE kEy"} {
		if !containsPrivateKey(value) {
			t.Fatalf("containsPrivateKey(%q) = false", value)
		}
	}
	for _, value := range []string{"private  key", "privatekey", "x private ke"} {
		if containsPrivateKey(value) {
			t.Fatalf("containsPrivateKey(%q) = true", value)
		}
	}
	for _, value := range []string{"\x00", "\x7f", "a\u0085"} {
		if !containsControl(value) {
			t.Fatalf("containsControl(%q) = false", value)
		}
	}
	for _, value := range []string{"cafe.be", "example.com", "2001:db8::1", "1.2.3.4"} {
		if !validSubscriptionHost(value) {
			t.Fatalf("validSubscriptionHost(%q) = false", value)
		}
	}
	for _, value := range []string{"2001:DB8::1", "Example.com", "fe80::1%eth0"} {
		if validSubscriptionHost(value) {
			t.Fatalf("validSubscriptionHost(%q) = true", value)
		}
	}
}

func BenchmarkCatalogueTextChecks(b *testing.B) {
	values := []string{"edge-17.tokyo.example.net", "vless reality tokyo 17", "chrome", "h2,http/1.1", "/ws?ed=2048"}
	b.ReportAllocs()
	for b.Loop() {
		for _, value := range values {
			_ = containsControl(value)
			_ = containsPrivateKey(value)
			_ = validSubscriptionHost(value)
		}
	}
}
