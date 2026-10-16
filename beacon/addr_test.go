package beacon

import (
	"errors"
	"testing"
)

func TestParseEndpoint(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
		err  error
	}{
		{"203.0.113.7:45001", "203.0.113.7:45001", nil},
		{"10.0.0.5:51000", "10.0.0.5:51000", nil}, // a node reached privately
		{"100.64.1.1:40000", "100.64.1.1:40000", nil},
		{"203.0.113.7:1", "203.0.113.7:1", nil},
		{"example.com:45001", "", ErrNotIPv4Literal},
		{"203.0.113.7", "", ErrNotIPv4Literal},
		{"[2001:db8::1]:45001", "", ErrNotIPv4Literal},
		{"::ffff:203.0.113.7:45001", "", ErrNotIPv4Literal},
		{"203.0.113.07:45001", "", ErrNotIPv4Literal},
		{"127.0.0.1:45001", "", ErrAddressRefused},
		{"169.254.169.254:80", "", ErrAddressRefused},
		{"224.0.0.1:45001", "", ErrAddressRefused},
		{"255.255.255.255:45001", "", ErrAddressRefused},
		{"240.0.0.1:45001", "", ErrAddressRefused},
		{"0.0.0.0:45001", "", ErrAddressRefused},
		{"203.0.113.7:0", "", ErrPort},
		{"203.0.113.7:65536", "", ErrPort},
		{"203.0.113.7:045001", "", ErrPort},
		{"203.0.113.7:+45001", "", ErrPort},
	} {
		got, err := ParseEndpoint(c.in)
		if c.err != nil {
			if !errors.Is(err, c.err) {
				t.Errorf("%q: %v, want %v", c.in, err, c.err)
			}
			continue
		}
		if err != nil || got.String() != c.want {
			t.Errorf("%q: %v, %v", c.in, got, err)
		}
	}
}

func TestParseIPv4AndPorts(t *testing.T) {
	if _, err := ParseIPv4("0.0.0.0"); !errors.Is(err, ErrAddressRefused) {
		t.Fatalf("the wildcard must be refused as a bind address: %v", err)
	}
	if _, err := ParseIPv4("10.1.2.3"); err != nil {
		t.Fatalf("a NAT node's private bind address: %v", err)
	}
	for port, ok := range map[int]bool{1023: false, 1024: true, PortRandomMin: true, PortRandomMax: true, 65535: true, 65536: false, 0: false} {
		if ValidListenPort(port) != ok {
			t.Errorf("ValidListenPort(%d) != %v", port, ok)
		}
	}
}
