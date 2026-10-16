package beacon

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
	"time"
)

func testKey(b byte) Key {
	var k Key
	for i := range k {
		k[i] = b + byte(i)
	}
	return k
}

func testRequest(sent time.Time) Request {
	req := Request{Epoch: 7, SourceID: 3, Seq: 42, SentUnixNano: sent.UnixNano()}
	for i := range req.Nonce {
		req.Nonce[i] = byte(0xa0 + i)
	}
	return req
}

// TestDerivePathKeyMatchesTheWrittenRule recomputes K_path from the rule as
// D12 states it, byte by byte, so the derivation cannot drift from the
// document without this test failing.
func TestDerivePathKeyMatchesTheWrittenRule(t *testing.T) {
	target := testKey(1)
	mac := hmac.New(sha256.New, target[:])
	mac.Write([]byte{0, 0, 0, 17})
	mac.Write([]byte("lattice-beacon/v1"))
	mac.Write([]byte{0, 0, 0, 4, 0, 0, 0, 3})
	mac.Write([]byte{0, 0, 0, 4, 0, 0, 0, 7})
	want := mac.Sum(nil)
	got := DerivePathKey(&target, 3, 7)
	if !bytes.Equal(got[:], want) {
		t.Fatalf("DerivePathKey = %x, want %x", got, want)
	}
	// The same vector computed outside Go (Python hmac), recorded in D12 for
	// implementations in other languages: target key bytes 0x01..0x20,
	// source 3, epoch 7.
	const vector = "95d783026533fad67f52bd4556f8f5a16f4067f379b7663a37082a0a784344a8"
	if hex.EncodeToString(got[:]) != vector {
		t.Fatalf("DerivePathKey = %x, want the recorded vector %s", got, vector)
	}
}

func TestDerivePathKeyIsDistinctPerSourceEpochAndTarget(t *testing.T) {
	a, b := testKey(1), testKey(2)
	seen := map[Key]string{}
	for _, c := range []struct {
		name   string
		target *Key
		source uint32
		epoch  uint32
	}{
		{"base", &a, 3, 7},
		{"source", &a, 4, 7},
		{"epoch", &a, 3, 8},
		{"swapped", &a, 7, 3},
		{"target", &b, 3, 7},
	} {
		k := DerivePathKey(c.target, c.source, c.epoch)
		if prev, ok := seen[k]; ok {
			t.Fatalf("%s derives the same key as %s", c.name, prev)
		}
		seen[k] = c.name
	}
}

func TestRequestRoundTrip(t *testing.T) {
	key := testKey(9)
	req := testRequest(time.Unix(1_800_000_000, 5))
	buf := make([]byte, ReadBufferLen)
	n, err := EncodeRequest(buf, &key, &req)
	if err != nil || n != RequestLen {
		t.Fatalf("EncodeRequest = %d, %v", n, err)
	}
	pkt := buf[:n]
	if string(pkt[:4]) != Magic || pkt[4] != Version {
		t.Fatalf("frame = %x", pkt[:5])
	}
	got, err := ParseRequest(pkt)
	if err != nil || got != req {
		t.Fatalf("ParseRequest = %+v, %v; want %+v", got, err, req)
	}
	if !VerifyRequest(pkt, &key) {
		t.Fatal("VerifyRequest refused its own request")
	}
	other := testKey(10)
	if VerifyRequest(pkt, &other) {
		t.Fatal("VerifyRequest accepted another key")
	}
	if _, err := EncodeRequest(buf, &key, &Request{Epoch: 1}); !errors.Is(err, ErrIDs) {
		t.Fatalf("zero source id: %v", err)
	}
	if _, err := EncodeRequest(buf[:95], &key, &req); !errors.Is(err, ErrLength) {
		t.Fatalf("short buffer: %v", err)
	}
}

func TestReplyRoundTripAndRefusals(t *testing.T) {
	key := testKey(9)
	rep := Reply{Status: StatusStale, Seq: 9, ResponderUnixNano: 123}
	rep.Nonce[0] = 1
	buf := make([]byte, ReplyLen)
	if n, err := EncodeReply(buf, &key, &rep); err != nil || n != ReplyLen {
		t.Fatalf("EncodeReply = %d, %v", n, err)
	}
	got, err := ParseReply(buf, &key)
	if err != nil || got != rep {
		t.Fatalf("ParseReply = %+v, %v", got, err)
	}
	other := testKey(10)
	if _, err := ParseReply(buf, &other); !errors.Is(err, ErrTag) {
		t.Fatalf("other key: %v", err)
	}
	if _, err := ParseReply(append(bytes.Clone(buf), 0), &key); !errors.Is(err, ErrLength) {
		t.Fatalf("long reply: %v", err)
	}
	if _, err := EncodeReply(buf, &key, &Reply{Status: 9}); !errors.Is(err, ErrStatus) {
		t.Fatalf("unknown status: %v", err)
	}
	for i := 0; i < ReplyLen; i++ {
		bad := bytes.Clone(buf)
		bad[i] ^= 0x01
		if _, err := ParseReply(bad, &key); err == nil {
			t.Fatalf("a reply with byte %d flipped parsed", i)
		}
	}
}

func TestParseRequestRefusals(t *testing.T) {
	key := testKey(9)
	req := testRequest(time.Unix(1_800_000_000, 0))
	good := make([]byte, RequestLen)
	if _, err := EncodeRequest(good, &key, &req); err != nil {
		t.Fatal(err)
	}
	mutate := func(f func([]byte) []byte) []byte { return f(bytes.Clone(good)) }
	cases := []struct {
		name string
		pkt  []byte
		want error
	}{
		{"empty", nil, ErrLength},
		{"95", good[:95], ErrLength},
		{"97 with a valid prefix", append(bytes.Clone(good), 0), ErrLength},
		{"128", make([]byte, 128), ErrLength},
		{"magic", mutate(func(b []byte) []byte { b[0] = 'X'; return b }), ErrMagic},
		{"version", mutate(func(b []byte) []byte { b[4] = 2; return b }), ErrVersion},
		{"padding", mutate(func(b []byte) []byte { b[60] = 1; return b }), ErrPadding},
	}
	for _, c := range cases {
		if _, err := ParseRequest(c.pkt); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", c.name, err, c.want)
		}
		if VerifyRequest(c.pkt, &key) {
			t.Errorf("%s: verified", c.name)
		}
	}
}

func TestLayoutConstants(t *testing.T) {
	if ReplyLen >= RequestLen {
		t.Fatalf("a reply (%d) must be smaller than a request (%d)", ReplyLen, RequestLen)
	}
	if ReadBufferLen <= RequestLen {
		t.Fatal("the read buffer must exceed a request so a longer datagram is seen as longer")
	}
	if reqOffPad != 41 || reqOffTag != 80 || repOffPad != 34 || repOffTag != 48 {
		t.Fatal("wire offsets moved; D12 documents them")
	}
	if NonceCacheSize != 2400 {
		t.Fatalf("NonceCacheSize = %d, want 20/s times 120 s", NonceCacheSize)
	}
	var b [8]byte
	neg := int64(-1)
	binary.BigEndian.PutUint64(b[:], uint64(neg))
	if int64(binary.BigEndian.Uint64(b[:])) != neg {
		t.Fatal("signed timestamps must round trip")
	}
}
