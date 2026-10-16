package beacon

import (
	"testing"
	"time"
)

// FuzzResponderHandle feeds arbitrary datagrams to a responder holding a
// table. Any panic fails the fuzz run; so does a reply to anything but an
// exactly RequestLen datagram, or a reply that is not exactly ReplyLen.
func FuzzResponderHandle(f *testing.F) {
	target := testKey(1)
	key := DerivePathKey(&target, 3, 7)
	now := t0.Add(time.Minute)
	good := make([]byte, RequestLen)
	req := Request{Epoch: 7, SourceID: 3, Seq: 1, SentUnixNano: now.UnixNano()}
	_, _ = EncodeRequest(good, &key, &req)
	f.Add(good)
	f.Add(good[:95])
	f.Add(append(append([]byte(nil), good...), 0))
	f.Add([]byte(Magic))
	f.Add(make([]byte, RequestLen))
	f.Add(make([]byte, ReadBufferLen))
	r := NewResponder(t0)
	if err := r.SetTable([]TableEntry{{SourceID: 3, Epoch: 7, Key: key}, {SourceID: 4, Epoch: 1, Key: key, Retired: true}}); err != nil {
		f.Fatal(err)
	}
	out := make([]byte, ReplyLen)
	f.Fuzz(func(t *testing.T, pkt []byte) {
		n, v := r.Handle(now, pkt, out)
		if n != 0 && n != ReplyLen {
			t.Fatalf("reply of %d bytes", n)
		}
		if n != 0 && len(pkt) != RequestLen {
			t.Fatalf("replied to a %d-byte datagram", len(pkt))
		}
		if (n != 0) != v.Replied() {
			t.Fatalf("verdict %v with %d bytes", v, n)
		}
		if n != 0 {
			if _, err := ParseReply(out[:n], &key); err != nil {
				t.Fatalf("reply does not verify: %v", err)
			}
		}
	})
}

// FuzzParseRequest and FuzzParseReply fail on any panic and on a parse that
// accepts a datagram of the wrong length.
func FuzzParseRequest(f *testing.F) {
	key := testKey(2)
	good := make([]byte, RequestLen)
	req := Request{Epoch: 1, SourceID: 1}
	_, _ = EncodeRequest(good, &key, &req)
	f.Add(good)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, pkt []byte) {
		if _, err := ParseRequest(pkt); err == nil && len(pkt) != RequestLen {
			t.Fatalf("parsed a %d-byte request", len(pkt))
		}
		if VerifyRequest(pkt, &key) && len(pkt) != RequestLen {
			t.Fatalf("verified a %d-byte request", len(pkt))
		}
	})
}

func FuzzParseReply(f *testing.F) {
	key := testKey(2)
	good := make([]byte, ReplyLen)
	_, _ = EncodeReply(good, &key, &Reply{Status: StatusOK})
	f.Add(good)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, pkt []byte) {
		if _, err := ParseReply(pkt, &key); err == nil && len(pkt) != ReplyLen {
			t.Fatalf("parsed a %d-byte reply", len(pkt))
		}
	})
}
