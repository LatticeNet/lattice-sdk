package beacon

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

var t0 = time.Unix(1_800_000_000, 0)

type fixture struct {
	r      *Responder
	target Key
	key    Key // path key of source 3, epoch 7
	seq    uint32
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{r: NewResponder(t0), target: testKey(1)}
	f.key = DerivePathKey(&f.target, 3, 7)
	if err := f.r.SetTable([]TableEntry{{SourceID: 3, Epoch: 7, Key: f.key}}); err != nil {
		t.Fatal(err)
	}
	return f
}

// request builds a fresh, signed request from source 3 at sent.
func (f *fixture) request(t *testing.T, sent time.Time) []byte {
	t.Helper()
	f.seq++
	req := Request{Epoch: 7, SourceID: 3, Seq: f.seq, SentUnixNano: sent.UnixNano()}
	req.Nonce[0], req.Nonce[1], req.Nonce[2] = byte(f.seq), byte(f.seq>>8), 0x5a
	buf := make([]byte, RequestLen)
	if _, err := EncodeRequest(buf, &f.key, &req); err != nil {
		t.Fatal(err)
	}
	return buf
}

func (f *fixture) handle(now time.Time, pkt []byte) ([]byte, Verdict) {
	out := make([]byte, ReplyLen)
	n, v := f.r.Handle(now, pkt, out)
	return out[:n], v
}

func TestHandleAnswersAFreshRequest(t *testing.T) {
	f := newFixture(t)
	now := t0.Add(time.Minute)
	pkt := f.request(t, now.Add(-30*time.Millisecond))
	rep, v := f.handle(now, pkt)
	if v != ReplyOK || len(rep) != ReplyLen {
		t.Fatalf("verdict %v, %d bytes", v, len(rep))
	}
	got, err := ParseReply(rep, &f.key)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := ParseRequest(pkt)
	if got.Status != StatusOK || got.Seq != req.Seq || got.Nonce != req.Nonce || got.ResponderUnixNano != now.UnixNano() {
		t.Fatalf("reply %+v for request %+v", got, req)
	}
	if !f.r.LastAuthenticated().Equal(now) {
		t.Fatalf("LastAuthenticated = %v", f.r.LastAuthenticated())
	}
}

// TestHandleRefusesEverythingD3Lists covers each rejection of D3 that must
// draw no reply at all.
func TestHandleRefusesEverythingD3Lists(t *testing.T) {
	now := t0.Add(time.Minute)
	cases := []struct {
		name string
		pkt  func(f *fixture) []byte
		want Verdict
	}{
		{"empty", func(*fixture) []byte { return nil }, DropLength},
		{"95 bytes", func(f *fixture) []byte { return f.request(t, now)[:95] }, DropLength},
		{"97 bytes with a valid 96-byte prefix", func(f *fixture) []byte { return append(f.request(t, now), 0) }, DropLength},
		{"128 bytes", func(f *fixture) []byte { return append(f.request(t, now), make([]byte, 32)...) }, DropLength},
		{"wrong magic", func(f *fixture) []byte { p := f.request(t, now); p[1] = 'X'; return p }, DropMalformed},
		{"wrong version", func(f *fixture) []byte { p := f.request(t, now); p[4] = 2; return p }, DropMalformed},
		{"padding not zero", func(f *fixture) []byte { p := f.request(t, now); p[79] = 1; return p }, DropMalformed},
		{"unknown source id", func(f *fixture) []byte {
			k := DerivePathKey(&f.target, 4, 7)
			req := Request{Epoch: 7, SourceID: 4, Seq: 1, SentUnixNano: now.UnixNano()}
			b := make([]byte, RequestLen)
			_, _ = EncodeRequest(b, &k, &req)
			return b
		}, DropUnknownSource},
		{"unknown epoch", func(f *fixture) []byte {
			k := DerivePathKey(&f.target, 3, 8)
			req := Request{Epoch: 8, SourceID: 3, Seq: 1, SentUnixNano: now.UnixNano()}
			b := make([]byte, RequestLen)
			_, _ = EncodeRequest(b, &k, &req)
			return b
		}, DropUnknownEpoch},
		{"wrong tag", func(f *fixture) []byte { p := f.request(t, now); p[95] ^= 1; return p }, DropBadTag},
		{"signed by the target key itself", func(f *fixture) []byte {
			req := Request{Epoch: 7, SourceID: 3, Seq: 1, SentUnixNano: now.UnixNano()}
			b := make([]byte, RequestLen)
			_, _ = EncodeRequest(b, &f.target, &req)
			return b
		}, DropBadTag},
		{"body changed after signing", func(f *fixture) []byte { p := f.request(t, now); p[20] ^= 1; return p }, DropBadTag},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			out := bytes.Repeat([]byte{0xee}, ReplyLen)
			n, v := f.r.Handle(now, c.pkt(f), out)
			if n != 0 || v != c.want {
				t.Fatalf("Handle = %d, %v; want no reply, %v", n, v, c.want)
			}
			if !bytes.Equal(out, bytes.Repeat([]byte{0xee}, ReplyLen)) {
				t.Fatal("a drop wrote into the reply buffer")
			}
			if v.Authenticated() || v.Replied() {
				t.Fatalf("%v counts as authenticated or replied", v)
			}
		})
	}
}

func TestHandleDropsAReplayedNonce(t *testing.T) {
	f := newFixture(t)
	now := t0.Add(time.Minute)
	pkt := f.request(t, now)
	if _, v := f.handle(now, pkt); v != ReplyOK {
		t.Fatalf("first: %v", v)
	}
	for _, later := range []time.Duration{0, time.Millisecond, 30 * time.Second, 59 * time.Second} {
		if rep, v := f.handle(now.Add(later), pkt); v != DropReplay || len(rep) != 0 {
			t.Fatalf("replay after %v: %v, %d bytes", later, v, len(rep))
		}
	}
	// Past the window the replay is no longer fresh: it draws one signed
	// stale reply, never a measurement.
	if _, v := f.handle(now.Add(61*time.Second), pkt); v != ReplyStale {
		t.Fatalf("replay past the window: %v", v)
	}
}

func TestHandleStaleTimestamps(t *testing.T) {
	now := t0.Add(10 * time.Minute)
	for _, c := range []struct {
		name string
		sent time.Time
	}{
		{"61 s behind", now.Add(-61 * time.Second)},
		{"63 s ahead", now.Add(63 * time.Second)},
		{"before the responder started", t0.Add(-time.Second)},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t)
			nowFor := now
			if c.name == "before the responder started" {
				nowFor = t0.Add(10 * time.Second)
			}
			rep, v := f.handle(nowFor, f.request(t, c.sent))
			if v != ReplyStale {
				t.Fatalf("verdict %v", v)
			}
			got, err := ParseReply(rep, &f.key)
			if err != nil || got.Status != StatusStale {
				t.Fatalf("reply %+v, %v", got, err)
			}
			// A second stale request inside NamedReplyInterval draws nothing.
			if rep, v := f.handle(nowFor.Add(500*time.Millisecond), f.request(t, c.sent)); v != DropNamedBudget || len(rep) != 0 {
				t.Fatalf("second stale: %v, %d bytes", v, len(rep))
			}
			if _, v := f.handle(nowFor.Add(1500*time.Millisecond), f.request(t, c.sent)); v != ReplyStale {
				t.Fatalf("stale after the interval: %v", v)
			}
		})
	}
	// Exactly at the window edge is still fresh.
	f := newFixture(t)
	if _, v := f.handle(now, f.request(t, now.Add(-FreshnessWindow))); v != ReplyOK {
		t.Fatalf("60 s behind: %v", v)
	}
}

func TestHandleRetiredEpochAnswersUnknownEpoch(t *testing.T) {
	f := newFixture(t)
	next := DerivePathKey(&f.target, 3, 8)
	if err := f.r.SetTable([]TableEntry{{SourceID: 3, Epoch: 7, Key: f.key, Retired: true}, {SourceID: 3, Epoch: 8, Key: next}}); err != nil {
		t.Fatal(err)
	}
	now := t0.Add(time.Minute)
	rep, v := f.handle(now, f.request(t, now))
	if v != ReplyUnknownEpoch {
		t.Fatalf("verdict %v", v)
	}
	got, err := ParseReply(rep, &f.key)
	if err != nil || got.Status != StatusUnknownEpoch {
		t.Fatalf("reply %+v, %v", got, err)
	}
	// The new epoch measures.
	req := Request{Epoch: 8, SourceID: 3, Seq: 100, SentUnixNano: now.UnixNano()}
	req.Nonce[0] = 0xff
	b := make([]byte, RequestLen)
	_, _ = EncodeRequest(b, &next, &req)
	if _, v := f.handle(now, b); v != ReplyOK {
		t.Fatalf("epoch 8: %v", v)
	}
}

func TestHandleRateLimitsEachSource(t *testing.T) {
	f := newFixture(t)
	now := t0.Add(time.Minute)
	for i := 0; i < SourceRatePerSecond; i++ {
		at := now.Add(time.Duration(i) * time.Millisecond)
		if _, v := f.handle(at, f.request(t, at)); v != ReplyOK {
			t.Fatalf("request %d: %v", i, v)
		}
	}
	at := now.Add(25 * time.Millisecond)
	rep, v := f.handle(at, f.request(t, at))
	if v != ReplyRateLimited {
		t.Fatalf("request over the rate: %v", v)
	}
	if got, err := ParseReply(rep, &f.key); err != nil || got.Status != StatusRateLimited {
		t.Fatalf("reply %+v, %v", got, err)
	}
	if _, v := f.handle(at, f.request(t, at)); v != DropNamedBudget {
		t.Fatalf("second over the rate: %v", v)
	}
	// A refused request's nonce was still recorded, so it cannot be
	// replayed into a later budget.
	refused := f.request(t, at)
	f.handle(at, refused)
	later := now.Add(3 * time.Second)
	if _, v := f.handle(later, refused); v != DropReplay {
		t.Fatalf("replay of a rate-refused request: %v", v)
	}
	if _, v := f.handle(later, f.request(t, later)); v != ReplyOK {
		t.Fatalf("after the budget refills: %v", v)
	}
}

func TestReplyIsNeverLargerThanItsRequest(t *testing.T) {
	f := newFixture(t)
	now := t0.Add(time.Minute)
	big := make([]byte, 1024)
	for i := 0; i < 50; i++ {
		at := now.Add(time.Duration(i) * 10 * time.Millisecond)
		pkt := f.request(t, at)
		n, v := f.r.Handle(at, pkt, big)
		if n > ReplyLen || (n > 0 && n >= len(pkt)) {
			t.Fatalf("reply of %d bytes to a %d-byte request (%v)", n, len(pkt), v)
		}
	}
}

func TestSetTableKeepsStateAndDropsRemovedSources(t *testing.T) {
	f := newFixture(t)
	now := t0.Add(time.Minute)
	pkt := f.request(t, now)
	if _, v := f.handle(now, pkt); v != ReplyOK {
		t.Fatal(v)
	}
	k5 := DerivePathKey(&f.target, 5, 7)
	if err := f.r.SetTable([]TableEntry{{SourceID: 5, Epoch: 7, Key: k5}, {SourceID: 3, Epoch: 7, Key: f.key}}); err != nil {
		t.Fatal(err)
	}
	if _, v := f.handle(now.Add(time.Second), pkt); v != DropReplay {
		t.Fatalf("a refresh reopened the replay window: %v", v)
	}
	if err := f.r.SetTable([]TableEntry{{SourceID: 5, Epoch: 7, Key: k5}}); err != nil {
		t.Fatal(err)
	}
	if _, v := f.handle(now.Add(2*time.Second), f.request(t, now.Add(2*time.Second))); v != DropUnknownSource {
		t.Fatalf("a removed source: %v", v)
	}
	if err := f.r.SetTable(nil); err != nil {
		t.Fatal(err)
	}
	if _, v := f.handle(now, f.request(t, now)); v != DropUnknownSource {
		t.Fatalf("empty table: %v", v)
	}
	var unset Responder
	if n, v := unset.Handle(now, f.request(t, now), make([]byte, ReplyLen)); n != 0 || v != DropUnknownSource {
		t.Fatalf("no table: %d, %v", n, v)
	}
}

func TestSetTableRefusals(t *testing.T) {
	r := NewResponder(t0)
	k := testKey(3)
	for name, entries := range map[string][]TableEntry{
		"zero source":     {{SourceID: 0, Epoch: 1, Key: k}},
		"zero epoch":      {{SourceID: 1, Epoch: 0, Key: k}},
		"duplicate epoch": {{SourceID: 1, Epoch: 1, Key: k}, {SourceID: 1, Epoch: 1, Key: k}},
		"three epochs":    {{SourceID: 1, Epoch: 1, Key: k}, {SourceID: 1, Epoch: 2, Key: k}, {SourceID: 1, Epoch: 3, Key: k}},
	} {
		if err := r.SetTable(entries); !errors.Is(err, ErrTable) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestDropPathAllocatesNothing is D10's AllocsPerRun == 0 requirement, for
// every verdict that sends nothing.
func TestDropPathAllocatesNothing(t *testing.T) {
	f := newFixture(t)
	now := t0.Add(time.Minute)
	good := f.request(t, now)
	if _, v := f.handle(now, good); v != ReplyOK {
		t.Fatal(v)
	}
	badTag := bytes.Clone(good)
	badTag[90] ^= 1
	unknownSource := bytes.Clone(good)
	unknownSource[12] = 9
	unknownEpoch := bytes.Clone(good)
	unknownEpoch[8] = 9
	malformed := bytes.Clone(good)
	malformed[0] = 0
	out := make([]byte, ReplyLen)
	for name, pkt := range map[string][]byte{
		"length":         good[:50],
		"long":           append(bytes.Clone(good), 1),
		"malformed":      malformed,
		"unknown source": unknownSource,
		"unknown epoch":  unknownEpoch,
		"bad tag":        badTag,
		"replay":         good,
	} {
		allocs := testing.AllocsPerRun(200, func() {
			if n, _ := f.r.Handle(now, pkt, out); n != 0 {
				t.Fatalf("%s replied", name)
			}
		})
		if allocs != 0 {
			t.Errorf("%s: %v allocations per datagram", name, allocs)
		}
	}
}

func TestNonceCacheRefusesWhenFullAndNeverEvictsALiveNonce(t *testing.T) {
	c := NewNonceCache()
	now := t0.UnixNano()
	expires := now + int64(FreshnessWindow)
	nonce := func(i int) *[NonceLen]byte {
		var n [NonceLen]byte
		n[0], n[1], n[2] = byte(i), byte(i>>8), 0x77
		return &n
	}
	for i := 0; i < NonceCacheSize; i++ {
		if !c.Insert(nonce(i), expires, now) {
			t.Fatalf("insert %d refused below the bound", i)
		}
	}
	if c.Insert(nonce(NonceCacheSize), expires, now) {
		t.Fatal("a full cache accepted a new nonce")
	}
	for i := 0; i < NonceCacheSize; i++ {
		if !c.Seen(nonce(i), now) {
			t.Fatalf("nonce %d was evicted by a refused insert", i)
		}
	}
	// Once the window has passed, the expired nonces make room.
	after := expires + 1
	if c.Seen(nonce(0), after) {
		t.Fatal("an expired nonce still reads as seen")
	}
	if !c.Insert(nonce(NonceCacheSize), after+int64(FreshnessWindow), after) {
		t.Fatal("expired nonces did not make room")
	}
	if c.Len() > NonceCacheSize {
		t.Fatalf("Len %d above the bound", c.Len())
	}
}

func TestNonceCacheGrowsFromSmall(t *testing.T) {
	c := NewNonceCache()
	now := t0.UnixNano()
	for i := 0; i < 1000; i++ {
		var n [NonceLen]byte
		n[0], n[1] = byte(i), byte(i>>8)
		if !c.Insert(&n, now+int64(time.Minute), now) {
			t.Fatal(i)
		}
		if !c.Seen(&n, now) {
			t.Fatalf("nonce %d not seen right after insert", i)
		}
	}
	if len(c.slots) > nonceSlotsMax || len(c.slots) < 1000 {
		t.Fatalf("%d slots for 1000 nonces", len(c.slots))
	}
}

func TestVerdictClasses(t *testing.T) {
	for v := DropLength; v <= ReplyRateLimited; v++ {
		if v.String() == "invalid" {
			t.Errorf("verdict %d has no name", v)
		}
	}
	if DropBadTag.Authenticated() || !DropReplay.Authenticated() || !ReplyStale.Authenticated() {
		t.Fatal("Authenticated boundary moved")
	}
	if DropNamedBudget.Replied() || !ReplyOK.Replied() {
		t.Fatal("Replied boundary moved")
	}
	for _, s := range []Status{StatusOK, StatusStale, StatusUnknownEpoch, StatusRateLimited} {
		if s.String() == "invalid" {
			t.Errorf("status %d has no name", s)
		}
	}
}

// A replayed, stale or retired datagram does not move "last authenticated":
// only a fresh, new request does.
func TestLastAuthenticatedCountsOnlyFreshRequests(t *testing.T) {
	f := newFixture(t)
	now := t0.Add(time.Minute)
	pkt := f.request(t, now)
	if _, v := f.handle(now, pkt); v != ReplyOK {
		t.Fatal(v)
	}
	first := f.r.LastAuthenticated()
	later := now.Add(10 * time.Second)
	if _, v := f.handle(later, pkt); v != DropReplay {
		t.Fatal(v)
	}
	if _, v := f.handle(later.Add(2*time.Minute), pkt); v != ReplyStale {
		t.Fatal(v)
	}
	if !f.r.LastAuthenticated().Equal(first) {
		t.Fatalf("a replay moved last authenticated to %v", f.r.LastAuthenticated())
	}
}

// At the exact last instant a request is fresh, its replay is still caught.
func TestReplayCaughtAtTheWindowEdge(t *testing.T) {
	f := newFixture(t)
	sent := t0.Add(time.Minute)
	pkt := f.request(t, sent)
	if _, v := f.handle(sent, pkt); v != ReplyOK {
		t.Fatal(v)
	}
	if _, v := f.handle(sent.Add(FreshnessWindow), pkt); v != DropReplay {
		t.Fatalf("a replay at the window edge: %v", v)
	}
}

// A caller may reuse its read buffer for the reply.
func TestReplyMayReuseTheReadBuffer(t *testing.T) {
	f := newFixture(t)
	now := t0.Add(time.Minute)
	buf := make([]byte, ReadBufferLen)
	pkt := f.request(t, now)
	copy(buf, pkt)
	req, _ := ParseRequest(pkt)
	n, v := f.r.Handle(now, buf[:RequestLen], buf)
	if v != ReplyOK {
		t.Fatal(v)
	}
	got, err := ParseReply(buf[:n], &f.key)
	if err != nil || got.Nonce != req.Nonce || got.Seq != req.Seq {
		t.Fatalf("reply from a shared buffer = %+v, %v", got, err)
	}
}

// SetTable may run beside Handle and beside itself (run with -race).
func TestSetTableConcurrentWithHandle(t *testing.T) {
	f := newFixture(t)
	now := t0.Add(time.Minute)
	entries := []TableEntry{{SourceID: 3, Epoch: 7, Key: f.key}}
	var wg sync.WaitGroup
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if err := f.r.SetTable(entries); err != nil {
					t.Error(err)
					return
				}
				_ = f.r.LastAuthenticated()
			}
		}()
	}
	out := make([]byte, ReplyLen)
	for i := 0; i < 400; i++ {
		at := now.Add(time.Duration(i) * 60 * time.Millisecond)
		f.r.Handle(at, f.request(t, at), out)
	}
	wg.Wait()
	pkt := f.request(t, now.Add(time.Minute))
	if _, v := f.handle(now.Add(time.Minute), pkt); v != ReplyOK {
		t.Fatal(v)
	}
	if _, v := f.handle(now.Add(time.Minute), pkt); v != DropReplay {
		t.Fatalf("concurrent table refreshes reset the replay cache: %v", v)
	}
}
