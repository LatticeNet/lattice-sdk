package beacon

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/maphash"
	"slices"
	"sync/atomic"
	"time"
)

// TableEntry is one path key a target holds: the key of one source for one
// epoch. A retired entry is held only to answer StatusUnknownEpoch to a
// source whose configuration is behind a rotation; it never yields a
// measurement.
type TableEntry struct {
	SourceID uint32
	Epoch    uint32
	Key      Key
	Retired  bool
}

// Verdict is what Handle did with one datagram, for the agent's counters.
// It is never sent anywhere.
type Verdict uint8

// Verdicts. The Drop verdicts send nothing.
const (
	// DropLength: not exactly RequestLen bytes.
	DropLength Verdict = iota + 1
	// DropMalformed: wrong magic or version, or padding that is not zero.
	DropMalformed
	// DropUnknownSource: no table entry for the source id. Decided before
	// any HMAC is computed.
	DropUnknownSource
	// DropUnknownEpoch: the source id is known, the epoch is not, so the
	// tag cannot be verified and nothing may be said.
	DropUnknownEpoch
	// DropBadTag: the tag does not verify.
	DropBadTag
	// DropReplay: the nonce was already answered inside the window.
	DropReplay
	// DropNamedBudget: a non-ok reply was due but the source id had one
	// within NamedReplyInterval.
	DropNamedBudget
	// ReplyOK and the three below sent a ReplyLen reply with that status.
	ReplyOK
	ReplyStale
	ReplyUnknownEpoch
	ReplyRateLimited
)

// Replied reports whether the verdict sent a reply.
func (v Verdict) Replied() bool { return v >= ReplyOK }

// Authenticated reports whether the datagram's tag verified, which is what
// "last authenticated request seen" counts.
func (v Verdict) Authenticated() bool { return v >= DropReplay }

// String names the verdict for logs and counters.
func (v Verdict) String() string {
	switch v {
	case DropLength:
		return "drop_length"
	case DropMalformed:
		return "drop_malformed"
	case DropUnknownSource:
		return "drop_unknown_source"
	case DropUnknownEpoch:
		return "drop_unknown_epoch"
	case DropBadTag:
		return "drop_bad_tag"
	case DropReplay:
		return "drop_replay"
	case DropNamedBudget:
		return "drop_named_budget"
	case ReplyOK:
		return "reply_ok"
	case ReplyStale:
		return "reply_stale"
	case ReplyUnknownEpoch:
		return "reply_unknown_epoch"
	case ReplyRateLimited:
		return "reply_rate_limited"
	}
	return "invalid"
}

// Responder is the decision core of a beacon responder: given a datagram it
// decides whether to reply and writes the reply. It does no I/O.
//
// Handle must be called from one goroutine at a time (the receive loop).
// SetTable and LastAuthenticated may be called from any goroutine while
// Handle runs.
type Responder struct {
	startNs  int64
	table    atomic.Pointer[responderTable]
	lastAuth atomic.Int64
	// sum is Handle's scratch for an HMAC digest, kept here so a drop
	// allocates nothing.
	sum [sha256.Size]byte
}

type responderTable struct {
	sources []*tableSource // sorted by id
}

type tableSource struct {
	id     uint32
	epochs []tableEpoch
	state  *sourceState
}

type tableEpoch struct {
	epoch   uint32
	retired bool
	mac     macHash
}

type sourceState struct {
	nonces *NonceCache
	// credit is the source's rate allowance in nanoseconds: each answered
	// request costs costNs, and credit refills with elapsed time up to
	// one second's worth.
	credit    int64
	lastNs    int64
	lastNamed int64
}

const (
	costNs   = int64(time.Second) / SourceRatePerSecond
	creditNs = int64(time.Second)
)

// NewResponder returns a responder that started at start: a request stamped
// before it is stale, so a request captured before a restart cannot be
// replayed into the fresh nonce caches.
func NewResponder(start time.Time) *Responder {
	return &Responder{startNs: start.UnixNano()}
}

// ErrTable is returned by SetTable for a table it refuses.
var ErrTable = errors.New("beacon: invalid table")

// SetTable replaces the path keys the responder accepts. A source id that is
// in both the old and the new table keeps its nonce cache and rate state, so
// a table refresh can neither reopen a replay window nor reset a budget. A
// source id missing from the new table is dropped at once. Each source may
// hold at most MaxEpochsPerSource epochs; a retired one only ever answers
// StatusUnknownEpoch.
func (r *Responder) SetTable(entries []TableEntry) error {
	old := r.table.Load()
	byID := map[uint32]*tableSource{}
	for _, e := range entries {
		if e.SourceID == 0 || e.Epoch == 0 {
			return fmt.Errorf("%w: source id and epoch must be above zero", ErrTable)
		}
		src := byID[e.SourceID]
		if src == nil {
			src = &tableSource{id: e.SourceID}
			if prev := old.find(e.SourceID); prev != nil {
				src.state = prev.state
			} else {
				src.state = &sourceState{credit: creditNs}
			}
			byID[e.SourceID] = src
		}
		for _, ep := range src.epochs {
			if ep.epoch == e.Epoch {
				return fmt.Errorf("%w: source %d holds epoch %d twice", ErrTable, e.SourceID, e.Epoch)
			}
		}
		if len(src.epochs) == MaxEpochsPerSource {
			return fmt.Errorf("%w: source %d holds more than %d epochs", ErrTable, e.SourceID, MaxEpochsPerSource)
		}
		key := e.Key
		src.epochs = append(src.epochs, tableEpoch{epoch: e.Epoch, retired: e.Retired, mac: hmac.New(sha256.New, key[:])})
	}
	t := &responderTable{sources: make([]*tableSource, 0, len(byID))}
	for _, src := range byID {
		t.sources = append(t.sources, src)
	}
	slices.SortFunc(t.sources, func(a, b *tableSource) int {
		switch {
		case a.id < b.id:
			return -1
		case a.id > b.id:
			return 1
		}
		return 0
	})
	r.table.Store(t)
	return nil
}

// LastAuthenticated is when a datagram's tag last verified, zero before the
// first one. An agent reports it as the beacon's last authenticated request.
func (r *Responder) LastAuthenticated() time.Time {
	ns := r.lastAuth.Load()
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns).UTC()
}

func (t *responderTable) find(id uint32) *tableSource {
	if t == nil {
		return nil
	}
	lo, hi := 0, len(t.sources)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		switch s := t.sources[mid]; {
		case s.id == id:
			return s
		case s.id < id:
			lo = mid + 1
		default:
			hi = mid
		}
	}
	return nil
}

// Handle decides what to do with one datagram received at now, writes a
// reply into out[:ReplyLen] when one is due, and returns the reply's length
// (zero for none) and the verdict. out must hold at least ReplyLen bytes; it
// is never written for a drop.
//
// The order is fixed: length and framing, source id, epoch (all before any
// HMAC), tag in constant time, then retirement, freshness, replay, nonce
// cache room and the source's rate. A non-ok reply is sent at most once per
// NamedReplyInterval per source id. Nothing on a drop path allocates.
func (r *Responder) Handle(now time.Time, pkt, out []byte) (int, Verdict) {
	if len(pkt) != RequestLen {
		return 0, DropLength
	}
	if len(out) < ReplyLen {
		return 0, DropLength
	}
	if checkRequestFrame(pkt) != nil {
		return 0, DropMalformed
	}
	src := r.table.Load().find(binary.BigEndian.Uint32(pkt[reqOffSource:]))
	if src == nil {
		return 0, DropUnknownSource
	}
	epoch := binary.BigEndian.Uint32(pkt[reqOffEpoch:])
	var ep *tableEpoch
	for i := range src.epochs {
		if src.epochs[i].epoch == epoch {
			ep = &src.epochs[i]
			break
		}
	}
	if ep == nil {
		return 0, DropUnknownEpoch
	}
	sum := tag(ep.mac, reqDomain, pkt[:reqOffTag], r.sum[:0])
	if subtle.ConstantTimeCompare(sum[:TagLen], pkt[reqOffTag:RequestLen]) != 1 {
		return 0, DropBadTag
	}
	nowNs := now.UnixNano()
	r.lastAuth.Store(nowNs)
	st := src.state
	seq := binary.BigEndian.Uint32(pkt[reqOffSeq:])
	nonce := pkt[reqOffNonce:reqOffPad]
	if ep.retired {
		return r.named(st, ep, nowNs, StatusUnknownEpoch, seq, nonce, out)
	}
	sent := int64(binary.BigEndian.Uint64(pkt[reqOffSent:]))
	if sent < r.startNs || nowNs-sent > int64(FreshnessWindow) || sent-nowNs > int64(FreshnessWindow) {
		return r.named(st, ep, nowNs, StatusStale, seq, nonce, out)
	}
	if st.nonces == nil {
		st.nonces = NewNonceCache()
	}
	var n [NonceLen]byte
	copy(n[:], nonce)
	if st.nonces.Seen(&n, nowNs) {
		return 0, DropReplay
	}
	// Inserted before the rate decision, so a request refused for rate
	// cannot be replayed later and answered.
	if !st.nonces.Insert(&n, sent+int64(FreshnessWindow), nowNs) {
		return r.named(st, ep, nowNs, StatusRateLimited, seq, nonce, out)
	}
	if !st.allow(nowNs) {
		return r.named(st, ep, nowNs, StatusRateLimited, seq, nonce, out)
	}
	writeReply(out[:ReplyLen], ep.mac, StatusOK, seq, nonce, nowNs, r.sum[:0])
	return ReplyLen, ReplyOK
}

func (r *Responder) named(st *sourceState, ep *tableEpoch, nowNs int64, status Status, seq uint32, nonce, out []byte) (int, Verdict) {
	if st.lastNamed != 0 && nowNs-st.lastNamed < int64(NamedReplyInterval) && nowNs >= st.lastNamed {
		return 0, DropNamedBudget
	}
	st.lastNamed = nowNs
	writeReply(out[:ReplyLen], ep.mac, status, seq, nonce, nowNs, r.sum[:0])
	switch status {
	case StatusStale:
		return ReplyLen, ReplyStale
	case StatusUnknownEpoch:
		return ReplyLen, ReplyUnknownEpoch
	default:
		return ReplyLen, ReplyRateLimited
	}
}

// allow spends one request of the source's rate.
func (st *sourceState) allow(nowNs int64) bool {
	if st.lastNs != 0 {
		if elapsed := nowNs - st.lastNs; elapsed > 0 {
			st.credit = min(creditNs, st.credit+elapsed)
		}
	}
	st.lastNs = nowNs
	if st.credit < costNs {
		return false
	}
	st.credit -= costNs
	return true
}

// NonceCache remembers the nonces one source's answered requests carried,
// each until its request can no longer be fresh. It holds at most
// NonceCacheSize unexpired nonces and refuses an insert beyond that rather
// than evicting a nonce still inside its window. Slots are found by a seeded
// hash, so a source cannot choose nonces that collide.
//
// A NonceCache is not safe for concurrent use.
type NonceCache struct {
	seed  maphash.Seed
	slots []nonceSlot
	used  int // occupied slots, expired ones included
	// fullUntil is when the earliest held nonce expires after a compaction
	// found the cache full; until then an insert is refused without
	// scanning again, so a source flooding its own cache costs no more
	// than a lookup per request.
	fullUntil int64
}

type nonceSlot struct {
	nonce   [NonceLen]byte
	expires int64 // unix nanoseconds; zero marks an empty slot
}

const (
	nonceSlotsMin = 256
	nonceSlotsMax = 4096 // power of two above NonceCacheSize / 0.6
)

// NewNonceCache returns an empty cache. It grows on insert, up to the slots
// NonceCacheSize needs, so a source probing at a few packets per second
// holds a few kilobytes.
func NewNonceCache() *NonceCache {
	return &NonceCache{seed: maphash.MakeSeed()}
}

// Len is how many slots are occupied, expired ones included until the next
// compaction.
func (c *NonceCache) Len() int { return c.used }

// Seen reports whether nonce is held and unexpired at nowNs.
func (c *NonceCache) Seen(nonce *[NonceLen]byte, nowNs int64) bool {
	if len(c.slots) == 0 {
		return false
	}
	mask := uint64(len(c.slots) - 1)
	for i := maphash.Bytes(c.seed, nonce[:]) & mask; ; i = (i + 1) & mask {
		s := &c.slots[i]
		if s.expires == 0 {
			return false
		}
		if s.nonce == *nonce {
			return s.expires > nowNs
		}
	}
}

// Insert holds nonce until expiresNs. It reports false, and holds nothing
// new, when NonceCacheSize unexpired nonces are already held at nowNs.
func (c *NonceCache) Insert(nonce *[NonceLen]byte, expiresNs, nowNs int64) bool {
	if expiresNs <= 0 {
		expiresNs = 1
	}
	if c.used >= NonceCacheSize || c.used+1 > len(c.slots)*6/10 {
		if nowNs < c.fullUntil || !c.compact(nowNs) {
			return false
		}
	}
	mask := uint64(len(c.slots) - 1)
	for i := maphash.Bytes(c.seed, nonce[:]) & mask; ; i = (i + 1) & mask {
		s := &c.slots[i]
		if s.expires == 0 {
			s.nonce, s.expires = *nonce, expiresNs
			c.used++
			return true
		}
		if s.nonce == *nonce {
			s.expires = expiresNs
			return true
		}
	}
}

// compact drops expired nonces and sizes the table for one more insert. It
// reports false when the unexpired nonces already number NonceCacheSize.
func (c *NonceCache) compact(nowNs int64) bool {
	live := 0
	earliest := int64(0)
	for i := range c.slots {
		if e := c.slots[i].expires; e > nowNs {
			live++
			if earliest == 0 || e < earliest {
				earliest = e
			}
		}
	}
	if live >= NonceCacheSize {
		c.fullUntil = earliest
		return false
	}
	c.fullUntil = 0
	size := nonceSlotsMin
	for (live+1) > size*6/10 && size < nonceSlotsMax {
		size *= 2
	}
	old := c.slots
	if len(old) == size {
		// Reuse the same backing array: copy the live slots out first.
		kept := make([]nonceSlot, 0, live)
		for _, s := range old {
			if s.expires > nowNs {
				kept = append(kept, s)
			}
		}
		clear(c.slots)
		old = kept
	} else {
		c.slots = make([]nonceSlot, size)
	}
	c.used = 0
	mask := uint64(size - 1)
	for _, s := range old {
		if s.expires <= nowNs {
			continue
		}
		for i := maphash.Bytes(c.seed, s.nonce[:]) & mask; ; i = (i + 1) & mask {
			if c.slots[i].expires == 0 {
				c.slots[i] = s
				c.used++
				break
			}
		}
	}
	return true
}
