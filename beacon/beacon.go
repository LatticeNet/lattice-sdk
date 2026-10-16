// Package beacon is the wire format of the measurement beacon (lattice docs,
// design 29 D3 and D12): an authenticated UDP responder an agent may run, and
// the requests its sources send it. The control plane, the agents and their
// tests share this one implementation, so a request one side encodes is the
// request the other side verifies.
//
// The package does no I/O. An agent owns the socket, the pre-authentication
// CPU guard, panic recovery and the circuit breaker, and feeds every
// datagram to Responder.Handle; a source encodes with EncodeRequest and reads
// replies with ParseReply.
//
// Keys. The control plane holds a 32-byte key per target node and never sends
// it anywhere. For each epoch it derives one path key per (source, target)
// with DerivePathKey; the target receives its table of path keys and each
// source only its own path key per target, through the authenticated agent
// config pull, and both hold them in memory only.
package beacon

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"time"
)

// Wire constants.
const (
	// Magic opens every request and reply.
	Magic = "LTB1"
	// Version is the only version this package speaks.
	Version = 1
	// RequestLen is the exact length of a request. A datagram of any other
	// length gets no reply.
	RequestLen = 96
	// ReplyLen is the exact length of a reply, always smaller than a
	// request, so the beacon can never amplify.
	ReplyLen = 64
	// ReadBufferLen is the receive buffer a responder reads into. It is
	// larger than a request so a longer datagram is seen as longer and
	// dropped, rather than truncated to a valid-looking prefix.
	ReadBufferLen = 128
	// KeyLen is the length of a target key and of a path key.
	KeyLen = 32
	// NonceLen is the length of a request nonce.
	NonceLen = 16
	// TagLen is the length of the truncated HMAC-SHA256 tag.
	TagLen = 16
	// DerivationLabel is the first input of every path key derivation.
	DerivationLabel = "lattice-beacon/v1"
)

// Freshness, replay and rate bounds a responder enforces.
const (
	// FreshnessWindow is how far a request's timestamp may be from the
	// responder's clock, either way.
	FreshnessWindow = 60 * time.Second
	// NonceWindow is how long a nonce can stay acceptable: a request stamped
	// FreshnessWindow ahead of the responder's clock stays fresh for twice
	// the window.
	NonceWindow = 2 * FreshnessWindow
	// SourceRatePerSecond is how many authenticated requests one source id
	// may have answered per second.
	SourceRatePerSecond = 20
	// NonceCacheSize is how many unexpired nonces a responder holds per
	// source: the rate times the nonce window. A full cache refuses new
	// requests rather than evicting a nonce still inside the window.
	NonceCacheSize = SourceRatePerSecond * int(NonceWindow/time.Second)
	// NamedReplyInterval is the least time between two replies with a
	// status other than StatusOK to one source id. A captured request
	// replayed after it went stale therefore draws at most one reply per
	// interval, and a reflection through the beacon stays below one
	// 64-byte datagram per second per source id.
	NamedReplyInterval = time.Second
	// MaxEpochsPerSource is how many epochs a responder table may hold for
	// one source: the current one and the one before it during a rotation.
	MaxEpochsPerSource = 2
)

// Status is the status byte of a reply.
type Status uint8

// Reply statuses. A non-ok reply is only ever sent to a request whose tag
// verified, so it tells the holder of a path key why it was not measured
// and tells nobody else anything.
const (
	// StatusOK: the request was fresh, new and within the source's rate.
	StatusOK Status = 0
	// StatusStale: the request's timestamp is more than FreshnessWindow
	// from the responder's clock, or older than the responder's start.
	StatusStale Status = 1
	// StatusUnknownEpoch: the request was signed with a path key the
	// responder holds only as retired; the source's configuration is behind
	// a rotation.
	StatusUnknownEpoch Status = 2
	// StatusRateLimited: the source id is over SourceRatePerSecond, or its
	// nonce cache is full.
	StatusRateLimited Status = 3
)

// String names a status as result reasons do.
func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusStale:
		return "stale"
	case StatusUnknownEpoch:
		return "unknown_epoch"
	case StatusRateLimited:
		return "rate_limited"
	}
	return "invalid"
}

func (s Status) known() bool { return s <= StatusRateLimited }

// Request layout, big-endian:
//
//	off len field
//	  0   4 magic "LTB1"
//	  4   1 version (1)
//	  5   4 epoch
//	  9   4 source id
//	 13   4 seq
//	 17   8 sent, unix nanoseconds
//	 25  16 nonce
//	 41  39 padding, zero
//	 80  16 tag = HMAC-SHA256(K_path, "req" | bytes 0..79)[:16]
const (
	reqOffVersion = 4
	reqOffEpoch   = 5
	reqOffSource  = 9
	reqOffSeq     = 13
	reqOffSent    = 17
	reqOffNonce   = 25
	reqOffPad     = 41
	reqOffTag     = RequestLen - TagLen
)

// Reply layout, big-endian:
//
//	off len field
//	  0   4 magic "LTB1"
//	  4   1 version (1)
//	  5   1 status
//	  6   4 seq, copied from the request
//	 10  16 nonce, copied from the request
//	 26   8 responder clock, unix nanoseconds
//	 34  14 padding, zero
//	 48  16 tag = HMAC-SHA256(K_path, "rep" | bytes 0..47)[:16]
const (
	repOffVersion   = 4
	repOffStatus    = 5
	repOffSeq       = 6
	repOffNonce     = 10
	repOffResponder = 26
	repOffPad       = 34
	repOffTag       = ReplyLen - TagLen
)

var (
	magicBytes = []byte(Magic)
	reqDomain  = []byte("req")
	repDomain  = []byte("rep")
)

// Errors the parsers return. A responder never tells a sender which one
// applied; they exist for tests and for the source's own accounting.
var (
	ErrLength  = errors.New("beacon: wrong datagram length")
	ErrMagic   = errors.New("beacon: wrong magic")
	ErrVersion = errors.New("beacon: unsupported version")
	ErrPadding = errors.New("beacon: padding is not zero")
	ErrTag     = errors.New("beacon: tag does not verify")
	ErrStatus  = errors.New("beacon: unknown status")
	ErrIDs     = errors.New("beacon: source id and epoch must be above zero")
)

// Key is a target key or a path key.
type Key [KeyLen]byte

// DerivePathKey is K_path = HMAC-SHA256(K_target, lp(label) | lp(source) |
// lp(epoch)), where lp(x) is x's length as a 4-byte big-endian integer
// followed by x, the label is DerivationLabel, and source and epoch are
// 4-byte big-endian integers. The length prefixes keep any two different
// inputs from producing the same byte string.
func DerivePathKey(target *Key, sourceID, epoch uint32) Key {
	mac := hmac.New(sha256.New, target[:])
	writeLP(mac, []byte(DerivationLabel))
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], sourceID)
	writeLP(mac, b[:])
	binary.BigEndian.PutUint32(b[:], epoch)
	writeLP(mac, b[:])
	var out Key
	mac.Sum(out[:0])
	return out
}

func writeLP(w interface{ Write([]byte) (int, error) }, p []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(p)))
	_, _ = w.Write(n[:])
	_, _ = w.Write(p)
}

// Request is the content of a request, without its tag.
type Request struct {
	Epoch        uint32
	SourceID     uint32
	Seq          uint32
	SentUnixNano int64
	Nonce        [NonceLen]byte
}

// EncodeRequest writes req, signed with key, into dst[:RequestLen] and
// returns RequestLen. The nonce must come from a cryptographic source and be
// used once.
func EncodeRequest(dst []byte, key *Key, req *Request) (int, error) {
	if len(dst) < RequestLen {
		return 0, ErrLength
	}
	if req.SourceID == 0 || req.Epoch == 0 {
		return 0, ErrIDs
	}
	b := dst[:RequestLen]
	clear(b)
	copy(b, magicBytes)
	b[reqOffVersion] = Version
	binary.BigEndian.PutUint32(b[reqOffEpoch:], req.Epoch)
	binary.BigEndian.PutUint32(b[reqOffSource:], req.SourceID)
	binary.BigEndian.PutUint32(b[reqOffSeq:], req.Seq)
	binary.BigEndian.PutUint64(b[reqOffSent:], uint64(req.SentUnixNano))
	copy(b[reqOffNonce:], req.Nonce[:])
	mac := hmac.New(sha256.New, key[:])
	var sum [sha256.Size]byte
	tag(mac, reqDomain, b[:reqOffTag], sum[:0])
	copy(b[reqOffTag:], sum[:TagLen])
	return RequestLen, nil
}

// ParseRequest reads a request's fields without verifying its tag, which
// needs the path key its source id and epoch select. It refuses any
// datagram that is not exactly RequestLen bytes, does not carry the magic
// and version, or has padding that is not zero.
func ParseRequest(pkt []byte) (Request, error) {
	if err := checkRequestFrame(pkt); err != nil {
		return Request{}, err
	}
	req := Request{
		Epoch:        binary.BigEndian.Uint32(pkt[reqOffEpoch:]),
		SourceID:     binary.BigEndian.Uint32(pkt[reqOffSource:]),
		Seq:          binary.BigEndian.Uint32(pkt[reqOffSeq:]),
		SentUnixNano: int64(binary.BigEndian.Uint64(pkt[reqOffSent:])),
	}
	copy(req.Nonce[:], pkt[reqOffNonce:reqOffPad])
	return req, nil
}

// VerifyRequest reports whether a well-framed request's tag verifies under
// key, comparing in constant time.
func VerifyRequest(pkt []byte, key *Key) bool {
	if checkRequestFrame(pkt) != nil {
		return false
	}
	mac := hmac.New(sha256.New, key[:])
	var sum [sha256.Size]byte
	tag(mac, reqDomain, pkt[:reqOffTag], sum[:0])
	return subtle.ConstantTimeCompare(sum[:TagLen], pkt[reqOffTag:RequestLen]) == 1
}

func checkRequestFrame(pkt []byte) error {
	if len(pkt) != RequestLen {
		return ErrLength
	}
	if !bytes.Equal(pkt[:reqOffVersion], magicBytes) {
		return ErrMagic
	}
	if pkt[reqOffVersion] != Version {
		return ErrVersion
	}
	for _, c := range pkt[reqOffPad:reqOffTag] {
		if c != 0 {
			return ErrPadding
		}
	}
	return nil
}

// Reply is the content of a reply, without its tag.
type Reply struct {
	Status            Status
	Seq               uint32
	Nonce             [NonceLen]byte
	ResponderUnixNano int64
}

// EncodeReply writes rep, signed with key, into dst[:ReplyLen] and returns
// ReplyLen.
func EncodeReply(dst []byte, key *Key, rep *Reply) (int, error) {
	if len(dst) < ReplyLen {
		return 0, ErrLength
	}
	if !rep.Status.known() {
		return 0, ErrStatus
	}
	mac := hmac.New(sha256.New, key[:])
	var sum [sha256.Size]byte
	writeReply(dst[:ReplyLen], mac, rep.Status, rep.Seq, rep.Nonce[:], rep.ResponderUnixNano, sum[:0])
	return ReplyLen, nil
}

// ParseReply verifies a reply under key and returns its content. A source
// must also drop a reply whose nonce is not one it sent and is still waiting
// for; ParseReply cannot know that.
func ParseReply(pkt []byte, key *Key) (Reply, error) {
	if len(pkt) != ReplyLen {
		return Reply{}, ErrLength
	}
	if !bytes.Equal(pkt[:repOffVersion], magicBytes) {
		return Reply{}, ErrMagic
	}
	if pkt[repOffVersion] != Version {
		return Reply{}, ErrVersion
	}
	for _, c := range pkt[repOffPad:repOffTag] {
		if c != 0 {
			return Reply{}, ErrPadding
		}
	}
	mac := hmac.New(sha256.New, key[:])
	var sum [sha256.Size]byte
	tag(mac, repDomain, pkt[:repOffTag], sum[:0])
	if subtle.ConstantTimeCompare(sum[:TagLen], pkt[repOffTag:ReplyLen]) != 1 {
		return Reply{}, ErrTag
	}
	rep := Reply{
		Status:            Status(pkt[repOffStatus]),
		Seq:               binary.BigEndian.Uint32(pkt[repOffSeq:]),
		ResponderUnixNano: int64(binary.BigEndian.Uint64(pkt[repOffResponder:])),
	}
	if !rep.Status.known() {
		return Reply{}, ErrStatus
	}
	copy(rep.Nonce[:], pkt[repOffNonce:repOffResponder])
	return rep, nil
}

type macHash interface {
	Reset()
	Write([]byte) (int, error)
	Sum([]byte) []byte
}

// tag computes HMAC(domain | msg) into sum, which must have capacity for a
// full SHA-256 digest so nothing is allocated.
func tag(mac macHash, domain, msg, sum []byte) []byte {
	mac.Reset()
	_, _ = mac.Write(domain)
	_, _ = mac.Write(msg)
	return mac.Sum(sum)
}

func writeReply(b []byte, mac macHash, status Status, seq uint32, nonce []byte, responderNs int64, sum []byte) {
	clear(b)
	copy(b, magicBytes)
	b[repOffVersion] = Version
	b[repOffStatus] = byte(status)
	binary.BigEndian.PutUint32(b[repOffSeq:], seq)
	copy(b[repOffNonce:repOffResponder], nonce)
	binary.BigEndian.PutUint64(b[repOffResponder:], uint64(responderNs))
	sum = tag(mac, repDomain, b[:repOffTag], sum)
	copy(b[repOffTag:], sum[:TagLen])
}
