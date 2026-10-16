// Package strictjson answers, in one pass and without allocating for the
// ASCII keys documents normally carry, whether a byte slice is exactly one
// JSON value in which no object repeats a key. The SDK and the core both use
// it in front of their encoding/json-based strict checks.
//
// The SDK's strict decoders (the plan, the convert request, the catalogue
// row's extra, the runtime's frames) refuse a duplicate key at any depth,
// because two readers of one document could otherwise take different values.
// They used to walk every document token by token through encoding/json's
// Decoder, which allocates per token and was most of what a 1000-node plan
// cost to validate. Valid is the fast path in front of that walk: when it
// answers true the document is valid and duplicate-free, and the caller is
// done; when it answers false the caller runs its encoding/json check, which
// stays the specification and the source of every error message. So Valid
// may refuse more than the specification (it refuses nesting deeper than
// MaxDepth, which encoding/json admits up to 10000 levels), but it never
// admits what the specification refuses; the fuzz test holds it to that.
package strictjson

import (
	"bytes"
	"encoding/json"
	"strconv"
	"sync"
)

// MaxDepth is the deepest nesting Valid scans. A deeper document is not
// refused by the callers; it takes their encoding/json path.
const MaxDepth = 512

// linearKeys is how many keys an object may carry before the duplicate check
// moves from comparing every pair to a map.
const linearKeys = 64

// Valid reports whether raw is one JSON value (RFC 8259, as encoding/json
// reads it, invalid UTF-8 inside strings included), surrounded only by JSON
// whitespace, in which no object at any depth carries the same key twice once
// its keys are decoded the way encoding/json decodes them.
func Valid(raw []byte) bool {
	s := getScanner(raw, nil)
	defer putScanner(s)
	s.space()
	if !s.value() {
		return false
	}
	s.space()
	return s.pos == len(s.data)
}

// Field is one member of a top-level object: its key, decoded the way
// encoding/json decodes it, and the raw bytes of its value.
type Field struct {
	Key   string
	Value []byte
}

// Fields answers the members of the object raw holds, in document order, when
// raw is an object Valid admits; ok is false otherwise, and the caller takes
// its encoding/json path. Each Value aliases raw. A strict decoder that knows
// its members by their exact names decodes each Value on its own instead of
// running encoding/json over the whole document again.
func Fields(raw []byte) (fields []Field, ok bool) {
	s := getScanner(raw, &fields)
	defer putScanner(s)
	s.space()
	if s.pos >= len(s.data) || s.data[s.pos] != '{' || !s.value() {
		return nil, false
	}
	s.space()
	if s.pos != len(s.data) {
		return nil, false
	}
	return fields, true
}

// Elements answers the elements of the array raw holds, in order, when raw is
// an array Valid admits; ok is false otherwise. Each element aliases raw. A
// reader that wants each element's own bytes (its size as received, say)
// takes them from here instead of encoding the decoded element again.
func Elements(raw []byte) (elements [][]byte, ok bool) {
	s := getScanner(raw, nil)
	s.elements = &elements
	defer putScanner(s)
	s.space()
	if s.pos >= len(s.data) || s.data[s.pos] != '[' || !s.value() {
		return nil, false
	}
	s.space()
	if s.pos != len(s.data) {
		return nil, false
	}
	if elements == nil {
		elements = [][]byte{}
	}
	return elements, true
}

// Compact reports whether raw is a value Valid admits with no whitespace
// outside its strings, so that json.Compact would leave it as it is. An
// encoder that splices such a value into its output in place of a
// json.RawMessage writes what encoding/json writes, without the pass
// encoding/json spends compacting it again, once it has also ruled out the
// bytes encoding/json escapes ('<', '>', '&', U+2028 and U+2029).
func Compact(raw []byte) bool {
	s := getScanner(raw, nil)
	defer putScanner(s)
	return s.value() && s.pos == len(s.data) && !s.spaced
}

type scanner struct {
	data   []byte
	pos    int
	depth  int
	spaced bool
	// keys holds, per depth, the keys of the object being scanned there; the
	// slices are kept from one object, and one document, to the next.
	keys [][]keyRef
	// top, when set, collects the members of the top-level object.
	top *[]Field
	// elements, when set, collects the elements of the top-level array.
	elements *[][]byte
}

// keyRef is one object key: its bytes in data when they are already its
// decoded form, or the decoded key when it had an escape or a byte outside
// ASCII. It holds no slice of data, so a pooled scanner keeps no document
// alive.
type keyRef struct {
	start, end int
	decoded    string
	plain      bool
}

var scanners = sync.Pool{New: func() any { return new(scanner) }}

func getScanner(raw []byte, top *[]Field) *scanner {
	s := scanners.Get().(*scanner)
	s.data, s.pos, s.depth, s.spaced, s.top = raw, 0, 0, false, top
	return s
}

func putScanner(s *scanner) {
	for i, keys := range s.keys {
		clear(keys[:cap(keys)])
		s.keys[i] = keys[:0]
	}
	s.data, s.top, s.elements = nil, nil, nil
	scanners.Put(s)
}

func (s *scanner) keyString(k keyRef) string {
	if k.plain {
		return string(s.data[k.start:k.end])
	}
	return k.decoded
}

func (s *scanner) sameKey(a, b keyRef) bool {
	switch {
	case a.plain && b.plain:
		return bytes.Equal(s.data[a.start:a.end], s.data[b.start:b.end])
	case a.plain:
		return string(s.data[a.start:a.end]) == b.decoded
	case b.plain:
		return a.decoded == string(s.data[b.start:b.end])
	default:
		return a.decoded == b.decoded
	}
}

func (s *scanner) space() {
	for s.pos < len(s.data) {
		switch s.data[s.pos] {
		case ' ', '\t', '\n', '\r':
			s.pos++
			s.spaced = true
		default:
			return
		}
	}
}

func (s *scanner) value() bool {
	if s.pos >= len(s.data) {
		return false
	}
	switch c := s.data[s.pos]; {
	case c == '{':
		return s.object()
	case c == '[':
		return s.array()
	case c == '"':
		_, _, _, ok := s.str()
		return ok
	case c == 't':
		return s.literal("true")
	case c == 'f':
		return s.literal("false")
	case c == 'n':
		return s.literal("null")
	case c == '-' || (c >= '0' && c <= '9'):
		return s.number()
	}
	return false
}

func (s *scanner) literal(word string) bool {
	if len(s.data)-s.pos < len(word) || string(s.data[s.pos:s.pos+len(word)]) != word {
		return false
	}
	s.pos += len(word)
	return true
}

// number scans -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)? and leaves the
// byte after it to the caller, which refuses anything but a delimiter. The
// specification's Decoder.Token reads every number as a float64, so a number
// float64 cannot hold (1e700) is refused there; it is refused here too. Only
// a number with an exponent or more than fifteen digits can be one.
func (s *scanner) number() bool {
	start := s.pos
	if s.data[s.pos] == '-' {
		s.pos++
	}
	switch {
	case s.pos < len(s.data) && s.data[s.pos] == '0':
		s.pos++
	case s.pos < len(s.data) && s.data[s.pos] >= '1' && s.data[s.pos] <= '9':
		s.digits()
	default:
		return false
	}
	if s.pos < len(s.data) && s.data[s.pos] == '.' {
		s.pos++
		if !s.digits() {
			return false
		}
	}
	exponent := false
	if s.pos < len(s.data) && (s.data[s.pos] == 'e' || s.data[s.pos] == 'E') {
		exponent = true
		s.pos++
		if s.pos < len(s.data) && (s.data[s.pos] == '+' || s.data[s.pos] == '-') {
			s.pos++
		}
		if !s.digits() {
			return false
		}
	}
	if exponent || s.pos-start > 15 {
		if _, err := strconv.ParseFloat(string(s.data[start:s.pos]), 64); err != nil {
			return false
		}
	}
	return true
}

// digits scans [0-9]+ and reports whether there was at least one.
func (s *scanner) digits() bool {
	start := s.pos
	for s.pos < len(s.data) && s.data[s.pos] >= '0' && s.data[s.pos] <= '9' {
		s.pos++
	}
	return s.pos > start
}

// str scans the string whose opening quote is at s.pos. It answers the span
// of its contents and whether those bytes are already its decoded form (no
// escape, nothing outside ASCII).
func (s *scanner) str() (start, end int, plain, ok bool) {
	s.pos++
	start, plain = s.pos, true
	for s.pos < len(s.data) {
		c := s.data[s.pos]
		switch {
		case c == '"':
			end = s.pos
			s.pos++
			return start, end, plain, true
		case c == '\\':
			plain = false
			s.pos++
			if s.pos >= len(s.data) {
				return 0, 0, false, false
			}
			switch s.data[s.pos] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				s.pos++
			case 'u':
				if len(s.data)-s.pos < 5 {
					return 0, 0, false, false
				}
				for _, h := range s.data[s.pos+1 : s.pos+5] {
					if !isHex(h) {
						return 0, 0, false, false
					}
				}
				s.pos += 5
			default:
				return 0, 0, false, false
			}
		case c < 0x20:
			return 0, 0, false, false
		default:
			if c >= 0x80 {
				plain = false
			}
			s.pos++
		}
	}
	return 0, 0, false, false
}

func isHex(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func (s *scanner) array() bool {
	if s.depth++; s.depth > MaxDepth {
		return false
	}
	s.pos++
	s.space()
	if s.pos < len(s.data) && s.data[s.pos] == ']' {
		s.pos++
		s.depth--
		return true
	}
	depth := s.depth
	for {
		elementStart := s.pos
		if !s.value() {
			return false
		}
		if depth == 1 && s.elements != nil {
			*s.elements = append(*s.elements, s.data[elementStart:s.pos])
		}
		s.space()
		if s.pos >= len(s.data) {
			return false
		}
		switch s.data[s.pos] {
		case ',':
			s.pos++
			s.space()
		case ']':
			s.pos++
			s.depth--
			return true
		default:
			return false
		}
	}
}

func (s *scanner) object() bool {
	if s.depth++; s.depth > MaxDepth {
		return false
	}
	depth := s.depth
	s.pos++
	s.space()
	if s.pos < len(s.data) && s.data[s.pos] == '}' {
		s.pos++
		s.depth--
		return true
	}
	for len(s.keys) <= depth {
		s.keys = append(s.keys, nil)
	}
	keys := s.keys[depth][:0]
	var seen map[string]struct{}
	for {
		if s.pos >= len(s.data) || s.data[s.pos] != '"' {
			return false
		}
		quote := s.pos
		start, end, plain, ok := s.str()
		if !ok {
			return false
		}
		key := keyRef{start: start, end: end, plain: plain}
		if !plain {
			decoded, ok := decodeKey(s.data[quote : end+1])
			if !ok {
				return false
			}
			key.decoded = decoded
		}
		switch {
		case seen != nil:
			name := s.keyString(key)
			if _, dup := seen[name]; dup {
				return false
			}
			seen[name] = struct{}{}
		default:
			for _, k := range keys {
				if s.sameKey(k, key) {
					return false
				}
			}
			keys = append(keys, key)
			if len(keys) == linearKeys {
				seen = make(map[string]struct{}, 2*linearKeys)
				for _, k := range keys {
					seen[s.keyString(k)] = struct{}{}
				}
			}
		}
		s.space()
		if s.pos >= len(s.data) || s.data[s.pos] != ':' {
			return false
		}
		s.pos++
		s.space()
		// The value may be an object one level down, which uses the next
		// slot; this object's keys stay in their own.
		s.keys[depth] = keys
		valueStart := s.pos
		if !s.value() {
			return false
		}
		if depth == 1 && s.top != nil {
			*s.top = append(*s.top, Field{Key: s.keyString(key), Value: s.data[valueStart:s.pos]})
		}
		s.space()
		if s.pos >= len(s.data) {
			return false
		}
		switch s.data[s.pos] {
		case ',':
			s.pos++
			s.space()
		case '}':
			s.pos++
			s.depth--
			s.keys[depth] = keys[:0]
			return true
		default:
			return false
		}
	}
}

// decodeKey decodes a quoted key as encoding/json does. It is its own
// function so that the pointer json.Unmarshal takes does not move every key
// the scanner reads to the heap.
func decodeKey(quoted []byte) (string, bool) {
	var decoded string
	if json.Unmarshal(quoted, &decoded) != nil {
		return "", false
	}
	return decoded, true
}
