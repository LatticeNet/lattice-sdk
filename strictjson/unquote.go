package strictjson

import (
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// String decodes the JSON string literal raw, quotes included, to exactly
// what json.Unmarshal decodes it to: escapes resolved, a \u surrogate pair
// joined and a lone surrogate replaced by U+FFFD, and every invalid UTF-8
// byte replaced by U+FFFD. ok is false when raw is not one string literal
// as encoding/json reads it (a control byte, an unknown escape, a short \u,
// a missing quote), and the caller runs json.Unmarshal, which words the
// error. A snapshot travels as a JSON string of several MiB, and
// json.Unmarshal scans it once to validate and again to unquote; this does
// both in one pass.
func String(raw []byte) (string, bool) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return "", false
	}
	s := raw[1 : len(raw)-1]
	i := 0
	for i < len(s) {
		if c := s[i]; c == '\\' || c == '"' || c < 0x20 || c >= utf8.RuneSelf {
			break
		}
		i++
	}
	if i == len(s) {
		return string(s), true
	}
	var b strings.Builder
	b.Grow(len(s))
	b.Write(s[:i])
	for i < len(s) {
		c := s[i]
		switch {
		case c == '\\':
			if i+1 >= len(s) {
				return "", false
			}
			switch s[i+1] {
			case '"', '\\', '/':
				b.WriteByte(s[i+1])
				i += 2
			case 'b':
				b.WriteByte('\b')
				i += 2
			case 'f':
				b.WriteByte('\f')
				i += 2
			case 'n':
				b.WriteByte('\n')
				i += 2
			case 'r':
				b.WriteByte('\r')
				i += 2
			case 't':
				b.WriteByte('\t')
				i += 2
			case 'u':
				r := hex4(s[i:])
				if r < 0 {
					return "", false
				}
				i += 6
				if utf16.IsSurrogate(r) {
					if dec := utf16.DecodeRune(r, hex4(s[i:])); dec != utf8.RuneError {
						b.WriteRune(dec)
						i += 6
						continue
					}
					r = utf8.RuneError
				}
				b.WriteRune(r)
			default:
				return "", false
			}
		case c == '"' || c < 0x20:
			return "", false
		case c < utf8.RuneSelf:
			j := i + 1
			for j < len(s) {
				if c := s[j]; c == '\\' || c == '"' || c < 0x20 || c >= utf8.RuneSelf {
					break
				}
				j++
			}
			b.Write(s[i:j])
			i = j
		default:
			r, size := utf8.DecodeRune(s[i:])
			if r == utf8.RuneError && size == 1 {
				b.WriteRune(utf8.RuneError)
			} else {
				b.Write(s[i : i+size])
			}
			i += size
		}
	}
	return b.String(), true
}

// StringInto is json.Unmarshal of the JSON value raw into *dst for the two
// forms a string member takes: a string literal, decoded by String, or null,
// which leaves *dst as it is, as json.Unmarshal does. ok is false for
// anything else, and the caller runs json.Unmarshal.
func StringInto(raw []byte, dst *string) bool {
	if string(raw) == "null" {
		return true
	}
	s, ok := String(raw)
	if ok {
		*dst = s
	}
	return ok
}

// hex4 is the code unit of the \uXXXX escape s starts with, or -1.
func hex4(s []byte) rune {
	if len(s) < 6 || s[0] != '\\' || s[1] != 'u' {
		return -1
	}
	var r rune
	for _, c := range s[2:6] {
		switch {
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			c = c - 'A' + 10
		default:
			return -1
		}
		r = r*16 + rune(c)
	}
	return r
}
