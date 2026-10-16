package main

import (
	"bytes"
	"unicode/utf8"
)

// textWindow is how far the end-of-string rule searches on either side of a
// run for the NUL bytes that delimit its string.
const textWindow = 4096

// textControl marks the ASCII bytes allowed in a valid UTF-8 string: the
// string bytes and ESC.
var textControl = func() (t [utf8.RuneSelf]bool) {
	copy(t[:], isRunByte[:utf8.RuneSelf])
	t[0x1B] = true

	return t
}()

// textPrintable marks the bytes counted as printable when a string is not
// valid UTF-8: the string bytes except vertical tab and form feed.
var textPrintable = func() (t [256]bool) {
	t = isRunByte
	t['\v'], t['\f'] = false, false

	return t
}()

// textRune returns the length of the character d starts with when it is valid
// UTF-8 text as isText defines it, or 0.
func textRune(d []byte) int {
	if c := d[0]; c < utf8.RuneSelf {
		if textControl[c] {
			return 1
		}

		return 0
	}

	r, n := utf8.DecodeRune(d)
	if r < 0xA0 || (r == utf8.RuneError && n <= 1) {
		return 0
	}

	return n
}

// isText reports whether seg reads as a string. It does when seg is valid
// UTF-8 without control characters other than textControl and without C1 code
// points (U+0080 to U+009F). It also does when at least three quarters of the
// bytes are printable ASCII.
func isText(seg []byte) bool {
	strict := true
	printable := 0

	for i := 0; i < len(seg); {
		if textPrintable[seg[i]] {
			printable++
		}

		if strict {
			if n := textRune(seg[i:]); n > 0 {
				i += n
				continue
			}

			strict = false
		}

		i++
	}

	return strict || printable >= 3*(len(seg)-printable)
}

// endRule decides whether the runs of a data section end a string. Runs must
// be passed in order. This lets it track the NUL bytes around them in one pass
// over the section. It can also reuse the verdict of a segment that several
// runs share.
type endRule struct {
	data []byte

	// prevNul is the offset of the last NUL byte before scanned, or -1.
	prevNul, scanned int

	// nextNul is the offset of the first NUL byte after the last run that
	// needed it, len(data) when there is none, or -1.
	nextNul int

	// start is the offset of the segment whose verdict is text, or -1.
	start int
	text  bool

	// nextBad is the offset of the first byte that is not valid UTF-8 text
	// at or after the start of the last window checked, or -1. Window starts
	// never decrease, so it holds until a window starts past it.
	nextBad int
}

func newEndRule(data []byte) endRule {
	return endRule{data: data, prevNul: -1, nextNul: -1, start: -1, nextBad: -1}
}

// keeps reports whether the run data[s:e] is kept. A run is kept when a NUL
// byte or the end of the section follows it. It is also kept when the text
// around it reads as a string.
func (r *endRule) keeps(s, e int) bool {
	d := r.data

	if e == len(d) || d[e] == 0 {
		return true
	}

	if s > r.scanned {
		if i := bytes.LastIndexByte(d[r.scanned:s], 0); i >= 0 {
			r.prevNul = r.scanned + i
		}
	}

	// A run holds no NUL bytes, so the search resumes at its end.
	r.scanned = e

	return r.textAround(s, e)
}

// textAround reports whether the text around the run data[s:e] reads as a
// string. The delimiters are the NUL bytes around the run, or the section
// start and end. When they lie within textWindow bytes of the run, the segment
// between them must pass isText. Otherwise, the window of textWindow bytes on
// each side must be valid UTF-8 text. A delimiting NUL byte cuts the window
// short.
func (r *endRule) textAround(s, e int) bool {
	d := r.data
	whole := true

	a := 0
	if r.prevNul >= 0 && r.prevNul >= s-textWindow {
		a = r.prevNul + 1
	} else if s > textWindow {
		a, whole = s-textWindow, false
	}

	if r.nextNul < e {
		r.nextNul = len(d)
		if i := bytes.IndexByte(d[e:], 0); i >= 0 {
			r.nextNul = e + i
		}
	}

	b := r.nextNul
	if b-e >= textWindow && e+textWindow < len(d) {
		b, whole = e+textWindow, false
	}

	if !whole {
		if r.nextBad < a {
			r.nextBad = firstNonText(d, a)
		}

		return r.nextBad >= b
	}

	if a != r.start {
		r.start, r.text = a, isText(d[a:b])
	}

	return r.text
}

// firstNonText returns the offset of the first byte at or after i that is not
// valid UTF-8 text as isText defines it, or len(d). It skips up to three
// continuation bytes at i, since i may fall inside a multibyte character.
func firstNonText(d []byte, i int) int {
	for k := 0; k < 3 && i < len(d) && d[i]&0xC0 == 0x80; k++ {
		i++
	}

	for i < len(d) {
		n := textRune(d[i:])
		if n == 0 {
			return i
		}

		i += n
	}

	return len(d)
}

// toolchains detect binaries whose toolchain stores strings with a length
// instead of a NUL terminator.
var toolchains = []struct {
	name  string
	match func(data []byte) bool
}{
	{"Go", hasGoBuildInfo},
	{"Rust", func(data []byte) bool { return bytes.Contains(data, []byte("/rustc/")) }},
}

var goBuildInfoMagic = []byte("\xff Go buildinf:")

// hasGoBuildInfo reports whether data holds Go build info: the magic at a
// 16-byte aligned offset followed by a pointer size of 4 or 8. C programs and
// the Go linker carry unaligned or malformed copies of the magic string as
// literals. These copies do not count.
func hasGoBuildInfo(data []byte) bool {
	for off := 0; off+15 <= len(data); off += 16 {
		if data[off] == 0xFF && bytes.HasPrefix(data[off:], goBuildInfoMagic) && (data[off+14] == 4 || data[off+14] == 8) {
			return true
		}
	}

	return false
}

// ResolveTerminated returns whether the end-of-string rule applies to a file
// for the given -terminated mode. For "auto", it also returns the toolchain
// that turned the rule off, if any.
func ResolveTerminated(mode string, data []byte) (bool, string) {
	switch mode {
	case "on":
		return true, ""
	case "off":
		return false, ""
	}

	for _, t := range toolchains {
		if t.match(data) {
			return false, t.name
		}
	}

	return true, ""
}
