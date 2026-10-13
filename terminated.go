package main

import (
	"bytes"
	"unicode/utf8"
)

// textWindow is how far the end-of-string rule searches on either side of a
// run for the NUL bytes that delimit its string.
const textWindow = 4096

// textControl marks the ASCII bytes allowed in a valid UTF-8 string: tab,
// line feed, vertical tab, form feed, carriage return, ESC and printable
// ASCII.
var textControl = func() (t [utf8.RuneSelf]bool) {
	for c := 0x09; c <= 0x0D; c++ {
		t[c] = true
	}

	t[0x1B] = true

	for c := 0x20; c <= 0x7E; c++ {
		t[c] = true
	}

	return t
}()

// textPrintable marks the bytes counted as printable when a string is not
// valid UTF-8: tab, line feed, carriage return and printable ASCII.
var textPrintable = func() (t [256]bool) {
	t['\t'], t['\n'], t['\r'] = true, true, true

	for c := 0x20; c <= 0x7E; c++ {
		t[c] = true
	}

	return t
}()

// isText reports whether seg reads as a string: valid UTF-8 without control
// characters other than textControl and without C1 code points (U+0080 to
// U+009F), or at least three quarters printable ASCII bytes.
func isText(seg []byte) bool {
	strict := true
	printable := 0

	for i := 0; i < len(seg); {
		c := seg[i]

		if c < utf8.RuneSelf {
			if textPrintable[c] {
				printable++
			} else if !textControl[c] {
				strict = false
			}

			i++
			continue
		}

		if strict {
			r, n := utf8.DecodeRune(seg[i:])
			if r >= 0xA0 && (r != utf8.RuneError || n > 1) {
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
// be passed in order, which lets it track the NUL bytes around them in one
// pass over the section and reuse the verdict of a segment shared by several
// runs.
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

// keeps reports whether the run data[s:e] is kept: it is followed by a NUL
// byte or the end of the section, or the text around it reads as a string.
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
// string. When the NUL bytes that delimit it, or the section start and end,
// lie within textWindow bytes of the run, the segment between them must pass
// isText. Otherwise the window of textWindow bytes on each side, cut short at
// a delimiting NUL byte, must be valid UTF-8 text.
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
// valid UTF-8 text as isText defines it, or len(d). Up to three continuation
// bytes at i are skipped, since i may fall inside a multibyte character.
func firstNonText(d []byte, i int) int {
	for k := 0; k < 3 && i < len(d) && d[i]&0xC0 == 0x80; k++ {
		i++
	}

	for i < len(d) {
		c := d[i]

		if c < utf8.RuneSelf {
			if !textControl[c] {
				return i
			}

			i++
			continue
		}

		r, n := utf8.DecodeRune(d[i:])
		if r < 0xA0 || (r == utf8.RuneError && n <= 1) {
			return i
		}

		i += n
	}

	return len(d)
}

// toolchainMarkers are byte strings found only in binaries whose toolchain
// stores strings with a length instead of a NUL terminator.
var toolchainMarkers = []struct {
	name   string
	marker []byte
}{
	{"Go", []byte("\xff Go buildinf:")},
	{"Rust", []byte("/rustc/")},
}

// ResolveTerminated returns whether the end-of-string rule applies to a file
// for the given -terminated mode, and for "auto" the toolchain that turned it
// off, if any.
func ResolveTerminated(mode string, data []byte) (bool, string) {
	switch mode {
	case "on":
		return true, ""
	case "off":
		return false, ""
	}

	for _, m := range toolchainMarkers {
		if bytes.Contains(data, m.marker) {
			return false, m.name
		}
	}

	return true, ""
}
