package main

import (
	"bytes"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
	"unicode/utf8"
)

// dumpData returns the lines of one section with the end-of-string rule on
// or off.
func dumpData(s Section, terminated bool) []string {
	var got []string

	d := Dumper{
		opts:       Options{MinLength: 4, SymLength: 10},
		sink:       func(line string) { got = append(got, line) },
		terminated: terminated,
	}
	d.DumpSection(s)

	return got
}

func TestEndRule(t *testing.T) {
	long := strings.Repeat("a", 5000)

	tests := []struct {
		name string
		data string
		want []string
	}{
		{"NUL-terminated", "\x01\x02hello world\x00", []string{"hello world"}},
		{"glued to binary data", "\x00hello world\xff\xfe\xfd\xfc\x01\x02\x03\x04\x00kept\x00", []string{"kept"}},
		{"UTF-8 character", "\x00Arc Tangent from -\xcf\x80\x00", []string{"Arc Tangent from -"}},
		{"ANSI escape", "\x00\x1b[31mred text\x1b[0m\x00", []string{"[31mred text"}},
		{"Latin-1 in mostly ASCII", "\x00value \xb1 tolerance\x00", []string{"value ", " tolerance"}},
		{"C1 code points", "\x00text\xc2\x80\xc2\x81\xc2\x82\xc2\x83\x00", nil},
		{"Latin-1 supplement code points", "\x00text\xc3\x80\xc3\x81\xc3\x82\xc3\x83\x00", []string{"text"}},
		{"DEL", "\x00text\x7f\x7f\x7f\x7f\x7f\x7f\x00", nil},
		{"no NUL after within window", "\x00hello world\x80" + long + "\x00", []string{long}},
		{"no NUL before within window", long + "\xc3hello world\x80\x00", []string{long}},
		{"section start and end within window", "hello world\x80tail", []string{"hello world", "tail"}},
		{"section start at window edge", strings.Repeat("é", textWindow/2) + "hello worldé\x00", []string{"hello world"}},
		{"section start past window edge", "\x01\x01" + strings.Repeat("é", textWindow/2-2) + "€hello worldé\x00", nil},
		{"section end at window edge", "\x00hello world" + strings.Repeat("é", textWindow/2), []string{"hello world"}},
		{"section end past window edge", "\x00hello world" + strings.Repeat("é", textWindow/2-2) + "€\x01\x01", nil},
		{"UTF-8 window without NUL", strings.Repeat("é", textWindow) + "hello world€" + strings.Repeat("é", textWindow), []string{"hello world"}},
		{"UTF-8 window cut inside characters", "\x01" + strings.Repeat("€", textWindow/3+1) + "hello world" + strings.Repeat("€", textWindow/3+1) + "\x01", []string{"hello world"}},
		{"binary in window without NUL", strings.Repeat("é", textWindow) + "hello world\x80" + strings.Repeat("é", textWindow), nil},
	}

	for _, test := range tests {
		data := []byte(test.data)

		if got := dumpData(Section{Kind: KindData, Data: data}, true); !reflect.DeepEqual(got, test.want) {
			t.Errorf("%s: lines = %q, want %q", test.name, got, test.want)
		}
	}
}

func TestEndRuleWindowPerRun(t *testing.T) {
	// Both runs share one text segment, but the NUL before "last" is
	// further back than the window, and its window is not valid UTF-8.
	filler := strings.Repeat("abc\x80", 375)
	data := []byte("\x00" + filler + "first\x80" + filler + filler + "last\x80\x00")

	got := dumpData(Section{Kind: KindData, Data: data}, true)
	want := []string{"first"}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("lines = %q, want %q", got, want)
	}
}

// referenceKeeps is the end-of-string rule with bounded searches for each run.
func referenceKeeps(d []byte, s, e int) bool {
	if e == len(d) || d[e] == 0 {
		return true
	}

	whole := true

	lo := max(0, s-textWindow)
	a := bytes.LastIndexByte(d[lo:s], 0)

	switch {
	case a >= 0:
		a += lo + 1
	case lo > 0:
		a, whole = lo, false
	default:
		a = 0
	}

	hi := min(len(d), e+textWindow)
	b := bytes.IndexByte(d[e:hi], 0)

	switch {
	case b >= 0:
		b += e
	case hi < len(d):
		b, whole = hi, false
	default:
		b = len(d)
	}

	if whole {
		return isText(d[a:b])
	}

	return referenceUTF8(d, a, b)
}

// referenceUTF8 reports whether every character that starts in d[a:b] is
// valid UTF-8 text, skipping continuation bytes at a.
func referenceUTF8(d []byte, a, b int) bool {
	for k := 0; k < 3 && a < b && d[a]&0xC0 == 0x80; k++ {
		a++
	}

	for i := a; i < b; {
		r, n := utf8.DecodeRune(d[i:])

		switch {
		case r < utf8.RuneSelf:
			if !textControl[r] {
				return false
			}
		case r < 0xA0, r == utf8.RuneError && n == 1:
			return false
		}

		i += n
	}

	return true
}

func TestEndRuleMatchesReference(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	alphabet := []byte("\x00\x01\x1b\x7f\x80\xa0\xb1\xc2\xc3\xcf\xe2\xffabc \t\n")
	outcomes := map[bool]int{}

	for iter := range 200 {
		data := make([]byte, 1+rng.IntN(3*textWindow))
		nul := 1 + rng.IntN(5000)
		special := 2 + rng.IntN(30)

		for i := range data {
			switch {
			case rng.IntN(nul) == 0:
				data[i] = 0
			case rng.IntN(special) == 0:
				data[i] = alphabet[1+rng.IntN(len(alphabet)-1)]
			default:
				data[i] = 'a' + byte(rng.IntN(26))
			}
		}

		ends := newEndRule(data)

		for off, run := range splitRuns(data) {
			e := off + len(run)
			got, want := ends.keeps(off, e), referenceKeeps(data, off, e)

			if got != want {
				t.Fatalf("iteration %d, run at %d of %d bytes: keeps = %v, want %v", iter, off, len(data), got, want)
			}

			if e < len(data) && data[e] != 0 {
				outcomes[got]++
			}
		}
	}

	if outcomes[false] == 0 || outcomes[true] == 0 {
		t.Errorf("unterminated runs kept %d, dropped %d; want both", outcomes[true], outcomes[false])
	}
}

func TestEndRuleSectionKinds(t *testing.T) {
	data := []byte("\x00hello world\xff\xfe\xfd\xfc\x01\x02\x03\x04\x00")

	for _, kind := range []SectionKind{KindStrings, KindNote, KindFallback} {
		if got := dumpData(Section{Kind: kind, Data: data}, true); len(got) != 1 {
			t.Errorf("%s: lines = %q, want the run kept", kind, got)
		}
	}

	if got := dumpData(Section{Kind: KindData, Data: data}, false); len(got) != 1 {
		t.Errorf("rule off: lines = %q, want the run kept", got)
	}
}

func TestEndRuleImportRewrite(t *testing.T) {
	rewrite := map[int]int{1: 3, 2: 3}

	kept := dumpData(Section{Kind: KindData, Data: []byte("\x00\x41\x42ImportedName\x00"), Rewrite: rewrite}, true)
	if want := []string{"ImportedName"}; !reflect.DeepEqual(kept, want) {
		t.Errorf("terminated import: lines = %q, want %q", kept, want)
	}

	glued := []byte("\x00\x41\x42ImportedName\xff\xfe\xfd\xfc\x01\x02\x03\x04\x00")

	if got := dumpData(Section{Kind: KindData, Data: glued, Rewrite: rewrite}, true); got != nil {
		t.Errorf("glued import: lines = %q, want none", got)
	}

	if got, want := dumpData(Section{Kind: KindData, Data: glued, Rewrite: rewrite}, false), []string{"ImportedName"}; !reflect.DeepEqual(got, want) {
		t.Errorf("glued import, rule off: lines = %q, want %q", got, want)
	}
}

func TestResolveTerminated(t *testing.T) {
	plain := []byte("\x7fELF plain C binary\x00")
	aligned := func(b []byte) []byte {
		return append(bytes.Clone(b), make([]byte, (16-len(b)%16)%16)...)
	}
	goBin := append(aligned(plain), "\xff Go buildinf:\x08\x02"...)
	unaligned := append(append(aligned(plain), 0), "\xff Go buildinf:\x08\x02"...)
	literal := append(aligned(plain), "\xff Go buildinf:\x001.21.0"...)
	literalFirst := append(aligned(literal), "\xff Go buildinf:\x04\x02"...)
	rustBin := append(bytes.Clone(plain), "/rustc/90b35a6239c3d8bdabc530a6a0816f7ff89a0aaf/library/core\x00"...)

	tests := []struct {
		mode      string
		data      []byte
		want      bool
		toolchain string
	}{
		{"auto", plain, true, ""},
		{"auto", goBin, false, "Go"},
		{"auto", rustBin, false, "Rust"},
		{"auto", unaligned, true, ""},
		{"auto", literal, true, ""},
		{"auto", literalFirst, false, "Go"},
		{"on", goBin, true, ""},
		{"off", plain, false, ""},
	}

	for _, test := range tests {
		got, toolchain := ResolveTerminated(test.mode, test.data)
		if got != test.want || toolchain != test.toolchain {
			t.Errorf("ResolveTerminated(%q, %q) = %v, %q, want %v, %q", test.mode, test.data, got, toolchain, test.want, test.toolchain)
		}
	}
}
