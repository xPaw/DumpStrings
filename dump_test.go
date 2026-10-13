package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

// testDumper returns a Dumper with opts that appends every line to lines.
func testDumper(opts Options, lines *[]string) *Dumper {
	return &Dumper{opts: opts, sink: func(l string) { *lines = append(*lines, l) }}
}

// parseAndDump parses data, detecting its format, and dumps it with opts,
// returning the binary, the lines and the warnings.
func parseAndDump(t *testing.T, data []byte, opts Options) (*Binary, []string, []string) {
	t.Helper()

	var warnings []string

	b, err := Parse(data, "auto", func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) })
	if err != nil {
		t.Fatal(err)
	}

	var lines []string

	testDumper(opts, &lines).Dump(b)

	return b, lines, warnings
}

func TestSplitRuns(t *testing.T) {
	var got []string

	for _, run := range splitRuns([]byte("ab\x00cd\tef\x80gh\x7fij\x01")) {
		got = append(got, string(run))
	}

	want := []string{"ab", "cd\tef", "gh", "ij"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("splitRuns = %q, want %q", got, want)
	}
}

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"\x7fELF\x02\x01", "elf"},
		{"MZ\x90\x00", "pe"},
		{"\xcf\xfa\xed\xfe", "macho"},
		{"\xce\xfa\xed\xfe", "macho"},
		{"\xfe\xed\xfa\xce", "macho"},
		{"\xfe\xed\xfa\xcf", "macho"},
		{"\xca\xfe\xba\xbe\x00\x00\x00\x02", "macho"},
		{"\xca\xfe\xba\xbe\x00\x00\x00\x34", ""},
		{"\xca\xfe\xba\xbe", ""},
		{"\x7fEL", ""},
		{"", ""},
	}

	for _, test := range tests {
		got, err := DetectFormat([]byte(test.in))
		if got != test.want || (err == nil) != (test.want != "") {
			t.Errorf("DetectFormat(%q) = %q, %v, want %q", test.in, got, err, test.want)
		}
	}
}

func TestParseFormat(t *testing.T) {
	data := buildElf64(binary.LittleEndian, []testElfSection{{name: ".rodata", data: []byte("some string\x00")}})

	if _, err := Parse(data, "elf", func(string, ...any) {}); err != nil {
		t.Errorf("elf: %v", err)
	}

	if _, err := Parse(data, "pe", func(string, ...any) {}); err == nil {
		t.Error("ELF parsed as PE")
	}

	if _, err := Parse(data, "", func(string, ...any) {}); err == nil {
		t.Error("empty format accepted")
	}
}

func TestFileSlice(t *testing.T) {
	data := []byte("0123456789")
	warnings := 0
	warn := func(string, ...any) { warnings++ }

	if got := fileSlice(data, 2, 3, "a", warn); string(got) != "234" || warnings != 0 {
		t.Errorf("in range: %q, %d warnings", got, warnings)
	}

	if got := fileSlice(data, 8, 5, "b", warn); string(got) != "89" || warnings != 1 {
		t.Errorf("truncated: %q, %d warnings", got, warnings)
	}

	if got := fileSlice(data, 20, 5, "c", warn); got != nil || warnings != 2 {
		t.Errorf("past end: %q, %d warnings", got, warnings)
	}

	if got := fileSlice(data, 4, ^uint64(0), "d", warn); string(got) != "456789" || warnings != 3 {
		t.Errorf("overflow: %q, %d warnings", got, warnings)
	}
}

// note encodes one ELF note record with the given alignment, padding so the
// name, descriptor and next record start at aligned offsets.
func note(name, desc string, align int) []byte {
	var buf bytes.Buffer
	pad := func() {
		for buf.Len()%align != 0 {
			buf.WriteByte(0)
		}
	}

	binary.Write(&buf, binary.LittleEndian, [3]uint32{uint32(len(name)), uint32(len(desc)), 1})
	buf.WriteString(name)
	pad()
	buf.WriteString(desc)
	pad()

	return buf.Bytes()
}

func TestElfNotes(t *testing.T) {
	for _, align := range []int{4, 8} {
		data := append(note("GNU\x00", "\x01\x02\x03\x04abcdefgh", align), note("FDO\x00", "{\"type\":\"deb\"}\x00", align)...)

		descs := elfNotes(data, uint64(align), binary.LittleEndian, "n", func(string, ...any) {
			t.Errorf("align %d: unexpected warning", align)
		})

		if len(descs) != 2 || isPrintableNote(descs[0]) || !isPrintableNote(descs[1]) {
			t.Errorf("align %d: descs %q", align, descs)
		}
	}

	// An 8-aligned property note has a 4-byte name and pads it to the next
	// absolute 8-byte offset.
	props := append(note("GNU\x00", "\x02\x00\x00\xc0\x04\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00", 8), note("FDO\x00", "{\"type\":\"deb\"}\x00", 8)...)
	descs := elfNotes(props, 8, binary.LittleEndian, "n", func(string, ...any) {
		t.Errorf("aligned property note: unexpected warning")
	})

	if len(descs) != 2 || len(descs[0]) != 16 || !isPrintableNote(descs[1]) {
		t.Errorf("aligned property note: descs %q", descs)
	}

	warned := false
	descs = elfNotes(note("GNU\x00", "abcdefgh", 4)[:20], 4, binary.LittleEndian, "n", func(string, ...any) { warned = true })

	if len(descs) != 0 || !warned {
		t.Errorf("truncated note: descs %q, warned %v", descs, warned)
	}
}

func TestParseELF(t *testing.T) {
	notes := append(note("GNU\x00", "\x01\x02\x03\x04abcdefgh", 4), note("FDO\x00", "{\"os\":\"linux\"}\x00", 4)...)
	notes = append(notes, note("PKG\x00", "second note\x00\x00\x00\x00\x00", 4)...)

	data := buildElf64(binary.LittleEndian, []testElfSection{
		{name: ".rodata", data: []byte("first rodata\x00")},
		{name: ".rodata", data: []byte("second rodata\x00")},
		{name: ".note.package", typ: elf.SHT_NOTE, data: notes},
		{name: ".data.rel.ro", data: []byte("relocated data\x00")},
	})

	b, got, warnings := parseAndDump(t, data, Options{MinLength: 4, SymLength: 10})

	want := []string{"first rodata", "second rodata", "{\"os\":\"linux\"}", "second note"}
	if !reflect.DeepEqual(got, want) || len(warnings) != 0 {
		t.Errorf("lines = %q, want %q (warnings %q)", got, want, warnings)
	}

	// The note descriptors are joined into one section that is not masked
	// and takes no end-of-string rule.
	if len(b.Sections) != 3 || string(b.Sections[2].Data) != "{\"os\":\"linux\"}\x00\x00second note\x00\x00\x00\x00\x00\x00" {
		t.Fatalf("sections %+v", b.Sections)
	}

	for i, s := range b.Sections {
		if wantRules := i < 2; s.Mask != wantRules || s.EndRule != wantRules {
			t.Errorf("section %d: mask %v, end rule %v", i, s.Mask, s.EndRule)
		}
	}
}

func TestParseELFBinaryNotesAreReadable(t *testing.T) {
	data := buildElf64(binary.LittleEndian, []testElfSection{
		{name: ".note.gnu.build-id", typ: elf.SHT_NOTE, data: note("GNU\x00", "\x01\x02\x03\x04\x05\x06\x07\x08", 4)},
	})

	b, lines, warnings := parseAndDump(t, data, Options{MinLength: 4, SymLength: 10})

	if !b.Readable || len(lines) != 0 || len(warnings) != 0 {
		t.Errorf("readable %v, lines %q, warnings %q", b.Readable, lines, warnings)
	}
}

func TestParseELFWithoutSections(t *testing.T) {
	data := buildElf64(binary.LittleEndian, nil)
	copy(data[0x28:0x30], make([]byte, 8)) // e_shoff
	data[0x3C] = 0                         // e_shnum
	data[0x3E] = 0                         // e_shstrndx

	warned := false
	if _, err := Parse(data, "auto", func(string, ...any) { warned = true }); err == nil || !warned {
		t.Errorf("Parse without section headers: err %v, warned %v", err, warned)
	}
}

func TestHasLine(t *testing.T) {
	d := Dumper{opts: Options{MinLength: 4, SymLength: 10}}

	tests := []struct {
		name string
		data string
		want bool
	}{
		{"empty", "", false},
		{"too short", "ab\x00cd\x00", false},
		{"short symbols", "!@#$%^\x00", false},
		{"long symbols", "!@#$%^&*()_+=", true},
		{"short word", "abcd", true},
		{"second run", "ab\x00\x01abcdef\x00", true},
	}

	for _, test := range tests {
		if got := d.hasLine(Section{Data: []byte(test.data)}); got != test.want {
			t.Errorf("%s: hasLine = %v, want %v", test.name, got, test.want)
		}
	}
}

func TestDumpMasksOnlyMaskedSections(t *testing.T) {
	blob := append(descriptor("x/y.proto"), 0)
	orig := bytes.Clone(blob)

	count := func(maskProtobufs bool, masks ...bool) int {
		b := &Binary{}
		for _, mask := range masks {
			b.Sections = append(b.Sections, Section{Data: blob, Mask: mask})
		}

		var lines []string
		testDumper(Options{MinLength: 4, SymLength: 10, MaskProtobufs: maskProtobufs}, &lines).Dump(b)

		return len(lines)
	}

	one := count(false, true)
	if one == 0 {
		t.Fatal("descriptor produced no lines")
	}

	if got := count(true, true, false, false); got != 2*one {
		t.Errorf("masked: %d lines, want %d", got, 2*one)
	}

	if got := count(false, true, false, false); got != 3*one {
		t.Errorf("kept: %d lines, want %d", got, 3*one)
	}

	if !bytes.Equal(blob, orig) {
		t.Error("masking modified the section data")
	}
}

func TestDumpDoesNotMaskByDefault(t *testing.T) {
	b := &Binary{Sections: []Section{{Data: append(descriptor("x/y.proto"), 0), Mask: true, EndRule: true}}}

	var got []string
	testDumper(Options{MinLength: 4, SymLength: 10}, &got).Dump(b)

	if !slices.ContainsFunc(got, func(l string) bool { return strings.Contains(l, "x/y.proto") }) {
		t.Errorf("descriptor name missing from %q", got)
	}
}

func TestPrintSections(t *testing.T) {
	b := &Binary{Headers: []SectionHeader{
		{Name: ".rodata", Type: "PROGBITS A", Addr: 0x1000, Size: 0x2a, Read: "data"},
		{Name: ".bss", Type: "NOBITS WA", Addr: 0x3000, Size: 0x10},
	}}

	var out strings.Builder
	PrintSections(&out, b)

	want := ".rodata\tPROGBITS A\taddr=0x1000\tsize=0x2a\tread=data\n" +
		".bss\tNOBITS WA\taddr=0x3000\tsize=0x10\tread=-\n"
	if out.String() != want {
		t.Errorf("PrintSections = %q, want %q", out.String(), want)
	}
}
