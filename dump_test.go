package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"reflect"
	"testing"
)

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

// note encodes one ELF note record with the given alignment.
func note(name, desc string, align int) []byte {
	pad := func(b []byte) []byte {
		for len(b)%align != 0 {
			b = append(b, 0)
		}
		return b
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, [3]uint32{uint32(len(name)), uint32(len(desc)), 1})
	buf.Write(pad([]byte(name)))
	buf.Write(pad([]byte(desc)))

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

	warned := false
	descs := elfNotes(note("GNU\x00", "abcdefgh", 4)[:20], 4, binary.LittleEndian, "n", func(string, ...any) { warned = true })

	if len(descs) != 0 || !warned {
		t.Errorf("truncated note: descs %q, warned %v", descs, warned)
	}
}

// buildELF returns a little-endian ELF64 file with the given sections after
// the null section; the section name table is appended last.
func buildELF(sections []elf.Section64, contents [][]byte, names []string) []byte {
	shstrtab := []byte{0}
	for i, name := range append(names, ".shstrtab") {
		if i < len(sections) {
			sections[i].Name = uint32(len(shstrtab))
		} else {
			sections = append(sections, elf.Section64{Name: uint32(len(shstrtab)), Type: uint32(elf.SHT_STRTAB), Addralign: 1})
			contents = append(contents, nil)
		}
		shstrtab = append(shstrtab, name...)
		shstrtab = append(shstrtab, 0)
	}
	contents[len(contents)-1] = shstrtab

	var body bytes.Buffer
	off := uint64(64)
	for i, c := range contents {
		sections[i].Off = off
		sections[i].Size = uint64(len(c))
		body.Write(c)
		off += uint64(len(c))
	}

	hdr := elf.Header64{
		Type:      uint16(elf.ET_DYN),
		Machine:   uint16(elf.EM_X86_64),
		Version:   uint32(elf.EV_CURRENT),
		Shoff:     off,
		Ehsize:    64,
		Shentsize: 64,
		Shnum:     uint16(len(sections) + 1),
		Shstrndx:  uint16(len(sections)),
	}
	copy(hdr.Ident[:], "\x7fELF\x02\x01\x01")

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, hdr)
	buf.Write(body.Bytes())
	binary.Write(&buf, binary.LittleEndian, elf.Section64{})
	binary.Write(&buf, binary.LittleEndian, sections)

	return buf.Bytes()
}

func TestParseELF(t *testing.T) {
	progbits := elf.Section64{Type: uint32(elf.SHT_PROGBITS), Flags: uint64(elf.SHF_ALLOC), Addralign: 1}
	notes := elf.Section64{Type: uint32(elf.SHT_NOTE), Flags: uint64(elf.SHF_ALLOC), Addralign: 4}

	data := buildELF(
		[]elf.Section64{progbits, progbits, notes, progbits},
		[][]byte{
			[]byte("first rodata\x00"),
			[]byte("second rodata\x00"),
			append(note("GNU\x00", "\x01\x02\x03\x04abcdefgh", 4), note("FDO\x00", "{\"os\":\"linux\"}\x00", 4)...),
			[]byte("relocated data\x00"),
		},
		[]string{".rodata", ".rodata", ".note.package", ".data.rel.ro"},
	)

	b, err := Parse(data, "", func(format string, args ...any) { t.Errorf("unexpected warning: "+format, args...) })
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	d := Dumper{opts: Options{MinLength: 4, SymLength: 10}, sink: func(line string) { got = append(got, line) }}
	d.Dump(b)

	want := []string{"first rodata", "second rodata", "{\"os\":\"linux\"}"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lines = %q, want %q", got, want)
	}
}

func TestParseELFWithoutSections(t *testing.T) {
	data := buildELF(nil, nil, nil)
	copy(data[0x28:0x30], make([]byte, 8)) // e_shoff
	data[0x3C] = 0                         // e_shnum
	data[0x3E] = 0                         // e_shstrndx

	warned := false
	if _, err := Parse(data, "", func(string, ...any) { warned = true }); err == nil || !warned {
		t.Errorf("Parse without section headers: err %v, warned %v", err, warned)
	}
}
