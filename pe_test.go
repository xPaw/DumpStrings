package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestRvaToOffset(t *testing.T) {
	secs := []peSection{
		{rva: 0x1000, vsize: 0x300, rawSize: 0x200, rawOff: 0x400},
		{rva: 0x2000, vsize: 0x100, rawSize: 0x200, rawOff: 0x600},
	}

	tests := []struct {
		rva  uint32
		size int
		want uint32
		ok   bool
	}{
		{0x0fff, 0x1000, 0, false},
		{0x1000, 0x1000, 0x400, true},
		{0x11ff, 0x1000, 0x5ff, true},
		{0x1200, 0x1000, 0, false},
		{0x12ff, 0x1000, 0, false},
		{0x1300, 0x1000, 0, false},
		{0x2000, 0x1000, 0x600, true},
		{0x21ff, 0x1000, 0x7ff, true},
		{0x2200, 0x1000, 0, false},
		{0x1100, 0x480, 0, false},
		{0xffffffff, 0x1000, 0, false},
	}

	for _, test := range tests {
		got, ok := rvaToOffset(secs, test.size, test.rva)
		if got != test.want || ok != test.ok {
			t.Errorf("rvaToOffset(0x%x, size 0x%x) = 0x%x, %v, want 0x%x, %v", test.rva, test.size, got, ok, test.want, test.ok)
		}
	}

	if _, ok := rvaToOffset([]peSection{{rva: 0xfffff000, vsize: 0x2000, rawSize: 0x2000, rawOff: 0xfffff000}}, 1<<20, 0xfffff800); ok {
		t.Error("offset past the file mapped")
	}
}

// flatImage maps one section so that RVA r is file offset r.
func flatImage(n int) *peReader {
	return &peReader{
		data: make([]byte, n),
		secs: []peSection{{rva: 0, vsize: uint32(n), rawSize: uint32(n), rawOff: 0}},
	}
}

func TestImportDirectories(t *testing.T) {
	for _, wide := range []bool{false, true} {
		r := flatImage(0x2000)
		put32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(r.data[off:], v) }
		stride := 4
		if wide {
			stride = 8
		}

		thunk := func(off int, v uint64) {
			if wide {
				binary.LittleEndian.PutUint64(r.data[off:], v)
			} else {
				put32(off, uint32(v))
			}
		}

		ord := uint64(1) << 31
		if wide {
			ord = 1 << 63
		}

		const base = 0x10000000

		// Import descriptor 1 uses its original thunks. Descriptor 2 has none,
		// so it uses the first thunks.
		put32(0x100, 0x400)
		put32(0x100+16, 0x500)
		put32(0x114+16, 0x600)
		thunk(0x400, 0x1000)
		thunk(0x400+stride, ord|5)
		thunk(0x400+2*stride, 0x1100)
		thunk(0x600, 0x1200)

		// Delay descriptor 1 holds VAs, descriptor 2 holds RVAs.
		put32(0x200, 0)
		put32(0x200+16, base+0x700)
		thunk(0x700, base+0x1300)
		thunk(0x700+stride, ord|7)
		thunk(0x700+2*stride, 0x1)
		put32(0x220, 1)
		put32(0x220+16, 0x800)
		thunk(0x800, 0x1400)

		hints := map[uint32]struct{}{}
		r.walkImports(0x100, wide, base, hints)
		r.walkDelayImports(0x200, wide, base, hints)

		want := []uint32{0x1000, 0x1100, 0x1200, 0x1300, 0x1400}
		if got := slices.Sorted(maps.Keys(hints)); !reflect.DeepEqual(got, want) {
			t.Errorf("wide=%v: hints = %x, want %x", wide, got, want)
		}
	}
}

func TestImportDirectoriesGarbage(t *testing.T) {
	r := flatImage(0x1000)

	for i := range r.data {
		r.data[i] = 0xff
	}

	hints := map[uint32]struct{}{}

	for _, wide := range []bool{false, true} {
		r.walkImports(0x0, wide, 0, hints)
		r.walkImports(0xfffffff0, wide, 0, hints)
		r.walkDelayImports(0x0, wide, 0x400000, hints)
		r.walkDelayImports(0x5000, wide, 0, hints)
		r.importNames(0xfffffffc, wide, 0, true, hints)
	}

	// A descriptor with a thunk table that never ends stops at the image.
	for i := range r.data {
		r.data[i] = 0
	}

	binary.LittleEndian.PutUint32(r.data[0x10:], 0x100)

	for i := 0x100; i+4 <= len(r.data); i += 4 {
		binary.LittleEndian.PutUint32(r.data[i:], uint32(0x10+i))
	}

	r.walkImports(0x10, false, 0, hints)

	if len(hints) == 0 {
		t.Error("unterminated thunk table produced no hints")
	}

	if len(peImportHints(nil, &pe.File{}, nil)) != 0 {
		t.Error("hints without an optional header")
	}
}

func TestImportRewrites(t *testing.T) {
	hints := map[uint32]struct{}{0x1004: {}, 0x1ffe: {}, 0x50: {}}
	got := importRewrites(hints, 0x1000, 0x1000)
	want := map[int]int{4: 6, 5: 6}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("importRewrites = %v, want %v", got, want)
	}
}

func TestDumpSectionRewrite(t *testing.T) {
	var got []string

	testDumper(Options{MinLength: 4, SymLength: 10}, &got).DumpSection(Section{
		Data:    []byte("\x00&?Name\x00\x01$Other\x00zz\x00"),
		Rewrite: map[int]int{1: 3, 9: 10, 18: 20},
	})

	want := []string{"Name", "Other"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lines = %q, want %q", got, want)
	}
}

type testPESection struct {
	name string
	data []byte

	// vsize is the VirtualSize. Zero means len(data).
	vsize uint32

	flags uint32
}

// peRVA is the virtual address buildPE gives to section i.
func peRVA(i int) uint32 { return 0x1000 * uint32(i+1) }

// buildPE assembles a minimal PE32 or PE32+ image. Section i is mapped at
// peRVA(i). A section with no data has SizeOfRawData zero. dirs maps a data
// directory index to its RVA and size.
func buildPE(wide bool, base uint64, secs []testPESection, dirs map[int][2]uint32) []byte {
	le := binary.LittleEndian
	optSize, magic, dirOff, machine := 224, uint16(0x10b), 96, uint16(0x14c)

	if wide {
		optSize, magic, dirOff, machine = 240, 0x20b, 112, 0x8664
	}

	hdrSize := 0x58 + optSize + 40*len(secs)
	hdr := make([]byte, (hdrSize+0x1ff)&^0x1ff)

	copy(hdr, "MZ")
	le.PutUint32(hdr[0x3c:], 0x40)
	copy(hdr[0x40:], "PE\x00\x00")
	le.PutUint16(hdr[0x44:], machine)
	le.PutUint16(hdr[0x46:], uint16(len(secs)))
	le.PutUint16(hdr[0x54:], uint16(optSize))

	opt := hdr[0x58:]
	le.PutUint16(opt, magic)

	if wide {
		le.PutUint64(opt[24:], base)
		le.PutUint32(opt[108:], 16)
	} else {
		le.PutUint32(opt[28:], uint32(base))
		le.PutUint32(opt[92:], 16)
	}

	for i, d := range dirs {
		le.PutUint32(opt[dirOff+8*i:], d[0])
		le.PutUint32(opt[dirOff+8*i+4:], d[1])
	}

	var body []byte

	for i, s := range secs {
		h := hdr[0x58+optSize+40*i:]
		vsize := s.vsize

		if vsize == 0 {
			vsize = uint32(len(s.data))
		}

		copy(h, s.name)
		le.PutUint32(h[8:], vsize)
		le.PutUint32(h[12:], peRVA(i))
		le.PutUint32(h[16:], uint32(len(s.data)))
		le.PutUint32(h[36:], s.flags)

		if len(s.data) > 0 {
			le.PutUint32(h[20:], uint32(len(hdr)+len(body)))
			body = append(body, s.data...)
		}
	}

	return append(hdr, body...)
}

// peImportData returns a section of 0x100 bytes mapped at rva. The section
// holds an import descriptor at 0x00 and a delay-import descriptor at 0x30. It
// also holds the hint/name entries "Hi" + "ImportedFunc" at 0xc0 and "Dl" +
// "DelayedFunc" at 0xe0.
// With delayVA the delay descriptor uses virtual addresses instead of RVAs.
func peImportData(wide bool, base uint64, rva uint32, delayVA bool) []byte {
	le := binary.LittleEndian
	d := make([]byte, 0x100)

	thunk := func(off int, v uint64) {
		if wide {
			le.PutUint64(d[off:], v)
		} else {
			le.PutUint32(d[off:], uint32(v))
		}
	}

	le.PutUint32(d[0x00:], rva+0x80)
	thunk(0x80, uint64(rva)+0xc0)

	attrs, table, name := uint32(1), uint64(rva)+0xa0, uint64(rva)+0xe0
	if delayVA {
		attrs, table, name = 0, table+base, name+base
	}

	le.PutUint32(d[0x30:], attrs)
	le.PutUint32(d[0x30+16:], uint32(table))
	thunk(0xa0, name)

	copy(d[0xc0:], "HiImportedFunc\x00")
	copy(d[0xe0:], "DlDelayedFunc\x00")

	return d
}

// peOptions are the options of the PE tests, with the end-of-string rule on
// or off.
func peOptions(terminated bool) Options {
	return Options{MinLength: 4, SymLength: 10, MaskProtobufs: true, Terminated: terminated}
}

func TestPESectionSelection(t *testing.T) {
	for _, wide := range []bool{false, true} {
		img := buildPE(wide, 0x10000000, []testPESection{
			{name: ".text", data: []byte("text only string\x00")},
			{name: ".data"},
			{name: ".data", data: []byte("data string one\x00data string two\x00")},
			{name: ".reloc", data: []byte("other section string\x00")},
			{name: ".rdata", data: []byte("rdata string one\x00")},
		}, nil)

		b, lines, warnings := parseAndDump(t, img, peOptions(false))

		want := []string{"data string one", "data string two", "rdata string one"}
		if !reflect.DeepEqual(lines, want) {
			t.Errorf("wide=%v: lines = %q, want %q", wide, lines, want)
		}

		if len(warnings) != 0 || !b.Readable || len(b.Sections) != 2 || len(b.Fallback) != 1 {
			t.Errorf("wide=%v: warnings %q, readable %v, sections %d, fallback %d", wide, warnings, b.Readable, len(b.Sections), len(b.Fallback))
		}

		for _, s := range b.Sections {
			if !s.Mask || !s.EndRule {
				t.Errorf("wide=%v: data section mask %v, end rule %v", wide, s.Mask, s.EndRule)
			}
		}

		if f := b.Fallback[0]; f.Mask || f.EndRule || f.Rewrite != nil {
			t.Errorf("wide=%v: fallback section %+v", wide, f)
		}

		var reads []string
		for _, h := range b.Headers {
			reads = append(reads, h.Name+"="+h.Read)
		}

		wantReads := []string{".text=fallback", ".data=", ".data=data", ".reloc=", ".rdata=data"}
		if !reflect.DeepEqual(reads, wantReads) {
			t.Errorf("wide=%v: headers = %q, want %q", wide, reads, wantReads)
		}
	}
}

func TestPEVirtualSizeClamp(t *testing.T) {
	img := buildPE(true, 0x140000000, []testPESection{
		{name: ".data", data: []byte("kept string\x00PADDING bytes after\x00"), vsize: 12},
	}, nil)

	_, lines, _ := parseAndDump(t, img, peOptions(false))

	if want := []string{"kept string"}; !reflect.DeepEqual(lines, want) {
		t.Errorf("lines = %q, want %q", lines, want)
	}
}

func TestPETextFallback(t *testing.T) {
	text := testPESection{name: ".text", data: []byte("code string here\x00")}
	ruledOut := []byte("\x00\x01\x02\x03ruled out string\x04\x05\x06\x00")

	tests := []struct {
		name       string
		data       []byte
		terminated bool
		want       []string
	}{
		{"data without a line", []byte("ab\x00"), false, []string{"code string here"}},
		{"data with a line", []byte("data string one\x00"), false, []string{"data string one"}},
		{"only a masked protobuf", append(descriptor("my/thing.proto"), 0), false, nil},
		{"only a ruled out run", ruledOut, true, nil},
		{"ruled out run with the rule off", ruledOut, false, []string{"ruled out string"}},
	}

	for _, test := range tests {
		for _, wide := range []bool{false, true} {
			img := buildPE(wide, 0x10000000, []testPESection{text, {name: ".rdata", data: test.data}}, nil)

			if _, lines, _ := parseAndDump(t, img, peOptions(test.terminated)); !reflect.DeepEqual(lines, test.want) {
				t.Errorf("%s (wide=%v): lines = %q, want %q", test.name, wide, lines, test.want)
			}
		}
	}
}

// peCLR is the data directory of a CLR runtime header, which marks a .NET
// assembly.
var peCLR = map[int][2]uint32{pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR: {peRVA(0), 0x48}}

func TestPEMergedText(t *testing.T) {
	text := []byte("code string here\x00\x00\x01\x02\x03ruled out string\x04\x05\x06\x00")

	tests := []struct {
		name      string
		secs      []testPESection
		dirs      map[int][2]uint32
		want      []string
		wantReads []string
		sections  int
		fallback  int
	}{
		{
			"native without .rdata",
			[]testPESection{{name: ".text", data: text}, {name: ".data", data: []byte("data string one\x00")}},
			nil,
			[]string{"code string here", "data string one"},
			[]string{".text=data", ".data=data"},
			2, 0,
		},
		{
			"only .text",
			[]testPESection{{name: ".text", data: text}},
			nil,
			[]string{"code string here"},
			[]string{".text=data"},
			1, 0,
		},
		{
			"CLR header",
			[]testPESection{{name: ".text", data: text}, {name: ".data", data: []byte("data string one\x00")}},
			peCLR,
			[]string{"data string one"},
			[]string{".text=fallback", ".data=data"},
			1, 1,
		},
		{
			"CLR header without data lines",
			[]testPESection{{name: ".text", data: text}, {name: ".data", data: []byte("ab\x00")}},
			peCLR,
			[]string{"code string here", "ruled out string"},
			[]string{".text=fallback", ".data=data"},
			1, 1,
		},
		{
			"with .rdata",
			[]testPESection{{name: ".text", data: text}, {name: ".data", data: []byte("data string one\x00")}, {name: ".rdata"}},
			nil,
			[]string{"data string one"},
			[]string{".text=fallback", ".data=data", ".rdata="},
			1, 1,
		},
	}

	for _, test := range tests {
		for _, wide := range []bool{false, true} {
			img := buildPE(wide, 0x10000000, test.secs, test.dirs)

			b, lines, warnings := parseAndDump(t, img, peOptions(true))

			var reads []string
			for _, h := range b.Headers {
				reads = append(reads, h.Name+"="+h.Read)
			}

			if !reflect.DeepEqual(lines, test.want) || !reflect.DeepEqual(reads, test.wantReads) || len(warnings) != 0 {
				t.Errorf("%s (wide=%v): lines %q, headers %q, warnings %q", test.name, wide, lines, reads, warnings)
			}

			if len(b.Sections) != test.sections || len(b.Fallback) != test.fallback {
				t.Errorf("%s (wide=%v): sections %d, fallback %d", test.name, wide, len(b.Sections), len(b.Fallback))
			}

			for _, s := range b.Sections {
				if !s.Mask || !s.EndRule {
					t.Errorf("%s (wide=%v): section mask %v, end rule %v", test.name, wide, s.Mask, s.EndRule)
				}
			}
		}
	}
}

func TestPEMergedTextImports(t *testing.T) {
	dirs := map[int][2]uint32{
		pe.IMAGE_DIRECTORY_ENTRY_IMPORT:       {peRVA(0), 0x28},
		pe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT: {peRVA(0) + 0x30, 0x40},
	}

	for _, wide := range []bool{false, true} {
		img := buildPE(wide, 0x10000000, []testPESection{{name: ".text", data: peImportData(wide, 0x10000000, peRVA(0), false)}}, dirs)

		b, lines, _ := parseAndDump(t, img, peOptions(true))

		if want := []string{"ImportedFunc", "DelayedFunc"}; !reflect.DeepEqual(lines, want) || len(b.Sections) != 1 || len(b.Sections[0].Rewrite) != 4 {
			t.Errorf("wide=%v: lines %q, want %q, sections %d", wide, lines, want, len(b.Sections))
		}
	}
}

func TestPEMergedTextTruncated(t *testing.T) {
	text := append([]byte("code string here\x00"), make([]byte, 0x40)...)
	img := buildPE(true, 0x140000000, []testPESection{
		{name: ".data", data: []byte("data string one\x00")},
		{name: ".text", data: text},
	}, nil)

	b, lines, warnings := parseAndDump(t, img[:len(img)-0x20], peOptions(true))

	if want := []string{"data string one", "code string here"}; !reflect.DeepEqual(lines, want) || len(b.Sections) != 2 || !b.Readable || len(warnings) != 1 {
		t.Errorf("lines %q, sections %d, readable %v, warnings %q", lines, len(b.Sections), b.Readable, warnings)
	}
}

func TestPETruncatedDataSkipsFallback(t *testing.T) {
	img := buildPE(true, 0x140000000, []testPESection{
		{name: ".text", data: []byte("code string here\x00")},
		{name: ".data", data: make([]byte, 0x40)},
	}, peCLR)

	b, lines, warnings := parseAndDump(t, img, peOptions(false))

	if want := []string{"code string here"}; !reflect.DeepEqual(lines, want) || len(b.Fallback) != 1 || len(warnings) != 0 {
		t.Errorf("intact: lines %q, fallback %d, warnings %q", lines, len(b.Fallback), warnings)
	}

	b, lines, warnings = parseAndDump(t, img[:len(img)-0x20], peOptions(false))

	if len(lines) != 0 || len(b.Sections) != 1 || len(b.Fallback) != 0 || len(warnings) != 1 {
		t.Errorf("truncated: lines %q, sections %d, fallback %d, warnings %q", lines, len(b.Sections), len(b.Fallback), warnings)
	}

	// With the only data section wholly past the end of the file, nothing
	// can be read.
	b, lines, warnings = parseAndDump(t, img[:len(img)-0x40], peOptions(false))

	if len(lines) != 0 || len(b.Sections) != 0 || len(b.Fallback) != 0 || b.Readable || len(warnings) != 1 {
		t.Errorf("data past the end: lines %q, sections %d, fallback %d, readable %v, warnings %q", lines, len(b.Sections), len(b.Fallback), b.Readable, warnings)
	}

	stdout, stderr, err := runFile(writeTestFile(t, img[:len(img)-0x40]), testRunConfig)
	if err == nil || err.Error() != "no readable sections" || stdout != "" || !strings.Contains(stderr, "past the end of the file") {
		t.Errorf("data past the end: run err %v, stdout %q, stderr %q", err, stdout, stderr)
	}
}

func TestPEDataPastEndWithOtherData(t *testing.T) {
	img := buildPE(true, 0x140000000, []testPESection{
		{name: ".text", data: []byte("code string here\x00")},
		{name: ".rdata", data: []byte("rdata string\x00")},
		{name: ".data", data: make([]byte, 0x40)},
	}, nil)

	b, lines, warnings := parseAndDump(t, img[:len(img)-0x40], peOptions(false))

	if want := []string{"rdata string"}; !reflect.DeepEqual(lines, want) || !b.Readable || len(b.Fallback) != 0 || len(warnings) != 1 {
		t.Errorf("lines %q, readable %v, fallback %d, warnings %q", lines, b.Readable, len(b.Fallback), warnings)
	}
}

// writePESectionOffset sets PointerToRawData of section i of a buildPE image
// and SizeOfHeaders of its optional header.
func writePESectionOffset(img []byte, wide bool, i int, off, sizeOfHeaders uint32) {
	optSize := 224
	if wide {
		optSize = 240
	}

	binary.LittleEndian.PutUint32(img[0x58+60:], sizeOfHeaders)
	binary.LittleEndian.PutUint32(img[0x58+optSize+40*i+20:], off)
}

func TestPESectionWithoutFileData(t *testing.T) {
	tests := []struct {
		name          string
		off           uint32
		sizeOfHeaders uint32
		skipped       bool
	}{
		{"zero offset", 0, 0, true},
		{"zero offset with headers", 0, 0x200, true},
		{"offset inside the headers", 0x10, 0x200, true},
		{"offset without a header size", 0x10, 0, false},
	}

	for _, test := range tests {
		for _, wide := range []bool{false, true} {
			img := buildPE(wide, 0x10000000, []testPESection{
				{name: ".text", data: []byte("code string here\x00")},
				{name: ".rdata", data: []byte("rdata string that is long enough\x00")},
			}, nil)

			copy(img[0x10:], "DOS stub string\x00")
			writePESectionOffset(img, wide, 1, test.off, test.sizeOfHeaders)

			b, lines, warnings := parseAndDump(t, img, peOptions(false))

			want := []string{"code string here"}
			if !test.skipped {
				want = []string{"DOS stub string"}
			}

			if !reflect.DeepEqual(lines, want) || (len(warnings) == 1) != test.skipped || (len(b.Sections) == 0) != test.skipped {
				t.Errorf("%s (wide=%v): lines %q, sections %d, warnings %q", test.name, wide, lines, len(b.Sections), warnings)
			}

			if h := b.Headers[1]; h.Name != ".rdata" || h.Read != "data" {
				t.Errorf("%s (wide=%v): header %+v", test.name, wide, h)
			}
		}
	}

	// A fallback section without file data is skipped too.
	img := buildPE(true, 0x140000000, []testPESection{{name: ".text", data: []byte("code string here\x00")}}, peCLR)
	writePESectionOffset(img, true, 0, 0, 0x200)

	var warnings []string

	b, err := Parse(img, "auto", func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) })
	if err != nil || b.Readable || len(b.Fallback) != 0 || len(warnings) != 1 || b.Headers[0].Read != "fallback" {
		t.Errorf("fallback without file data: err %v, readable %v, fallback %d, warnings %q, header %+v", err, b.Readable, len(b.Fallback), warnings, b.Headers[0])
	}
}

func TestPEImportDescriptorsStopAtWrap(t *testing.T) {
	// The second section covers the top of the address space, so descriptor
	// RVAs past it wrap around to the first section.
	newReader := func() *peReader {
		return &peReader{
			data: make([]byte, 0x200),
			secs: []peSection{
				{rva: 0, vsize: 0x100, rawSize: 0x100, rawOff: 0},
				{rva: 0xffffff00, vsize: 0x100, rawSize: 0x100, rawOff: 0x100},
			},
		}
	}

	put32 := func(r *peReader, off int, v uint32) { binary.LittleEndian.PutUint32(r.data[off:], v) }

	// Two non-empty import descriptors without a name table end exactly at
	// the top. A third at RVA 0 names a hint at 0x80.
	r := newReader()
	put32(r, 0x1d8+4, 1)
	put32(r, 0x1ec+4, 1)
	put32(r, 0x00, 0x40)
	put32(r, 0x40, 0x80)

	hints := map[uint32]struct{}{}
	r.walkImports(0xffffffd8, false, 0, hints)

	if len(hints) != 0 {
		t.Errorf("imports: hints %x after the descriptor RVA wrapped", slices.Sorted(maps.Keys(hints)))
	}

	r = newReader()
	put32(r, 0x1c0, 1)
	put32(r, 0x1e0, 1)
	put32(r, 0x00, 1)
	put32(r, 0x10, 0x40)
	put32(r, 0x40, 0x80)

	r.walkDelayImports(0xffffffc0, false, 0, hints)

	if len(hints) != 0 {
		t.Errorf("delay imports: hints %x after the descriptor RVA wrapped", slices.Sorted(maps.Keys(hints)))
	}
}

func TestRunNoReadableSections(t *testing.T) {
	path := writeTestFile(t, buildPE(true, 0x140000000, []testPESection{{name: ".reloc", data: []byte("reloc string\x00")}}, nil))

	if stdout, _, err := runFile(path, testRunConfig); err == nil || err.Error() != "no readable sections" || stdout != "" {
		t.Errorf("dump: err %v, stdout %q", err, stdout)
	}

	cfg := testRunConfig
	cfg.printSections = true

	stdout, stderr, err := runFile(path, cfg)
	if err != nil || !strings.HasPrefix(stdout, ".reloc\t") || stderr != "" {
		t.Errorf("print sections: err %v, stdout %q, stderr %q", err, stdout, stderr)
	}

	var out, errOut bytes.Buffer

	if code := runMain([]string{"dump", path}, &out, &errOut); code != 1 || errOut.String() != path+": no readable sections\n" {
		t.Errorf("runMain dump: exit %d, stderr %q", code, errOut.String())
	}

	if code := runMain([]string{"dump", "-print-sections", path}, &out, &errOut); code != 0 {
		t.Errorf("runMain dump -print-sections: exit %d", code)
	}
}

func TestPEImports(t *testing.T) {
	const (
		importDir = 1
		delayDir  = 13
	)

	imports := [2]uint32{peRVA(0), 0x28}
	delays := [2]uint32{peRVA(0) + 0x30, 0x40}

	tests := []struct {
		name      string
		wide      bool
		delayVA   bool
		dirs      map[int][2]uint32
		wantHints []uint32
		want      []string
	}{
		{"no directories", false, false, nil, nil, []string{"HiImportedFunc", "DlDelayedFunc"}},
		{"imports", false, false, map[int][2]uint32{importDir: imports}, []uint32{0x10c0}, []string{"ImportedFunc", "DlDelayedFunc"}},
		{"imports wide", true, false, map[int][2]uint32{importDir: imports}, []uint32{0x10c0}, []string{"ImportedFunc", "DlDelayedFunc"}},
		{"delay imports", false, false, map[int][2]uint32{delayDir: delays}, []uint32{0x10e0}, []string{"HiImportedFunc", "DelayedFunc"}},
		{"delay imports wide", true, false, map[int][2]uint32{delayDir: delays}, []uint32{0x10e0}, []string{"HiImportedFunc", "DelayedFunc"}},
		{"both", false, false, map[int][2]uint32{importDir: imports, delayDir: delays}, []uint32{0x10c0, 0x10e0}, []string{"ImportedFunc", "DelayedFunc"}},
		{"both wide", true, false, map[int][2]uint32{importDir: imports, delayDir: delays}, []uint32{0x10c0, 0x10e0}, []string{"ImportedFunc", "DelayedFunc"}},
		{"delay virtual addresses", false, true, map[int][2]uint32{delayDir: delays}, []uint32{0x10e0}, []string{"HiImportedFunc", "DelayedFunc"}},
		{"delay virtual addresses wide", true, true, map[int][2]uint32{importDir: imports, delayDir: delays}, []uint32{0x10c0}, []string{"ImportedFunc", "DlDelayedFunc"}},
	}

	for _, test := range tests {
		base := uint64(0x10000000)
		if test.wide {
			base = 0x140000000
		}

		img := buildPE(test.wide, base, []testPESection{{name: ".rdata", data: peImportData(test.wide, base, peRVA(0), test.delayVA)}}, test.dirs)

		f, err := pe.NewFile(bytes.NewReader(img))
		if err != nil {
			t.Fatal(err)
		}

		var secs []peSection
		for _, s := range f.Sections {
			secs = append(secs, peSection{s.VirtualAddress, s.VirtualSize, s.Size, s.Offset})
		}

		if got := slices.Sorted(maps.Keys(peImportHints(img, f, secs))); !reflect.DeepEqual(got, test.wantHints) {
			t.Errorf("%s: hints = %x, want %x", test.name, got, test.wantHints)
		}

		if _, lines, _ := parseAndDump(t, img, peOptions(false)); !reflect.DeepEqual(lines, test.want) {
			t.Errorf("%s: lines = %q, want %q", test.name, lines, test.want)
		}
	}
}

// appendLea appends to text, code mapped at addr, a lea rax, [rip+disp] that
// refers to target.
func appendLea(text []byte, addr, target uint32) []byte {
	next := addr + uint32(len(text)) + 7
	text = append(text, 0x48, 0x8D, 0x05)

	return binary.LittleEndian.AppendUint32(text, target-next)
}

// gluePE builds an image whose .rdata holds rdata. When lea is set,
// RIP-relative lea instructions in .text refer to the offsets in refs.
// Otherwise, relocated pointers in .data refer to them.
func gluePE(wide, lea bool, rdata string, refs []uint32) []byte {
	le := binary.LittleEndian
	textRVA, rdataRVA, dataRVA := peRVA(0), peRVA(1), peRVA(2)

	base := uint64(0x10000000)
	relocType := uint16(relocHighLow)

	if wide {
		base = 0x140000000
		relocType = relocDir64
	}

	var text, data []byte

	reloc := le.AppendUint32(nil, dataRVA)
	reloc = le.AppendUint32(reloc, 8)

	for _, off := range refs {
		target := rdataRVA + off

		if lea {
			text = appendLea(text, textRVA, target)
			continue
		}

		reloc = le.AppendUint16(reloc, relocType<<12|uint16(len(data)))

		if wide {
			data = le.AppendUint64(data, base+uint64(target))
		} else {
			data = le.AppendUint32(data, uint32(base)+target)
		}
	}

	le.PutUint32(reloc[4:], uint32(len(reloc)))
	text = append(text, 0xC3)

	return buildPE(wide, base, []testPESection{
		{name: ".text", data: text, flags: pe.IMAGE_SCN_MEM_EXECUTE},
		{name: ".rdata", data: []byte(rdata)},
		{name: ".data", data: data},
		{name: ".reloc", data: reloc},
	}, map[int][2]uint32{pe.IMAGE_DIRECTORY_ENTRY_BASERELOC: {peRVA(3), uint32(len(reloc))}})
}

func TestPEGlue(t *testing.T) {
	tests := []struct {
		name  string
		rdata string
		refs  []uint32
		want  []string
	}{
		{"1.0f", "\x00\x00\x80?CDOTA_Modifier_VoidSpirit_AstralStep_Caster\x00", []uint32{4}, []string{"CDOTA_Modifier_VoidSpirit_AstralStep_Caster"}},
		{"2.0f after NUL", "\x00\x00\x80>\x00\x00\x00@CDOTA_Modifier_MonkeyKing_FurArmy_SoldierInPosition\x00", []uint32{8}, []string{"CDOTA_Modifier_MonkeyKing_FurArmy_SoldierInPosition"}},
		{"2048.0f", "\x00\x00\x00EDOTAHidePasswordToggled\x00", []uint32{4}, []string{"DOTAHidePasswordToggled"}},
		{"two bytes", "\x00\x00>@DOTAOpenNewsPopupURL\x00", []uint32{4}, []string{"DOTAOpenNewsPopupURL"}},
		{"carriage return", "\x00\x00\xaa\rCDOTA_Modifier_PushWave\x00", []uint32{4}, []string{"CDOTA_Modifier_PushWave"}},
		{"identifier byte", "\x00\x00\x16CDOTATooltipHeroAttribute\x00", []uint32{4}, []string{"DOTATooltipHeroAttribute"}},
		{"not referenced", "\x00\x00\x80?Unreferenced_Name\x00", nil, []string{"?Unreferenced_Name"}},
		{"start referenced", "\x00Bopomofo\x00", []uint32{1, 4}, []string{"Bopomofo"}},
		{"later offset referenced", "\x00\x00\x80?Name_With_Inner_Ref\x00", []uint32{8}, []string{"?Name_With_Inner_Ref"}},
		{"aligned start", "\x00\x00\x00\x00?Aligned_Name\x00", []uint32{8}, []string{"?Aligned_Name"}},
		{"packed table", "\x00\x00\x00\x00\x00Bopomofo\x00Georgian\x00", nil, []string{"Bopomofo", "Georgian"}},
		{"length prefix", "\x00\x00\x92\x03\x10dota_overworld.h\x00", nil, []string{"dota_overworld.h"}},
	}

	modes := []struct {
		name      string
		wide, lea bool
	}{
		{"lea", true, true},
		{"DIR64", true, false},
		{"HIGHLOW", false, false},
	}

	for _, test := range tests {
		for _, mode := range modes {
			img := gluePE(mode.wide, mode.lea, test.rdata, test.refs)

			if _, lines, _ := parseAndDump(t, img, peOptions(true)); !reflect.DeepEqual(lines, test.want) {
				t.Errorf("%s (%s): lines = %q, want %q", test.name, mode.name, lines, test.want)
			}
		}
	}
}

func TestGlueRewritesKeepImports(t *testing.T) {
	refs := map[uint32]struct{}{0x1004: {}}
	got := glueRewrites([]byte("\x00\x00\x80?Name\x00"), 0x1000, refs, map[int]int{3: 5})

	if want := map[int]int{3: 5}; !reflect.DeepEqual(got, want) {
		t.Errorf("glueRewrites = %v, want %v", got, want)
	}
}

// unwindPE builds an image whose .rdata holds a string, two unwind infos with
// handler data between them, and another string. The exception directory
// lists both unwind infos. A RIP-relative lea in .text refers to rdata offset
// ref when ref is not zero.
func unwindPE(wide bool, ref uint32) []byte {
	le := binary.LittleEndian
	rdataRVA := peRVA(1)

	rdata := make([]byte, 0x60)
	copy(rdata[0x00:], "real string here\x00")
	copy(rdata[0x20:], "\x19\x0b\x02\x00P08@JAB\x00")
	copy(rdata[0x2c:], "xyz!QRS\x00")
	copy(rdata[0x34:], "\x01\x00\x02\x00p08@")
	copy(rdata[0x40:], "another real string\x00")

	var pdata []byte
	for _, off := range []uint32{0x20, 0x34} {
		pdata = le.AppendUint32(pdata, 0)
		pdata = le.AppendUint32(pdata, 0)
		pdata = le.AppendUint32(pdata, rdataRVA+off)
	}

	var text []byte
	if ref != 0 {
		text = appendLea(text, peRVA(0), rdataRVA+ref)
	}

	text = append(text, 0xC3)

	return buildPE(wide, 0x140000000, []testPESection{
		{name: ".text", data: text, flags: pe.IMAGE_SCN_MEM_EXECUTE},
		{name: ".rdata", data: rdata},
		{name: ".pdata", data: pdata},
	}, map[int][2]uint32{pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION: {peRVA(2), uint32(len(pdata))}})
}

func TestPEUnwindData(t *testing.T) {
	tests := []struct {
		name string
		wide bool
		ref  uint32
		want []string
	}{
		{"whole span", true, 0, []string{"real string here", "another real string"}},
		{"reference into the span", true, 0x2c, []string{"real string here", "xyz!QRS", "another real string"}},
		{"not x86-64", false, 0, []string{"real string here", "P08@JAB", "xyz!QRS", "p08@", "another real string"}},
	}

	for _, test := range tests {
		img := unwindPE(test.wide, test.ref)

		if _, lines, _ := parseAndDump(t, img, peOptions(true)); !reflect.DeepEqual(lines, test.want) {
			t.Errorf("%s: lines = %q, want %q", test.name, lines, test.want)
		}
	}
}

func TestUnwindBlanks(t *testing.T) {
	infos := map[uint32]uint32{0x100: 0x110, 0x120: 0x130}

	if got, want := unwindBlanks(infos, nil), []peRange{{0x100, 0x130}}; !reflect.DeepEqual(got, want) {
		t.Errorf("filled span = %x, want %x", got, want)
	}

	// Unwind infos that fill less than half of their span are blanked one by
	// one.
	infos[0x200] = 0x210

	got := unwindBlanks(infos, nil)
	slices.SortFunc(got, func(a, b peRange) int { return int(a.start) - int(b.start) })

	if want := []peRange{{0x100, 0x110}, {0x120, 0x130}, {0x200, 0x210}}; !reflect.DeepEqual(got, want) {
		t.Errorf("sparse span = %x, want %x", got, want)
	}

	if got := unwindBlanks(nil, nil); got != nil {
		t.Errorf("no unwind infos = %x", got)
	}
}

func TestBlankRanges(t *testing.T) {
	data := []byte("abcdefgh")
	got := blankRanges(data, 0x1000, []peRange{{0xff0, 0x1002}, {0x1006, 0x1100}, {0x2000, 0x2001}}, 0)

	if want := []byte("\x00\x00cdef\x00\x00"); !bytes.Equal(got, want) || string(data) != "abcdefgh" {
		t.Errorf("blankRanges = %q, data %q", got, data)
	}

	if got := blankRanges([]byte("ab\x00d"), 0x1000, []peRange{{0x1001, 0x1004}}, 1); !bytes.Equal(got, []byte("a\x01\x00\x01")) {
		t.Errorf("blankRanges with fill = %q", got)
	}

	if got := blankRanges(data, 0x1000, []peRange{{0x2000, 0x2001}}, 0); &got[0] != &data[0] {
		t.Error("data copied without a range inside it")
	}
}

func TestRelocTargetsGarbage(t *testing.T) {
	r := flatImage(0x100)
	refs := map[uint32]struct{}{}

	// A block shorter than its header, a block longer than the directory and
	// a directory past the image add nothing.
	binary.LittleEndian.PutUint32(r.data[0x04:], 4)
	sites := r.relocations(0, 0x10, 0, refs)
	binary.LittleEndian.PutUint32(r.data[0x04:], 0x20)
	sites = append(sites, r.relocations(0, 0x10, 0, refs)...)
	sites = append(sites, r.relocations(0xfffffff8, 0x10, 0, refs)...)

	if len(refs) != 0 || len(sites) != 0 {
		t.Errorf("refs = %x, sites = %x", slices.Sorted(maps.Keys(refs)), sites)
	}
}

func TestPERelocatedPointers(t *testing.T) {
	le := binary.LittleEndian
	dataRVA := peRVA(0)

	// With an image base of 0x40000000, a pointer to RVA 0x363330 is the bytes
	// "036@", which would print as a line. Its NUL bytes are kept, so the
	// constant before the second pointer still lacks a terminator.
	const base = 0x40000000
	const target = 0x363330

	for _, wide := range []bool{true, false} {
		relocType := uint16(relocHighLow)
		pointer := le.AppendUint32(nil, base+target)

		if wide {
			relocType = relocDir64
			pointer = le.AppendUint64(nil, base+target)
		}

		data := append(pointer, "Real_String\x00IYUV"...)
		second := len(data)
		data = append(data, pointer...)
		data = append(data, 0)

		reloc := le.AppendUint32(nil, dataRVA)
		reloc = le.AppendUint32(reloc, 12)
		reloc = le.AppendUint16(reloc, relocType<<12)
		reloc = le.AppendUint16(reloc, relocType<<12|uint16(second))

		img := buildPE(wide, base, []testPESection{
			{name: ".data", data: data},
			{name: ".reloc", data: reloc},
		}, map[int][2]uint32{pe.IMAGE_DIRECTORY_ENTRY_BASERELOC: {peRVA(1), uint32(len(reloc))}})

		if _, lines, _ := parseAndDump(t, img, peOptions(true)); !reflect.DeepEqual(lines, []string{"Real_String"}) {
			t.Errorf("wide %v: lines = %q", wide, lines)
		}
	}
}

func TestDelayImportsSkipUnusableDescriptors(t *testing.T) {
	r := flatImage(0x1000)
	put32 := func(off int, v uint32) { binary.LittleEndian.PutUint32(r.data[off:], v) }

	// Descriptor 1 has no name table. Descriptor 2 holds a virtual address
	// below the image base. Descriptor 3 is usable.
	put32(0x100, 1)
	put32(0x120+16, 0x100)
	put32(0x140, 1)
	put32(0x140+16, 0x800)
	binary.LittleEndian.PutUint32(r.data[0x800:], 0x900)

	hints := map[uint32]struct{}{}
	r.walkDelayImports(0x100, false, 0x400000, hints)

	if got, want := slices.Sorted(maps.Keys(hints)), []uint32{0x900}; !reflect.DeepEqual(got, want) {
		t.Errorf("hints = %x, want %x", got, want)
	}
}
