package main

import (
	"debug/pe"
	"encoding/binary"
	"reflect"
	"sort"
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

// flatImage lays one section out so that RVA r is file offset r.
func flatImage(n int) *peReader {
	return &peReader{
		data: make([]byte, n),
		secs: []peSection{{rva: 0, vsize: uint32(n), rawSize: uint32(n), rawOff: 0}},
	}
}

func sortedKeys(m map[uint32]struct{}) []uint32 {
	var keys []uint32

	for k := range m {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	return keys
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

		// Import descriptor 1 uses its original thunks, descriptor 2 has none and
		// falls back to the first thunks.
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
		if got := sortedKeys(hints); !reflect.DeepEqual(got, want) {
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

	d := Dumper{opts: Options{MinLength: 4, SymLength: 10}, sink: func(l string) { got = append(got, l) }}
	d.DumpSection(Section{
		Data:    []byte("\x00&?Name\x00\x01$Other\x00zz\x00"),
		Rewrite: map[int]int{1: 3, 9: 10, 18: 20},
	})

	want := []string{"Name", "Other"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("lines = %q, want %q", got, want)
	}
}
