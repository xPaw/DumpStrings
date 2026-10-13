package main

import (
	"debug/elf"
	"encoding/binary"
	"reflect"
	"testing"
)

type testElfSection struct {
	name    string
	typ     elf.SectionType // zero means SHT_PROGBITS
	flags   uint64
	entsize uint64
	data    []byte
}

// buildElf64 assembles a minimal ELF64 file with the given sections after the
// null section; the section name table is appended last.
func buildElf64(order binary.ByteOrder, secs []testElfSection) []byte {
	shstr := []byte{0}
	nameOff := make([]int, len(secs))

	for i, s := range secs {
		nameOff[i] = len(shstr)
		shstr = append(shstr, s.name...)
		shstr = append(shstr, 0)
	}

	shstrName := len(shstr)
	shstr = append(shstr, ".shstrtab\x00"...)

	out := make([]byte, 64)
	offs := make([]int, len(secs))

	for i, s := range secs {
		offs[i] = len(out)
		out = append(out, s.data...)
	}

	shstrOff := len(out)
	out = append(out, shstr...)

	for len(out)%8 != 0 {
		out = append(out, 0)
	}

	shoff := len(out)
	out = append(out, make([]byte, 64*(len(secs)+2))...)

	put := func(idx int, name uint32, typ uint32, flags uint64, off, size, entsize uint64) {
		h := out[shoff+idx*64:]
		order.PutUint32(h[0:], name)
		order.PutUint32(h[4:], typ)
		order.PutUint64(h[8:], flags)
		order.PutUint64(h[24:], off)
		order.PutUint64(h[32:], size)
		order.PutUint64(h[56:], entsize)
	}

	for i, s := range secs {
		typ := s.typ
		if typ == 0 {
			typ = elf.SHT_PROGBITS
		}

		put(i+1, uint32(nameOff[i]), uint32(typ), s.flags, uint64(offs[i]), uint64(len(s.data)), s.entsize)
	}

	put(len(secs)+1, uint32(shstrName), uint32(elf.SHT_STRTAB), 0, uint64(shstrOff), uint64(len(shstr)), 0)

	copy(out, "\x7fELF")
	out[4] = 2
	out[5] = 1

	if order == binary.BigEndian {
		out[5] = 2
	}

	out[6] = 1
	order.PutUint16(out[16:], 3)
	order.PutUint16(out[18:], 62)
	order.PutUint32(out[20:], 1)
	order.PutUint64(out[40:], uint64(shoff))
	order.PutUint16(out[52:], 64)
	order.PutUint16(out[58:], 64)
	order.PutUint16(out[60:], uint16(len(secs)+2))
	order.PutUint16(out[62:], uint16(len(secs)+1))

	return out
}

func wideUnits(order binary.ByteOrder, width int, units ...uint32) []byte {
	var out []byte

	for _, u := range units {
		if width == 2 {
			out, _ = binary.Append(out, order, uint16(u))
		} else {
			out, _ = binary.Append(out, order, u)
		}
	}

	return out
}

func asciiUnits(s string) []uint32 {
	var u []uint32
	for _, c := range []byte(s) {
		u = append(u, uint32(c))
	}

	return u
}

func TestElfWideStrings(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, width := range []int{2, 4} {
			var units []uint32
			units = append(units, asciiUnits("hello")...)
			units = append(units, 0)
			units = append(units, asciiUnits("split")...)
			units = append(units, 0x00e9)
			units = append(units, asciiUnits("here")...)
			units = append(units, 0x20ac, 0x1f600)
			units = append(units, asciiUnits("a\tb c")...)
			units = append(units, 0)
			units = append(units, asciiUnits("tail")...)

			wide := wideUnits(order, width, units...)
			wide = append(wide, 'x')

			f := buildElf64(order, []testElfSection{
				{name: ".rodata.str", flags: 0x32, entsize: uint64(width), data: wide},
				{name: ".rodata.str1.1", flags: 0x32, entsize: 1, data: []byte("bytes\x00")},
			})

			_, got, _ := parseAndDump(t, f, Options{MinLength: 4, MaskProtobufs: true})
			want := []string{"hello", "split", "here", `a\tb c`, "tail", "bytes"}

			if !reflect.DeepEqual(got, want) {
				t.Errorf("order %v width %d: got %q, want %q", order, width, got, want)
			}
		}
	}
}

func TestElfWideSectionHeader(t *testing.T) {
	data := wideUnits(binary.LittleEndian, 2, asciiUnits("abcdef")...)
	f := buildElf64(binary.LittleEndian, []testElfSection{{name: ".rodata.str2.2", flags: 0x32, entsize: 2, data: data}})

	b, err := Parse(f, "auto", func(string, ...any) {})
	if err != nil {
		t.Fatal(err)
	}

	// A narrowed section is not masked and takes no end-of-string rule.
	if len(b.Sections) != 1 || b.Sections[0].Mask || b.Sections[0].EndRule || string(b.Sections[0].Data) != "abcdef" {
		t.Fatalf("unexpected sections: %+v", b.Sections)
	}

	if got := b.Headers[1].Read; got != "strings/u16" {
		t.Errorf("read = %q", got)
	}
}

func TestElfExcluded(t *testing.T) {
	tests := map[string]bool{
		"protodesc_cold":     true,
		".gnu_debuglink":     true,
		".valvesig":          true,
		".note.go.buildid":   true,
		".rodata.cst16":      true,
		".rodata.cst":        true,
		".debug_str":         true,
		".data.rel.ro":       true,
		".data.rel.ro.local": true,
		".rodata":            false,
		".rodata.str1.1":     false,
		".data":              false,
		".data.rel":          false,
		".debug":             false,
		".note.gnu.build-id": false,
		"":                   false,
	}

	for name, want := range tests {
		if got := elfExcluded(name); got != want {
			t.Errorf("elfExcluded(%q) = %v, want %v", name, got, want)
		}
	}
}
