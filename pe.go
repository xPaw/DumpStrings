package main

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"fmt"
)

// Limits that keep a corrupt import table from running away.
const (
	maxImportDescriptors = 1 << 14
	maxImportThunks      = 1 << 20
)

// peSection is the part of a section header needed to map RVAs to file
// offsets.
type peSection struct {
	rva, vsize, rawSize, rawOff uint32
}

// rvaToOffset maps an RVA to a file offset through the section whose virtual
// range contains it, if the offset falls inside the section's raw data and
// the file.
func rvaToOffset(secs []peSection, size int, rva uint32) (uint32, bool) {
	for _, s := range secs {
		span := max(s.vsize, s.rawSize)
		if rva < s.rva || rva-s.rva >= span {
			continue
		}

		d := rva - s.rva
		if d >= s.rawSize {
			return 0, false
		}

		off := uint64(s.rawOff) + uint64(d)
		if off >= uint64(size) {
			return 0, false
		}

		return uint32(off), true
	}

	return 0, false
}

// peReader reads little-endian fields at RVAs of a PE image.
type peReader struct {
	data []byte
	secs []peSection
}

func (r *peReader) bytes(rva uint32, n int) []byte {
	off, ok := rvaToOffset(r.secs, len(r.data), rva)
	if !ok || uint64(off)+uint64(n) > uint64(len(r.data)) {
		return nil
	}

	return r.data[off : int(off)+n]
}

// importNames collects the RVAs of the hint/name entries of the by-name
// imports listed in a name table. Thunks are 8 bytes when wide, 4 otherwise;
// ordinals are skipped. For delay imports with VA addressing, thunk values
// are virtual addresses and base is subtracted.
func (r *peReader) importNames(table uint32, wide bool, base uint64, va bool, out map[uint32]struct{}) {
	size := uint32(4)
	if wide {
		size = 8
	}

	for i := uint32(0); i < maxImportThunks; i++ {
		rva := table + i*size
		if rva < table {
			return
		}

		b := r.bytes(rva, int(size))
		if b == nil {
			return
		}

		var v uint64
		if wide {
			v = binary.LittleEndian.Uint64(b)
		} else {
			v = uint64(binary.LittleEndian.Uint32(b))
		}

		if v == 0 {
			return
		}

		if v>>(size*8-1) != 0 {
			continue
		}

		if va {
			if v < base {
				continue
			}

			v -= base
		}

		if v > 0xFFFFFFFF {
			continue
		}

		out[uint32(v)] = struct{}{}
	}
}

// peDirectories returns the data directories and image base of the optional
// header, and whether the image is PE32+. Without an optional header there are
// no directories.
func peDirectories(f *pe.File) (dirs []pe.DataDirectory, base uint64, wide bool) {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return oh.DataDirectory[:], uint64(oh.ImageBase), false
	case *pe.OptionalHeader64:
		return oh.DataDirectory[:], oh.ImageBase, true
	}

	return nil, 0, false
}

// peIsCLR reports whether the image has a CLR runtime header, as a .NET
// assembly does.
func peIsCLR(f *pe.File) bool {
	const clr = pe.IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR

	dirs, _, _ := peDirectories(f)

	return len(dirs) > clr && (dirs[clr].VirtualAddress != 0 || dirs[clr].Size != 0)
}

// peImportHints returns the RVAs of the hint/name entries of every by-name
// import and delay import of the image.
func peImportHints(data []byte, f *pe.File, secs []peSection) map[uint32]struct{} {
	dirs, base, wide := peDirectories(f)
	if dirs == nil {
		return nil
	}

	r := &peReader{data: data, secs: secs}
	hints := map[uint32]struct{}{}

	if len(dirs) > pe.IMAGE_DIRECTORY_ENTRY_IMPORT {
		r.walkImports(dirs[pe.IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, wide, base, hints)
	}

	if len(dirs) > pe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT {
		r.walkDelayImports(dirs[pe.IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress, wide, base, hints)
	}

	return hints
}

// walkImports reads the import descriptors at rva, which end at an all-zero
// descriptor.
func (r *peReader) walkImports(rva uint32, wide bool, base uint64, out map[uint32]struct{}) {
	if rva == 0 {
		return
	}

	for i := uint32(0); i < maxImportDescriptors; i++ {
		at := rva + i*20
		if at < rva {
			return
		}

		d := r.bytes(at, 20)
		if d == nil || allZero(d) {
			return
		}

		table := binary.LittleEndian.Uint32(d[0:])
		if table == 0 {
			table = binary.LittleEndian.Uint32(d[16:])
		}

		if table != 0 {
			r.importNames(table, wide, base, false, out)
		}
	}
}

// walkDelayImports reads the delay-import descriptors at rva, which end at an
// all-zero descriptor.
func (r *peReader) walkDelayImports(rva uint32, wide bool, base uint64, out map[uint32]struct{}) {
	if rva == 0 {
		return
	}

	for i := uint32(0); i < maxImportDescriptors; i++ {
		at := rva + i*32
		if at < rva {
			return
		}

		d := r.bytes(at, 32)
		if d == nil || allZero(d) {
			return
		}

		// Without the RVA attribute, the address fields hold virtual
		// addresses.
		va := binary.LittleEndian.Uint32(d[0:])&1 == 0
		table := uint64(binary.LittleEndian.Uint32(d[16:]))
		if table == 0 {
			table = uint64(binary.LittleEndian.Uint32(d[12:]))
		}

		if table == 0 {
			continue
		}

		if va {
			if table < base {
				continue
			}

			table -= base
		}

		r.importNames(uint32(table), wide, base, va, out)
	}
}

func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}

	return true
}

// importRewrites maps, for a section, the offsets where a hint/name entry
// starts (the hint, its second byte, or the name) to the offset of the name.
func importRewrites(hints map[uint32]struct{}, addr uint64, n int) map[int]int {
	var m map[int]int

	for h := range hints {
		if uint64(h) < addr {
			continue
		}

		off := uint64(h) - addr
		if off+2 >= uint64(n) {
			continue
		}

		if m == nil {
			m = map[int]int{}
		}

		m[int(off)] = int(off) + 2
		m[int(off)+1] = int(off) + 2
	}

	return m
}

// peSizeOfHeaders returns SizeOfHeaders from the optional header, or 0 when
// there is none.
func peSizeOfHeaders(f *pe.File) uint32 {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return oh.SizeOfHeaders
	case *pe.OptionalHeader64:
		return oh.SizeOfHeaders
	}

	return 0
}

// parsePE selects every .data and .rdata section, and every .text section as
// the fallback. A native image without an .rdata section keeps its read-only
// data in .text, which is then read as a data section instead. A section whose
// raw data starts at offset 0 or inside the headers has no data of its own and
// is skipped. The fallback is dropped when a data section runs past the end of
// the file, since its missing bytes may hold the lines, and the binary is then
// readable only through the data bytes that are present.
func parsePE(data []byte, warn Warner) (*Binary, error) {
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	b := &Binary{}
	headers := peSizeOfHeaders(f)
	textKind := KindData

	secs := make([]peSection, 0, len(f.Sections))
	for _, s := range f.Sections {
		secs = append(secs, peSection{s.VirtualAddress, s.VirtualSize, s.Size, s.Offset})

		if s.Name == ".rdata" {
			textKind = KindFallback
		}
	}

	if peIsCLR(f) {
		textKind = KindFallback
	}

	hints := peImportHints(data, f, secs)
	truncated := false

	for _, s := range f.Sections {
		h := SectionHeader{
			Name: s.Name,
			Type: fmt.Sprintf("flags=0x%08x vsize=0x%x", s.Characteristics, s.VirtualSize),
			Addr: uint64(s.VirtualAddress),
			Size: uint64(s.Size),
		}

		var kind SectionKind

		switch s.Name {
		case ".data", ".rdata":
			kind = KindData
		case ".text":
			kind = textKind
		default:
			b.Headers = append(b.Headers, h)
			continue
		}

		if s.Size == 0 {
			b.Headers = append(b.Headers, h)
			continue
		}

		h.Read = kind.String()

		if s.Offset == 0 || s.Offset < headers {
			warn("%s: section at offset 0x%x lies inside the headers, skipped", s.Name, s.Offset)
			b.Headers = append(b.Headers, h)
			continue
		}

		// Bytes past VirtualSize are file alignment padding.
		size := s.Size
		if s.VirtualSize > 0 && s.VirtualSize < size {
			size = s.VirtualSize
		}

		sdata := fileSlice(data, uint64(s.Offset), uint64(size), s.Name, warn)
		ok := len(sdata) > 0

		if kind == KindFallback {
			b.Headers = append(b.Headers, h)

			if ok {
				b.Fallback = append(b.Fallback, Section{Data: sdata})
				b.Readable = true
			}

			continue
		}

		if uint64(len(sdata)) < uint64(size) {
			truncated = true
		}

		b.add(h, Section{
			Data:    sdata,
			Mask:    true,
			EndRule: true,
			Rewrite: importRewrites(hints, uint64(s.VirtualAddress), len(sdata)),
		}, ok)
	}

	if truncated {
		b.Fallback = nil
		b.Readable = len(b.Sections) > 0
	}

	return b, nil
}
