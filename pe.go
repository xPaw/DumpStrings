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

// Base relocation types that patch an absolute address.
const (
	relocHighLow = 3
	relocDir64   = 10
)

// relocTargets adds the RVA that each HIGHLOW and DIR64 base relocation in the
// size bytes of relocation blocks at rva points to.
func (r *peReader) relocTargets(rva, size uint32, base uint64, out map[uint32]struct{}) {
	for size >= 8 {
		h := r.bytes(rva, 8)
		if h == nil {
			return
		}

		page := binary.LittleEndian.Uint32(h[0:])
		n := binary.LittleEndian.Uint32(h[4:])
		if n < 8 || n > size {
			return
		}

		entries := r.bytes(rva+8, int(n-8))
		if entries == nil {
			return
		}

		for i := 0; i+2 <= len(entries); i += 2 {
			e := binary.LittleEndian.Uint16(entries[i:])
			at := page + uint32(e&0xFFF)

			var width int

			switch e >> 12 {
			case relocHighLow:
				width = 4
			case relocDir64:
				width = 8
			default:
				continue
			}

			b := r.bytes(at, width)
			if b == nil {
				continue
			}

			var v uint64
			if width == 8 {
				v = binary.LittleEndian.Uint64(b)
			} else {
				v = uint64(binary.LittleEndian.Uint32(b))
			}

			if v < base || v-base > 0xFFFFFFFF {
				continue
			}

			out[uint32(v-base)] = struct{}{}
		}

		if rva+n < rva {
			return
		}

		rva += n
		size -= n
	}
}

// ripTargets adds the target of every RIP-relative lea with a 64-bit operand
// in code, x86-64 code mapped at addr.
func ripTargets(code []byte, addr uint32, out map[uint32]struct{}) {
	for i := 0; i+7 <= len(code); i++ {
		// Skip to the next lea opcode, which follows the REX prefix.
		at := bytes.IndexByte(code[i+1:], 0x8D)
		if at < 0 {
			return
		}

		i += at
		if i+7 > len(code) {
			return
		}

		// REX.W with any R and B bits, and a ModRM byte with mod 00 and r/m 101.
		if code[i]&0xFA != 0x48 || code[i+2]&0xC7 != 0x05 {
			continue
		}

		disp := int32(binary.LittleEndian.Uint32(code[i+3:]))
		next := addr + uint32(i+7)
		out[next+uint32(disp)] = struct{}{}
	}
}

// peReferences returns the RVAs the image refers to: the targets of its base
// relocations and, in x86-64 images, of the RIP-relative lea instructions in
// its executable sections.
func peReferences(data []byte, f *pe.File, secs []peSection) map[uint32]struct{} {
	refs := map[uint32]struct{}{}
	dirs, base, _ := peDirectories(f)

	if len(dirs) > pe.IMAGE_DIRECTORY_ENTRY_BASERELOC {
		r := &peReader{data: data, secs: secs}
		d := dirs[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
		r.relocTargets(d.VirtualAddress, d.Size, base, refs)
	}

	if f.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		return refs
	}

	for _, s := range f.Sections {
		if s.Characteristics&pe.IMAGE_SCN_MEM_EXECUTE == 0 || s.Offset == 0 {
			continue
		}

		start := uint64(s.Offset)
		end := min(start+uint64(peRawSize(s)), uint64(len(data)))
		if start >= end {
			continue
		}

		ripTargets(data[start:end], s.VirtualAddress, refs)
	}

	return refs
}

// Unwind info flags of x86-64 images.
const (
	unwindFlagHandler   = 0x3
	unwindFlagChainInfo = 0x4
)

// peRange is a range of RVAs.
type peRange struct {
	start, end uint32
}

// unwindInfos maps the RVA of each unwind info that the size bytes of
// RUNTIME_FUNCTION entries at rva lead to, to the end of its fixed part: the
// header, the unwind codes, and the handler RVA or chained function entry
// that follows them.
func (r *peReader) unwindInfos(rva, size uint32) map[uint32]uint32 {
	table := r.bytes(rva, int(size/12*12))
	infos := map[uint32]uint32{}

	for i := 0; i+12 <= len(table); i += 12 {
		at := binary.LittleEndian.Uint32(table[i+8:])

		// The low bit marks an entry that points to another RUNTIME_FUNCTION.
		if at&1 != 0 {
			continue
		}

		// Many functions share an unwind info.
		if _, ok := infos[at]; ok {
			continue
		}

		h := r.bytes(at, 4)
		if h == nil {
			continue
		}

		version := h[0] & 7
		if version != 1 && version != 2 {
			continue
		}

		// The unwind codes are 2 bytes each, padded to an even count.
		codes := uint32(h[2])
		if codes%2 != 0 {
			codes++
		}

		flags := h[0] >> 3
		n := 4 + 2*codes

		if flags&unwindFlagChainInfo != 0 {
			n += 12
		} else if flags&unwindFlagHandler != 0 {
			n += 4
		}

		if at+n < at || r.bytes(at, int(n)) == nil {
			continue
		}

		infos[at] = at + n
	}

	return infos
}

// unwindBlanks returns the RVA ranges of unwind data to blank: the span from
// the first unwind info to the end of the last, which also holds the handler
// data between them, when unwind infos fill at least half of it and nothing
// refers into it; otherwise each unwind info.
func unwindBlanks(infos map[uint32]uint32, refs map[uint32]struct{}) []peRange {
	if len(infos) == 0 {
		return nil
	}

	each := make([]peRange, 0, len(infos))
	span := peRange{start: 0xFFFFFFFF}
	filled := uint64(0)

	for start, end := range infos {
		each = append(each, peRange{start, end})
		span.start = min(span.start, start)
		span.end = max(span.end, end)
		filled += uint64(end - start)
	}

	if filled*2 < uint64(span.end-span.start) {
		return each
	}

	for ref := range refs {
		if ref >= span.start && ref < span.end {
			return each
		}
	}

	return []peRange{span}
}

// peUnwindBlanks returns the RVA ranges of the unwind data of an x86-64 image,
// which the exception directory lists.
func peUnwindBlanks(data []byte, f *pe.File, secs []peSection, refs map[uint32]struct{}) []peRange {
	dirs, _, _ := peDirectories(f)
	if f.Machine != pe.IMAGE_FILE_MACHINE_AMD64 || len(dirs) <= pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION {
		return nil
	}

	r := &peReader{data: data, secs: secs}
	d := dirs[pe.IMAGE_DIRECTORY_ENTRY_EXCEPTION]

	return unwindBlanks(r.unwindInfos(d.VirtualAddress, d.Size), refs)
}

// blankRanges returns data, a section mapped at addr, with the parts of the
// ranges inside it zero-filled. data is not modified: it is returned as is
// when no range falls inside it, and copied otherwise.
func blankRanges(data []byte, addr uint32, ranges []peRange) []byte {
	var blanked []byte

	end := uint64(addr) + uint64(len(data))

	for _, rg := range ranges {
		start := max(uint64(rg.start), uint64(addr))
		stop := min(uint64(rg.end), end)

		if start >= stop {
			continue
		}

		if blanked == nil {
			blanked = bytes.Clone(data)
		}

		clear(blanked[start-uint64(addr) : stop-uint64(addr)])
	}

	if blanked == nil {
		return data
	}

	return blanked
}

// glueRewrites adds to m, for a section mapped at addr, the runs that start
// off 4-byte alignment where nothing refers to the start but something refers
// to the next 4-byte aligned offset inside the run. Compilers align string
// literals, so the bytes before that offset are the printable tail of the
// constant stored before the string. Offsets already in m are left alone.
func glueRewrites(data []byte, addr uint32, refs map[uint32]struct{}, m map[int]int) map[int]int {
	for off, run := range splitRuns(data) {
		start := addr + uint32(off)
		aligned := (start + 3) &^ 3

		if aligned <= start || aligned-start >= uint32(len(run)) {
			continue
		}

		if _, ok := m[off]; ok {
			continue
		}

		if _, ok := refs[start]; ok {
			continue
		}

		if _, ok := refs[aligned]; !ok {
			continue
		}

		if m == nil {
			m = map[int]int{}
		}

		m[off] = off + int(aligned-start)
	}

	return m
}

// peRawSize returns the size of the raw data of a section without the file
// alignment padding past VirtualSize.
func peRawSize(s *pe.Section) uint32 {
	if s.VirtualSize > 0 && s.VirtualSize < s.Size {
		return s.VirtualSize
	}

	return s.Size
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
	refs := peReferences(data, f, secs)
	unwind := peUnwindBlanks(data, f, secs, refs)
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

		size := peRawSize(s)
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

		sdata = blankRanges(sdata, s.VirtualAddress, unwind)
		rewrite := importRewrites(hints, uint64(s.VirtualAddress), len(sdata))
		rewrite = glueRewrites(sdata, s.VirtualAddress, refs, rewrite)

		b.add(h, Section{
			Data:    sdata,
			Mask:    true,
			EndRule: true,
			Rewrite: rewrite,
		}, ok)
	}

	if truncated {
		b.Fallback = nil
		b.Readable = len(b.Sections) > 0
	}

	return b, nil
}
