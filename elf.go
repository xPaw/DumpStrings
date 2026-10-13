package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"strings"
)

// elfExcluded reports whether an ELF section is never read: debug info,
// relocated pointers, merged constants, protobuf descriptors, signatures and
// per-build hashes.
func elfExcluded(name string) bool {
	switch name {
	case "protodesc_cold", ".gnu_debuglink", ".valvesig", ".note.go.buildid":
		return true
	}

	return strings.HasPrefix(name, ".rodata.cst") ||
		strings.HasPrefix(name, ".debug_") ||
		strings.HasPrefix(name, ".data.rel.ro")
}

// elfKind returns how an ELF section is read, or false when it is not.
func elfKind(s *elf.Section, shstrndx int, index int) (SectionKind, bool) {
	if s.Type == elf.SHT_NOBITS || elfExcluded(s.Name) {
		return 0, false
	}

	switch {
	case s.Type == elf.SHT_NOTE:
		return KindNote, true
	case s.Type == elf.SHT_STRTAB:
		return KindStrings, index != shstrndx
	case s.Flags&elf.SHF_STRINGS != 0:
		return KindStrings, true
	}

	switch s.Name {
	case ".rodata", ".data", ".stab":
		return KindData, true
	case ".comment", ".stabstr":
		return KindStrings, true
	}

	return 0, false
}

// elfShstrndx returns e_shstrndx, the index of the section name table.
func elfShstrndx(f *elf.File, data []byte) int {
	off := 0x32
	if f.Class == elf.ELFCLASS64 {
		off = 0x3E
	}

	if len(data) < off+2 {
		return -1
	}

	index := int(f.ByteOrder.Uint16(data[off:]))

	if index == int(elf.SHN_XINDEX) && len(f.Sections) > 0 {
		index = int(f.Sections[0].Link)
	}

	return index
}

// parseELF selects string tables (except the section name table), sections of
// strings, a fixed set of data sections by name, and printable note
// descriptors, in section header order.
func parseELF(data []byte, warn Warner) (*Binary, error) {
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	if len(f.Sections) == 0 {
		warn("no section headers")
	}

	shstrndx := elfShstrndx(f, data)
	b := &Binary{}

	for i, s := range f.Sections {
		h := SectionHeader{
			Name: s.Name,
			Type: fmt.Sprintf("%s %s entsize=%d", s.Type, s.Flags, s.Entsize),
			Addr: s.Addr,
			Size: s.Size,
		}

		kind, ok := elfKind(s, shstrndx, i)
		if !ok || s.FileSize == 0 {
			b.Headers = append(b.Headers, h)
			continue
		}

		if s.Flags&elf.SHF_COMPRESSED != 0 {
			warn("%s: compressed section skipped", s.Name)
			b.Headers = append(b.Headers, h)
			continue
		}

		h.Read = kind.String()
		b.Headers = append(b.Headers, h)

		sdata := fileSlice(data, s.Offset, s.FileSize, s.Name, warn)
		if len(sdata) == 0 {
			continue
		}

		b.Readable++

		if kind != KindNote {
			b.Sections = append(b.Sections, Section{
				Name:    s.Name,
				Kind:    kind,
				Data:    sdata,
				Addr:    s.Addr,
				EntSize: s.Entsize,
			})
			continue
		}

		for _, desc := range elfNotes(sdata, s.Addralign, f.ByteOrder, s.Name, warn) {
			if isPrintableNote(desc) {
				b.Sections = append(b.Sections, Section{
					Name: s.Name,
					Kind: KindNote,
					Data: desc,
					Addr: s.Addr,
				})
			}
		}
	}

	return b, nil
}

// elfNotes returns the descriptor of every note record in a note section.
// Names and descriptors are padded to the section alignment, 4 or 8 bytes.
func elfNotes(data []byte, align uint64, order binary.ByteOrder, name string, warn Warner) [][]byte {
	if align != 8 {
		align = 4
	}

	pad := func(n uint64) uint64 {
		return (n + align - 1) &^ (align - 1)
	}

	var descs [][]byte

	size := uint64(len(data))
	off := uint64(0)

	for off < size {
		if size-off < 12 {
			warn("%s: truncated note header at offset 0x%x", name, off)
			break
		}

		namesz := uint64(order.Uint32(data[off:]))
		descsz := uint64(order.Uint32(data[off+4:]))

		descOff := off + 12 + pad(namesz)
		if descOff > size || descsz > size-descOff {
			warn("%s: note at offset 0x%x runs past the section end", name, off)
			break
		}

		descs = append(descs, data[descOff:descOff+descsz])

		off = descOff + pad(descsz)
	}

	return descs
}

// isPrintableNote reports whether a note descriptor is text: string bytes
// followed only by NUL padding.
func isPrintableNote(desc []byte) bool {
	desc = bytes.TrimRight(desc, "\x00")

	if len(desc) == 0 {
		return false
	}

	for _, c := range desc {
		if !isRunByte[c] {
			return false
		}
	}

	return true
}
