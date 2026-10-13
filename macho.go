package main

import (
	"bytes"
	"debug/macho"
	"encoding/binary"
	"fmt"
)

// machoSections maps the read sections, as "segment,section", to their kind.
var machoSections = map[string]SectionKind{
	"__TEXT,__cstring":        KindStrings,
	"__TEXT,__const":          KindData,
	"__TEXT,__objc_classname": KindStrings,
	"__TEXT,__objc_methname":  KindStrings,
	"__TEXT,__objc_methtype":  KindStrings,
	"__DATA,__data":           KindData,
}

// machoZerofill reports whether a section type has no bytes in the file.
func machoZerofill(flags uint32) bool {
	switch flags & 0xff {
	case 0x1, 0xc, 0x12: // S_ZEROFILL, S_GB_ZEROFILL, S_THREAD_LOCAL_ZEROFILL
		return true
	}

	return false
}

// machoCpuName returns the conventional name of a CPU type.
func machoCpuName(cpu macho.Cpu) string {
	switch cpu {
	case macho.Cpu386:
		return "i386"
	case macho.CpuAmd64:
		return "x86_64"
	case macho.CpuArm:
		return "arm"
	case macho.CpuArm64:
		return "arm64"
	case macho.CpuPpc:
		return "ppc"
	case macho.CpuPpc64:
		return "ppc64"
	}

	return fmt.Sprintf("cpu%d", uint32(cpu))
}

// machoPathCommands are the load commands whose lc_str, at bytes 8..12 of the
// command, names a dylib, an rpath or the dynamic linker.
var machoPathCommands = map[macho.LoadCmd]bool{
	macho.LoadCmdDylib:    true, // LC_LOAD_DYLIB
	0xd:                   true, // LC_ID_DYLIB
	0xe:                   true, // LC_LOAD_DYLINKER
	macho.LoadCmdDylinker: true, // LC_ID_DYLINKER
	0x20:                  true, // LC_LAZY_LOAD_DYLIB
	0x80000018:            true, // LC_LOAD_WEAK_DYLIB
	macho.LoadCmdRpath:    true, // LC_RPATH
	0x8000001f:            true, // LC_REEXPORT_DYLIB
	0x80000023:            true, // LC_LOAD_UPWARD_DYLIB
}

// addMachOLoadStrings adds the dylib, rpath and dynamic linker paths of one
// image as a NUL-separated pseudo-section.
func addMachOLoadStrings(b *Binary, f *macho.File, prefix string) {
	var data []byte
	count := 0

	for _, l := range f.Loads {
		raw := l.Raw()
		if len(raw) < 12 || !machoPathCommands[macho.LoadCmd(f.ByteOrder.Uint32(raw))] {
			continue
		}

		size := min(uint64(f.ByteOrder.Uint32(raw[4:])), uint64(len(raw)))
		off := uint64(f.ByteOrder.Uint32(raw[8:]))
		if off < 12 || off >= size {
			continue
		}

		str := raw[off:size]
		if i := bytes.IndexByte(str, 0); i >= 0 {
			str = str[:i]
		}

		data = append(data, str...)
		data = append(data, 0)
		count++
	}

	if count == 0 {
		return
	}

	b.add(SectionHeader{
		Name: prefix + "load commands",
		Type: fmt.Sprintf("paths=%d", count),
		Size: uint64(len(data)),
		Read: KindStrings.String(),
	}, Section{Data: data, Mask: true}, true)
}

// parseMachO selects a fixed set of sections and the symbol string table of a
// thin file, or of every arch of a fat file in turn.
func parseMachO(data []byte, warn Warner) (*Binary, error) {
	b := &Binary{}

	if !isFatMachO(data) {
		f, err := macho.NewFile(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}

		addMachO(b, f, data, "", warn)

		return b, nil
	}

	ff, err := macho.NewFatFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	for _, arch := range ff.Arches {
		prefix := machoCpuName(arch.Cpu) + ":"
		archData := fileSlice(data, uint64(arch.Offset), uint64(arch.Size), prefix+"arch", warn)

		addMachO(b, arch.File, archData, prefix, warn)
	}

	return b, nil
}

// addMachO adds the sections of one Mach-O image. Offsets in f are relative
// to data, the bytes of that image.
func addMachO(b *Binary, f *macho.File, data []byte, prefix string, warn Warner) {
	for _, s := range f.Sections {
		name := s.Seg + "," + s.Name
		h := SectionHeader{
			Name: prefix + name,
			Type: fmt.Sprintf("type=0x%x flags=0x%08x", s.Flags&0xff, s.Flags),
			Addr: s.Addr,
			Size: s.Size,
		}

		kind, ok := machoSections[name]
		if !ok || machoZerofill(s.Flags) || s.Size == 0 {
			b.Headers = append(b.Headers, h)
			continue
		}

		h.Read = kind.String()

		sdata := fileSlice(data, uint64(s.Offset), s.Size, h.Name, warn)
		b.add(h, Section{Data: sdata, Mask: true, EndRule: kind == KindData}, len(sdata) > 0)
	}

	addMachOLoadStrings(b, f, prefix)

	// debug/macho leaves Symtab.SymtabCmd empty, so the command is decoded
	// from its raw bytes.
	var cmd macho.SymtabCmd
	if f.Symtab == nil || binary.Read(bytes.NewReader(f.Symtab.LoadBytes), f.ByteOrder, &cmd) != nil || cmd.Strsize == 0 {
		return
	}

	h := SectionHeader{
		Name: prefix + "LC_SYMTAB",
		Type: fmt.Sprintf("stroff=0x%x symbols=%d", cmd.Stroff, cmd.Nsyms),
		Size: uint64(cmd.Strsize),
		Read: KindStrings.String(),
	}

	sdata := fileSlice(data, uint64(cmd.Stroff), uint64(cmd.Strsize), h.Name, warn)
	b.add(h, Section{Data: sdata, Mask: true}, len(sdata) > 0)
}
