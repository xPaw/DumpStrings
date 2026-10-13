package main

import (
	"bytes"
	"debug/pe"
	"fmt"
)

// parsePE selects every .data and .rdata section, and every .text section as
// the fallback.
func parsePE(data []byte, warn Warner) (*Binary, error) {
	f, err := pe.NewFile(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	b := &Binary{}

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
			kind = KindFallback
		default:
			b.Headers = append(b.Headers, h)
			continue
		}

		if s.Size == 0 {
			b.Headers = append(b.Headers, h)
			continue
		}

		h.Read = kind.String()
		b.Headers = append(b.Headers, h)

		// Bytes past VirtualSize are file alignment padding.
		size := s.Size
		if s.VirtualSize > 0 && s.VirtualSize < size {
			size = s.VirtualSize
		}

		sect := Section{
			Name: s.Name,
			Kind: kind,
			Data: fileSlice(data, uint64(s.Offset), uint64(size), s.Name, warn),
			Addr: uint64(s.VirtualAddress),
		}

		if kind == KindData && uint64(len(sect.Data)) < uint64(size) {
			b.Truncated = true
		}

		if len(sect.Data) == 0 {
			continue
		}

		b.Readable++

		if kind == KindFallback {
			b.Fallback = append(b.Fallback, sect)
		} else {
			b.Sections = append(b.Sections, sect)
		}
	}

	return b, nil
}
