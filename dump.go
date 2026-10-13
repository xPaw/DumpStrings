package main

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"encoding/binary"
	"fmt"
	"io"
	"iter"
	"slices"
)

// SectionKind tells how the bytes of a section were laid out by the toolchain,
// which decides how a parser reads it.
type SectionKind int

const (
	// KindData is a data section that mixes strings with other data.
	KindData SectionKind = iota
	// KindStrings is a string table or a section of NUL-terminated strings.
	KindStrings
	// KindNote is an ELF note section, read for its printable descriptors.
	KindNote
	// KindFallback is code read only when nothing else produced a line.
	KindFallback
)

func (k SectionKind) String() string {
	switch k {
	case KindData:
		return "data"
	case KindStrings:
		return "strings"
	case KindNote:
		return "note"
	case KindFallback:
		return "fallback"
	}

	return fmt.Sprintf("kind%d", int(k))
}

// Section is a byte range of the binary selected for string extraction, with
// the rules that apply to it.
type Section struct {
	Data []byte

	// Mask lets -mask-protobufs blank serialized protobuf descriptors.
	Mask bool

	// EndRule applies the end-of-string rule, when it is on, to the runs.
	EndRule bool

	// Rewrite maps the offset of a run start to the offset the run is emitted
	// from instead; the end of the run is unchanged.
	Rewrite map[int]int
}

// SectionHeader describes one section of the binary for -print-sections.
type SectionHeader struct {
	Name string
	Type string
	Addr uint64
	Size uint64
	Read string
}

// Binary is the parsed view of a file: every section header, the sections to
// read, and the sections read only when the others produce no lines.
type Binary struct {
	Headers  []SectionHeader
	Sections []Section
	Fallback []Section

	// Readable is set when a selected section had bytes in the file, even
	// if none of them are read, as with a note section whose descriptors
	// are all binary.
	Readable bool
}

// add records the header of a section and, when ok, the section read from
// it, which makes the binary readable.
func (b *Binary) add(h SectionHeader, s Section, ok bool) {
	b.Headers = append(b.Headers, h)

	if ok {
		b.Sections = append(b.Sections, s)
		b.Readable = true
	}
}

// Options controls how strings are extracted and filtered.
type Options struct {
	MinLength int
	SymLength int
	Demangle  bool

	// MaskProtobufs blanks serialized protobuf descriptors before extraction.
	MaskProtobufs bool

	// Terminated applies the end-of-string rule to the sections that take it.
	Terminated bool
}

// Sink receives each output line, without a trailing newline.
type Sink func(line string)

// Warner reports a recoverable problem with the input.
type Warner func(format string, args ...any)

// isRunByte marks the bytes that make up a string: tab, line feed, vertical
// tab, form feed, carriage return and printable ASCII.
var isRunByte = func() (t [256]bool) {
	for c := 0x09; c <= 0x0D; c++ {
		t[c] = true
	}

	for c := 0x20; c <= 0x7E; c++ {
		t[c] = true
	}

	return t
}()

// splitRuns yields the offset and bytes of every maximal run of string bytes
// in buf.
func splitRuns(buf []byte) iter.Seq2[int, []byte] {
	return func(yield func(int, []byte) bool) {
		start := -1

		for i, c := range buf {
			if isRunByte[c] {
				if start < 0 {
					start = i
				}
			} else if start >= 0 {
				if !yield(start, buf[start:i]) {
					return
				}

				start = -1
			}
		}

		if start >= 0 {
			yield(start, buf[start:])
		}
	}
}

// Dumper extracts strings from sections and sends them to a sink.
type Dumper struct {
	opts Options
	sink Sink
}

// keeps reports whether a run passes the minimum length and the symbol filter.
func (d *Dumper) keeps(run []byte) bool {
	if len(run) < d.opts.MinLength {
		return false
	}

	return len(run) > d.opts.SymLength || !UtilIsMajoritySymbols(string(run))
}

// hasLine reports whether the unmodified runs of s produce at least one line.
func (d *Dumper) hasLine(s Section) bool {
	for _, run := range splitRuns(s.Data) {
		if d.keeps(run) {
			return true
		}
	}

	return false
}

// DumpSection emits the strings of one section.
func (d *Dumper) DumpSection(s Section) {
	ends := newEndRule(s.Data)
	ruled := d.opts.Terminated && s.EndRule

	for off, run := range splitRuns(s.Data) {
		// A rewrite only shortens a run, and the end-of-string rule does not
		// depend on the runs it skips.
		if len(run) < d.opts.MinLength {
			continue
		}

		if to, ok := s.Rewrite[off]; ok && to < off+len(run) {
			run = run[to-off:]
			off = to
		}

		if ruled && !ends.keeps(off, off+len(run)) {
			continue
		}

		if !d.keeps(run) {
			continue
		}

		str := UtilEscape(string(run))

		if d.opts.Demangle {
			str = UtilDemangle(str)
		}

		d.sink(str)
	}
}

// Dump emits the strings of every section, then of the fallback sections when
// the unmasked runs of the others produce no lines.
func (d *Dumper) Dump(b *Binary) {
	needFallback := len(b.Fallback) > 0 && !slices.ContainsFunc(b.Sections, d.hasLine)

	for _, s := range b.Sections {
		if d.opts.MaskProtobufs && s.Mask {
			s.Data = MaskProtobufs(s.Data)
		}

		d.DumpSection(s)
	}

	if needFallback {
		for _, s := range b.Fallback {
			d.DumpSection(s)
		}
	}
}

// PrintSections writes one line per section header.
func PrintSections(w io.Writer, b *Binary) {
	for _, h := range b.Headers {
		read := h.Read
		if read == "" {
			read = "-"
		}

		fmt.Fprintf(w, "%s\t%s\taddr=0x%x\tsize=0x%x\tread=%s\n", h.Name, h.Type, h.Addr, h.Size, read)
	}
}

// Parse detects the format of data when format is "auto", and parses it.
func Parse(data []byte, format string, warn Warner) (*Binary, error) {
	if format == "auto" {
		var err error
		if format, err = DetectFormat(data); err != nil {
			return nil, err
		}
	}

	var b *Binary
	var err error

	switch format {
	case "pe":
		b, err = parsePE(data, warn)
	case "elf":
		b, err = parseELF(data, warn)
	case "macho":
		b, err = parseMachO(data, warn)
	default:
		return nil, fmt.Errorf("unsupported file type: %s", format)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse as %s: %w", format, err)
	}

	return b, nil
}

// DetectFormat identifies the binary format by its magic bytes.
func DetectFormat(data []byte) (string, error) {
	if len(data) < 4 {
		return "", fmt.Errorf("file too small to detect its format (%d bytes)", len(data))
	}

	be, le := binary.BigEndian.Uint32(data), binary.LittleEndian.Uint32(data)

	switch {
	case bytes.HasPrefix(data, []byte(elf.ELFMAG)):
		return "elf", nil
	case bytes.HasPrefix(data, []byte("MZ")):
		return "pe", nil
	case isFatMachO(data):
		return "macho", nil
	case be == macho.Magic32, be == macho.Magic64, le == macho.Magic32, le == macho.Magic64:
		return "macho", nil
	}

	return "", fmt.Errorf("unsupported file type, magic bytes: % x", data[:4])
}

// isFatMachO reports whether data starts with a fat Mach-O header. Java class
// files share the magic but hold their major version (45 or more) where the
// fat header holds the arch count.
func isFatMachO(data []byte) bool {
	if len(data) < 8 || binary.BigEndian.Uint32(data) != macho.MagicFat {
		return false
	}

	n := binary.BigEndian.Uint32(data[4:8])

	return n >= 1 && n <= 16
}

// fileSlice returns data[off:off+size], clamped to the bytes present, and
// warns when the range runs past the end of data.
func fileSlice(data []byte, off, size uint64, name string, warn Warner) []byte {
	end := off + size
	n := uint64(len(data))

	if end < off || end > n {
		if off >= n {
			warn("%s: section at offset 0x%x is past the end of the file (0x%x bytes), skipped", name, off, n)
			return nil
		}

		warn("%s: section truncated to 0x%x of 0x%x bytes", name, n-off, size)
		end = n
	}

	return data[off:end]
}
