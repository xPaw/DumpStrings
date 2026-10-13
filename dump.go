package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"iter"
)

// SectionKind tells how the bytes of a section were laid out by the toolchain.
type SectionKind int

const (
	// KindData is a data section that mixes strings with other data.
	KindData SectionKind = iota
	// KindStrings is a string table or a section of NUL-terminated strings.
	KindStrings
	// KindNote is a printable ELF note descriptor.
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

// Section is a byte range of the binary selected for string extraction.
type Section struct {
	Name    string
	Kind    SectionKind
	Data    []byte
	Addr    uint64
	EntSize uint64

	// Wide marks a section that was narrowed from 16 or 32-bit code units.
	Wide bool

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
	Format   string
	Headers  []SectionHeader
	Sections []Section
	Fallback []Section

	// Readable counts the selected sections that had bytes to read, including
	// note sections whose descriptors were all binary.
	Readable int

	// Truncated is set when a selected section runs past the end of the
	// file; the fallback sections are then not read.
	Truncated bool
}

// Options controls how strings are extracted and filtered.
type Options struct {
	Format        string
	MinLength     int
	SymLength     int
	Demangle      bool
	PrintSections bool

	// MaskProtobufs blanks serialized protobuf descriptors before extraction.
	MaskProtobufs bool

	// Terminated is "on" to apply the end-of-string rule to data sections,
	// "off" to skip it, or "auto" to apply it unless the file was built by
	// a toolchain that does not NUL-terminate its strings.
	Terminated string
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

	// terminated applies the end-of-string rule to data sections.
	terminated bool
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

// DumpSection emits the strings of one section and returns how many lines it
// emitted.
func (d *Dumper) DumpSection(s Section) int {
	lines := 0
	ends := newEndRule(s.Data)
	ruled := d.terminated && s.Kind == KindData

	for off, run := range splitRuns(s.Data) {
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
		lines++
	}

	return lines
}

// Dump emits the strings of every section, falling back to the fallback
// sections when the others produce no lines and none of them was truncated.
// Protobuf descriptors are masked in place in the section data first; the
// fallback decision is made on the unmasked sections.
func (d *Dumper) Dump(b *Binary) {
	needFallback := false

	if len(b.Fallback) > 0 && !b.Truncated {
		needFallback = true

		for _, s := range b.Sections {
			if d.hasLine(s) {
				needFallback = false
				break
			}
		}
	}

	if d.opts.MaskProtobufs {
		for _, s := range b.Sections {
			if s.Kind != KindNote && !s.Wide {
				MaskProtobufs(s.Data, nil)
			}
		}
	}

	for _, s := range b.Sections {
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

// Parse detects the format of data, unless format is set, and parses it.
func Parse(data []byte, format string, warn Warner) (*Binary, error) {
	if format == "" {
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

	if b.Readable == 0 {
		return nil, fmt.Errorf("no readable sections")
	}

	b.Format = format

	return b, nil
}

// DetectFormat identifies the binary format by its magic bytes.
func DetectFormat(data []byte) (string, error) {
	if len(data) < 4 {
		return "", fmt.Errorf("file too small to detect its format (%d bytes)", len(data))
	}

	switch {
	case bytes.HasPrefix(data, []byte("\x7fELF")):
		return "elf", nil
	case bytes.HasPrefix(data, []byte("MZ")):
		return "pe", nil
	case isFatMachO(data):
		return "macho", nil
	case bytes.HasPrefix(data, []byte{0xFE, 0xED, 0xFA, 0xCE}),
		bytes.HasPrefix(data, []byte{0xFE, 0xED, 0xFA, 0xCF}),
		bytes.HasPrefix(data, []byte{0xCE, 0xFA, 0xED, 0xFE}),
		bytes.HasPrefix(data, []byte{0xCF, 0xFA, 0xED, 0xFE}):
		return "macho", nil
	}

	return "", fmt.Errorf("unsupported file type, magic bytes: % x", data[:4])
}

// isFatMachO reports whether data starts with a fat Mach-O header. Java class
// files share the magic but hold their major version (45 or more) where the
// fat header holds the arch count.
func isFatMachO(data []byte) bool {
	if len(data) < 8 || !bytes.HasPrefix(data, []byte{0xCA, 0xFE, 0xBA, 0xBE}) {
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
