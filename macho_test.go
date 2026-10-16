package main

import (
	"debug/macho"
	"encoding/binary"
	"reflect"
	"strings"
	"testing"
)

type testMachoSection struct {
	seg, name string
	flags     uint32
	data      []byte
}

const (
	testCpuAmd64 = uint32(macho.CpuAmd64)
	testCpuArm64 = uint32(macho.CpuArm64)
)

var testMachOOptions = Options{MinLength: 4, SymLength: 10, MaskProtobufs: true, Terminated: true}

// machoLoadPath encodes a load command whose lc_str of path sits at off.
func machoLoadPath(cmd, off uint32, path string) []byte {
	size := (int(off) + len(path) + 1 + 7) &^ 7
	b := make([]byte, size)

	binary.LittleEndian.PutUint32(b, cmd)
	binary.LittleEndian.PutUint32(b[4:], uint32(size))
	binary.LittleEndian.PutUint32(b[8:], off)
	copy(b[off:], path)

	return b
}

// buildMachO assembles a thin little-endian 64-bit Mach-O file with one
// segment per section, an LC_SYMTAB when strtab is set, and the given raw
// load commands. The file content of every section is written, whatever its
// type.
func buildMachO(cpu uint32, secs []testMachoSection, strtab []byte, loads [][]byte) []byte {
	le := binary.LittleEndian
	ncmds := len(secs) + len(loads)
	cmdsSize := len(secs) * 152

	for _, l := range loads {
		cmdsSize += len(l)
	}

	if strtab != nil {
		ncmds++
		cmdsSize += 24
	}

	out := make([]byte, 32+cmdsSize)
	le.PutUint32(out, macho.Magic64)
	le.PutUint32(out[4:], cpu)
	le.PutUint32(out[8:], 3)
	le.PutUint32(out[12:], 6)
	le.PutUint32(out[16:], uint32(ncmds))
	le.PutUint32(out[20:], uint32(cmdsSize))

	p := 32
	strOff := len(out)
	out = append(out, strtab...)

	offs := make([]int, len(secs))

	for i, s := range secs {
		offs[i] = len(out)
		out = append(out, s.data...)
	}

	for i, s := range secs {
		c := out[p:]
		off := offs[i]

		le.PutUint32(c, uint32(macho.LoadCmdSegment64))
		le.PutUint32(c[4:], 152)
		copy(c[8:], s.seg)
		le.PutUint64(c[24:], 0x1000*uint64(i+1))
		le.PutUint64(c[32:], 0x1000)
		le.PutUint64(c[40:], uint64(off))
		le.PutUint64(c[48:], uint64(len(s.data)))
		le.PutUint32(c[64:], 1)

		copy(c[72:], s.name)
		copy(c[88:], s.seg)
		le.PutUint64(c[104:], 0x1000*uint64(i+1))
		le.PutUint64(c[112:], uint64(len(s.data)))
		le.PutUint32(c[120:], uint32(off))
		le.PutUint32(c[136:], s.flags)

		p += 152
	}

	for _, l := range loads {
		copy(out[p:], l)
		p += len(l)
	}

	if strtab != nil {
		le.PutUint32(out[p:], uint32(macho.LoadCmdSymtab))
		le.PutUint32(out[p+4:], 24)
		le.PutUint32(out[p+8:], uint32(strOff))
		le.PutUint32(out[p+16:], uint32(strOff))
		le.PutUint32(out[p+20:], uint32(len(strtab)))
	}

	return out
}

// buildFatMachO joins images into a big-endian fat file, each at a 0x100
// aligned offset.
func buildFatMachO(cpus []uint32, images [][]byte) []byte {
	be := binary.BigEndian
	out := make([]byte, 8+20*len(images))
	be.PutUint32(out, macho.MagicFat)
	be.PutUint32(out[4:], uint32(len(images)))

	for i, img := range images {
		for len(out)%0x100 != 0 {
			out = append(out, 0)
		}

		a := out[8+20*i:]
		be.PutUint32(a, cpus[i])
		be.PutUint32(a[4:], 3)
		be.PutUint32(a[8:], uint32(len(out)))
		be.PutUint32(a[12:], uint32(len(img)))
		be.PutUint32(a[16:], 8)

		out = append(out, img...)
	}

	return out
}

func TestMachOThin(t *testing.T) {
	img := buildMachO(testCpuAmd64, []testMachoSection{
		{"__TEXT", "__cstring", 0x2, []byte("cstring one\x00cstring two\x00")},
		{"__TEXT", "__const", 0, []byte("const data string\x00")},
		{"__DATA", "__data", 0, []byte("data section str\x00")},
		{"__DATA", "__bss", 0x1, []byte("zerofill trap string\x00")},
		{"__TEXT", "__text", 0, []byte("unselected text string\x00")},
	}, []byte("\x00_symbol_name_one\x00_symbol_two\x00"), [][]byte{
		machoLoadPath(uint32(macho.LoadCmdDylib), 24, "/usr/lib/libSystem.B.dylib"),
		machoLoadPath(uint32(macho.LoadCmdRpath), 12, "@executable_path/../lib"),
	})

	b, lines, warnings := parseAndDump(t, img, testMachOOptions)

	want := []string{
		"cstring one", "cstring two", "const data string", "data section str",
		"/usr/lib/libSystem.B.dylib", "@executable_path/../lib",
		"_symbol_name_one", "_symbol_two",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Errorf("lines = %q, want %q", lines, want)
	}

	if len(warnings) != 0 || !b.Readable || len(b.Sections) != 5 {
		t.Errorf("warnings %q, readable %v, %d sections", warnings, b.Readable, len(b.Sections))
	}

	// Every section is masked. Only __const and __data take the end-of-string
	// rule.
	for i, s := range b.Sections {
		if wantRule := i == 1 || i == 2; !s.Mask || s.EndRule != wantRule {
			t.Errorf("section %d: mask %v, end rule %v", i, s.Mask, s.EndRule)
		}
	}

	var reads []string
	for _, h := range b.Headers {
		reads = append(reads, h.Name+"="+h.Read)
	}

	wantReads := []string{
		"__TEXT,__cstring=strings", "__TEXT,__const=data", "__DATA,__data=data",
		"__DATA,__bss=", "__TEXT,__text=", "load commands=strings", "LC_SYMTAB=strings",
	}
	if !reflect.DeepEqual(reads, wantReads) {
		t.Errorf("headers = %q, want %q", reads, wantReads)
	}

	if got, want := b.Headers[0].Type, "type=0x2 flags=0x00000002"; got != want {
		t.Errorf("section type = %q, want %q", got, want)
	}

	if got, want := b.Headers[5].Type, "paths=2"; got != want {
		t.Errorf("load commands type = %q, want %q", got, want)
	}
}

func TestMachOFat(t *testing.T) {
	first := buildMachO(testCpuAmd64, []testMachoSection{{"__TEXT", "__cstring", 0x2, []byte("alpha string one\x00")}}, []byte("\x00_alpha_symbol\x00"), nil)
	second := buildMachO(testCpuArm64, []testMachoSection{{"__TEXT", "__cstring", 0x2, []byte("beta string two\x00")}}, nil, nil)
	img := buildFatMachO([]uint32{testCpuAmd64, testCpuArm64}, [][]byte{first, second})

	if format, err := DetectFormat(img); format != "macho" || err != nil {
		t.Fatalf("DetectFormat = %q, %v", format, err)
	}

	b, lines, warnings := parseAndDump(t, img, testMachOOptions)

	if want := []string{"alpha string one", "_alpha_symbol", "beta string two"}; !reflect.DeepEqual(lines, want) {
		t.Errorf("lines = %q, want %q", lines, want)
	}

	var names []string
	for _, h := range b.Headers {
		names = append(names, h.Name)
	}

	if want := []string{"x86_64:__TEXT,__cstring", "x86_64:LC_SYMTAB", "arm64:__TEXT,__cstring"}; !reflect.DeepEqual(names, want) {
		t.Errorf("headers = %q, want %q", names, want)
	}

	if len(warnings) != 0 {
		t.Errorf("warnings %q", warnings)
	}
}

func TestMachOFatTruncated(t *testing.T) {
	first := buildMachO(testCpuAmd64, []testMachoSection{{"__TEXT", "__cstring", 0x2, []byte("alpha string one\x00")}}, nil, nil)
	second := buildMachO(testCpuArm64, []testMachoSection{{"__TEXT", "__cstring", 0x2, []byte("beta string two\x00padding after")}}, nil, nil)
	img := buildFatMachO([]uint32{testCpuAmd64, testCpuArm64}, [][]byte{first, second})

	_, lines, warnings := parseAndDump(t, img[:len(img)-14], testMachOOptions)

	if want := []string{"alpha string one", "beta string two"}; !reflect.DeepEqual(lines, want) {
		t.Errorf("lines = %q, want %q", lines, want)
	}

	if len(warnings) != 2 || !strings.HasPrefix(warnings[0], "arm64:arch:") || !strings.HasPrefix(warnings[1], "arm64:__TEXT,__cstring:") {
		t.Errorf("warnings = %q", warnings)
	}
}

func TestMachORejectsBadFat(t *testing.T) {
	for _, n := range []uint32{0, 17, 0x34} {
		img := binary.BigEndian.AppendUint32([]byte{0xca, 0xfe, 0xba, 0xbe}, n)

		if format, err := DetectFormat(img); err == nil {
			t.Errorf("nfat_arch %d detected as %q", n, format)
		}

		if _, err := parseMachO(img, func(string, ...any) {}); err == nil {
			t.Errorf("nfat_arch %d parsed", n)
		}
	}
}

func TestMachOZerofill(t *testing.T) {
	for flags, want := range map[uint32]bool{0: false, 0x2: false, 0x1: true, 0xc: true, 0x12: true, 0x80000401: true, 0x80000400: false} {
		if got := machoZerofill(flags); got != want {
			t.Errorf("machoZerofill(0x%x) = %v, want %v", flags, got, want)
		}
	}
}

func TestMachOCpuName(t *testing.T) {
	tests := map[macho.Cpu]string{
		macho.Cpu386:   "i386",
		macho.CpuAmd64: "x86_64",
		macho.CpuArm:   "arm",
		macho.CpuArm64: "arm64",
		macho.CpuPpc:   "ppc",
		macho.CpuPpc64: "ppc64",
		macho.Cpu(99):  "cpu99",
	}

	for cpu, want := range tests {
		if got := machoCpuName(cpu); got != want {
			t.Errorf("machoCpuName(%d) = %q, want %q", uint32(cpu), got, want)
		}
	}
}
