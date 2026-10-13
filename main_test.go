package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunMainExitCodes(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "x.so")
	if err := os.WriteFile(bin, []byte("\x7fELF"), 0o644); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"no args", nil, 2},
		{"help", []string{"-h"}, 0},
		{"unknown command", []string{"bogus"}, 2},
		{"dump help", []string{"dump", "-h"}, 0},
		{"dump unknown flag", []string{"dump", "-bogus", bin}, 2},
		{"dump bad terminated", []string{"dump", "-terminated=x", bin}, 2},
		{"dump bad format", []string{"dump", "-format=x", bin}, 2},
		{"dump no positional", []string{"dump"}, 2},
		{"dump two positionals", []string{"dump", bin, bin}, 2},
		{"dump old flag", []string{"dump", "-binary", bin}, 2},
		{"dump missing file", []string{"dump", bin + ".missing"}, 1},
		{"dump unparsable", []string{"dump", bin}, 1},
		{"dedupe no config", []string{"dedupe"}, 2},
		{"dedupe help", []string{"dedupe", "-h"}, 0},
		{"fix-encoding no path", []string{"fix-encoding"}, 2},
		{"fix-encoding help", []string{"fix-encoding", "-h"}, 0},
		{"version", []string{"version"}, 0},
	}

	for _, tt := range tests {
		var stdout, stderr bytes.Buffer

		if got := runMain(tt.args, &stdout, &stderr); got != tt.want {
			t.Errorf("%s: exit %d, want %d (stderr %q)", tt.name, got, tt.want, stderr.String())
		}
	}
}

func TestRunMainVersion(t *testing.T) {
	var stdout, stderr bytes.Buffer

	runMain([]string{"version"}, &stdout, &stderr)

	if !strings.HasPrefix(stdout.String(), "DumpStrings ") {
		t.Errorf("version output %q", stdout.String())
	}
}

func TestRunMainUsageOnStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer

	runMain(nil, &stdout, &stderr)

	if stdout.Len() != 0 || !strings.Contains(stderr.String(), "dedupe") {
		t.Errorf("stdout %q stderr %q", stdout.String(), stderr.String())
	}
}

func TestRunMainSubcommandUsage(t *testing.T) {
	for _, cmd := range []string{"dump", "dedupe", "fix-encoding"} {
		var stdout, stderr bytes.Buffer

		if code := runMain([]string{cmd}, &stdout, &stderr); code != 2 {
			t.Errorf("%s: exit %d", cmd, code)
		}

		if stdout.Len() != 0 || !strings.Contains(stderr.String(), "Usage: DumpStrings "+cmd+" ") {
			t.Errorf("%s: stdout %q stderr %q", cmd, stdout.String(), stderr.String())
		}
	}
}

func TestBuildVersion(t *testing.T) {
	if buildVersion() == "" {
		t.Error("empty version")
	}
}

// writeTestELF writes an ELF file whose only read section is .rodata.
func writeTestELF(t *testing.T, rodata string) string {
	t.Helper()

	data := buildElf64(binary.LittleEndian, []testElfSection{{name: ".rodata", data: []byte(rodata)}})

	path := filepath.Join(t.TempDir(), "x.so")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}

	return path
}

// runFile calls run and returns what it wrote to stdout and stderr.
func runFile(path string, cfg dumpConfig) (stdout, stderr string, err error) {
	var out, errOut bytes.Buffer

	w := bufio.NewWriter(&out)
	err = run(path, testRunOptions, cfg, w, &errOut)
	w.Flush()

	return out.String(), errOut.String(), err
}

var (
	testRunOptions = Options{MinLength: 4, SymLength: 10, MaskProtobufs: true}
	testRunConfig  = dumpConfig{format: "auto", terminated: "auto"}
)

func TestRunSorted(t *testing.T) {
	path := writeTestELF(t, "zebra string\x00apple string\x00zebra string\x00mango fruit\x00")

	tests := []struct {
		sorted bool
		want   string
	}{
		{false, "zebra string\napple string\nzebra string\nmango fruit\n"},
		{true, "apple string\nmango fruit\nzebra string\n"},
	}

	for _, test := range tests {
		cfg := testRunConfig
		cfg.sorted = test.sorted

		stdout, stderr, err := runFile(path, cfg)

		if err != nil || stderr != "" || stdout != test.want {
			t.Errorf("sorted=%v: stdout %q, stderr %q, err %v, want %q", test.sorted, stdout, stderr, err, test.want)
		}
	}
}

func TestRunToolchainMarker(t *testing.T) {
	const ruledOut = "\x01\x02\x03ruled out string\x04\x05\x06\x00"

	tests := []struct {
		name       string
		rodata     string
		terminated string
		wantLine   bool
		wantNote   bool
	}{
		{"auto without a marker", ruledOut, "auto", false, false},
		{"auto with the Go marker", "\xff Go buildinf:\x08\x00" + ruledOut, "auto", true, true},
		{"auto with the Rust marker", "/rustc/0123abcd\x00" + ruledOut, "auto", true, true},
		{"on with the Go marker", "\xff Go buildinf:\x00" + ruledOut, "on", false, false},
		{"off without a marker", ruledOut, "off", true, false},
	}

	for _, test := range tests {
		cfg := testRunConfig
		cfg.terminated = test.terminated

		stdout, stderr, err := runFile(writeTestELF(t, test.rodata), cfg)
		if err != nil {
			t.Errorf("%s: %v", test.name, err)
			continue
		}

		if got := strings.Contains(stdout, "ruled out string"); got != test.wantLine {
			t.Errorf("%s: ruled out run printed = %v, want %v", test.name, got, test.wantLine)
		}

		if got := strings.Contains(stderr, "note: ") && strings.Contains(stderr, "end-of-string rule off"); got != test.wantNote {
			t.Errorf("%s: note printed = %v, want %v (stderr %q)", test.name, got, test.wantNote, stderr)
		}
	}
}

func TestRunErrors(t *testing.T) {
	dir := t.TempDir()
	garbage := filepath.Join(dir, "garbage")
	if err := os.WriteFile(garbage, []byte("not a binary at all"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, _, err := runFile(filepath.Join(dir, "missing"), testRunConfig); err == nil {
		t.Error("missing file: no error")
	}

	if _, _, err := runFile(garbage, testRunConfig); err == nil {
		t.Error("unsupported file: no error")
	}
}

func TestRunRecoversFromPanic(t *testing.T) {
	path := writeTestELF(t, "some string\x00")

	// A nil writer panics on the first line.
	err := run(path, testRunOptions, testRunConfig, nil, &bytes.Buffer{})

	if err == nil || !strings.HasPrefix(err.Error(), "panic: ") {
		t.Errorf("err = %v, want a recovered panic", err)
	}
}

func TestRunPrintSections(t *testing.T) {
	cfg := testRunConfig
	cfg.printSections = true

	stdout, stderr, err := runFile(writeTestELF(t, "\xff Go buildinf:\x08\x00some string\x00"), cfg)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(stdout, "\n.rodata\t") || !strings.Contains(stdout, "\tread=data\n") || strings.Contains(stdout, "some string") || stderr != "" {
		t.Errorf("stdout %q, stderr %q", stdout, stderr)
	}
}

func TestRunMainDumpFlags(t *testing.T) {
	path := writeTestELF(t, "zebra string\x00apple string\x00zebra string\x00")

	var stdout, stderr bytes.Buffer

	if code := runMain([]string{"dump", "-sort", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr.String())
	}

	if want := "apple string\nzebra string\n"; stdout.String() != want {
		t.Errorf("stdout = %q, want %q", stdout.String(), want)
	}
}
