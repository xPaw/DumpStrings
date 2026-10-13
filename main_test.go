package main

import (
	"bytes"
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
		{"dump bad protobufs", []string{"dump", "-protobufs=x", bin}, 2},
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
