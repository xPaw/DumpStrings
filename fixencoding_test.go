package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func writeTestFile(t *testing.T, path string, data []byte) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	return data
}

func TestFixFileEncoding(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		enc  string
		out  string
	}{
		{"utf16le", []byte{0xFF, 0xFE, 'h', 0, 'i', 0, ' ', 0, '\r', 0, '\n', 0}, "UTF-16LE", "hi\n"},
		{"utf16be", []byte{0xFE, 0xFF, 0, 'h', 0, 'i', 0, '\n'}, "UTF-16BE", "hi\n"},
		{"utf32le", []byte{0xFF, 0xFE, 0, 0, 'h', 0, 0, 0, 'i', 0, 0, 0}, "UTF-32LE", "hi\n"},
		{"utf32be", []byte{0, 0, 0xFE, 0xFF, 0, 0, 0, 'h', 0, 0, 0, 'i'}, "UTF-32BE", "hi\n"},
		{"utf16le empty", []byte{0xFF, 0xFE}, "UTF-16LE", "\n"},
		{"utf16le odd length", []byte{0xFF, 0xFE, 'a', 0, 'b'}, "UTF-16LE", "a�\n"},
		{"utf16le leading nul is utf32le", []byte{0xFF, 0xFE, 0, 0, 'a', 0}, "UTF-32LE", "�\n"},
		{"utf16le nbsp", []byte{0xFF, 0xFE, 'a', 0, 0xA0, 0, 0x85, 0}, "UTF-16LE", "a\n"},
		{"ascii", []byte("plain\r\n"), "", ""},
		{"utf8 bom", []byte{0xEF, 0xBB, 0xBF, 'a'}, "", ""},
		{"one byte", []byte{0xFF}, "", ""},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "f.txt")
			writeTestFile(t, path, c.in)

			enc, err := fixFileEncoding(path)
			if err != nil {
				t.Fatal(err)
			}

			if enc != c.enc {
				t.Fatalf("encoding %q, want %q", enc, c.enc)
			}

			want := c.in
			if c.enc != "" {
				want = []byte(c.out)
			}

			if got := readTestFile(t, path); !bytes.Equal(got, want) {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

func TestRunFixEncodingWalk(t *testing.T) {
	dir := t.TempDir()
	utf16 := []byte{0xFF, 0xFE, 'a', 0}

	files := map[string]bool{
		"a.txt":                   true,
		"sub/b.txt":               true,
		"sub/c.xml":               false,
		"sub/UPPER.TXT":           false,
		"noext":                   false,
		".git/d.txt":              false,
		"node_modules/x/e.txt":    false,
		"sub/deep/.hidden.txt":    true,
		"sub/deep/archive.tar.gz": false,
	}

	for name := range files {
		writeTestFile(t, filepath.Join(dir, name), utf16)
	}

	if code := runFixEncoding([]string{dir}); code != 0 {
		t.Fatalf("exit %d", code)
	}

	for name, converted := range files {
		got := readTestFile(t, filepath.Join(dir, name))
		if converted != bytes.Equal(got, []byte("a\n")) {
			t.Errorf("%s: converted=%v, content %q", name, !converted, got)
		}
	}

	if code := runFixEncoding([]string{"-ext", "xml,TXT", dir}); code != 0 {
		t.Fatalf("exit %d", code)
	}

	for _, name := range []string{"sub/c.xml", "sub/UPPER.TXT"} {
		if got := readTestFile(t, filepath.Join(dir, name)); !bytes.Equal(got, []byte("a\n")) {
			t.Errorf("%s: %q", name, got)
		}
	}

	if got := readTestFile(t, filepath.Join(dir, ".git/d.txt")); !bytes.Equal(got, utf16) {
		t.Error(".git was touched")
	}
}

func TestRunFixEncodingFileArgIgnoresExt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.bin")
	writeTestFile(t, path, []byte{0xFF, 0xFE, 'a', 0})

	if code := runFixEncoding([]string{path}); code != 0 {
		t.Fatalf("exit %d", code)
	}

	if got := readTestFile(t, path); !bytes.Equal(got, []byte("a\n")) {
		t.Fatalf("got %q", got)
	}
}

func TestRunFixEncodingExitCodes(t *testing.T) {
	dir := t.TempDir()

	if code := runFixEncoding(nil); code != 2 {
		t.Errorf("no args: %d", code)
	}

	if code := runFixEncoding([]string{"-bogus", dir}); code != 2 {
		t.Errorf("bad flag: %d", code)
	}

	good := filepath.Join(dir, "g.txt")
	writeTestFile(t, good, []byte{0xFF, 0xFE, 'a', 0})

	if code := runFixEncoding([]string{filepath.Join(dir, "missing"), good}); code != 1 {
		t.Errorf("missing path: %d", code)
	}

	if got := readTestFile(t, good); !bytes.Equal(got, []byte("a\n")) {
		t.Errorf("later path not processed: %q", got)
	}
}

func TestFixFileEncodingKeepsMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.txt")
	writeTestFile(t, path, []byte{0xFF, 0xFE, 'a', 0})

	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := fixFileEncoding(path); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if info.Mode().Perm() != 0600 {
		t.Errorf("mode %v", info.Mode().Perm())
	}
}
