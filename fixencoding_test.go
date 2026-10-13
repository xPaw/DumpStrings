package main

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

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
			root := writeTree(t, map[string]string{"f.txt": string(c.in)})

			enc, err := fixFileEncoding(filepath.Join(root, "f.txt"))
			if err != nil {
				t.Fatal(err)
			}

			if enc != c.enc {
				t.Fatalf("encoding %q, want %q", enc, c.enc)
			}

			want := string(c.in)
			if c.enc != "" {
				want = c.out
			}

			if got := readTree(t, root, "f.txt"); got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

func TestRunFixEncodingWalk(t *testing.T) {
	const utf16 = "\xFF\xFEa\x00"

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

	tree := map[string]string{}
	for name := range files {
		tree[name] = utf16
	}

	dir := writeTree(t, tree)

	var stdout bytes.Buffer

	if code := runFixEncoding([]string{dir}, &stdout, io.Discard); code != 0 {
		t.Fatalf("exit %d", code)
	}

	for name, converted := range files {
		got := readTree(t, dir, name)
		if converted != (got == "a\n") {
			t.Errorf("%s: converted=%v, content %q", name, !converted, got)
		}
	}

	if want := " UTF-16LE - " + filepath.Join(dir, "a.txt") + "\n"; !strings.Contains(stdout.String(), want) {
		t.Errorf("stdout %q, want a line %q", stdout.String(), want)
	}

	if code := runFixEncoding([]string{"-ext", "xml,TXT", dir}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("exit %d", code)
	}

	for _, name := range []string{"sub/c.xml", "sub/UPPER.TXT"} {
		if got := readTree(t, dir, name); got != "a\n" {
			t.Errorf("%s: %q", name, got)
		}
	}

	if got := readTree(t, dir, ".git/d.txt"); got != utf16 {
		t.Error(".git was touched")
	}
}

func TestRunFixEncodingSymlinks(t *testing.T) {
	const utf16 = "\xFF\xFEa\x00"

	root := writeTree(t, map[string]string{"real/a.txt": utf16, "other/f.txt": utf16})
	dirLink := filepath.Join(root, "dirlink")
	fileLink := filepath.Join(root, "filelink.txt")

	symlink(t, filepath.Join(root, "real"), dirLink)
	symlink(t, filepath.Join(root, "other", "f.txt"), fileLink)

	var stdout bytes.Buffer

	if code := runFixEncoding([]string{dirLink, fileLink}, &stdout, io.Discard); code != 0 {
		t.Fatalf("exit %d", code)
	}

	want := " UTF-16LE - " + filepath.Join(dirLink, "a.txt") + "\n UTF-16LE - " + fileLink + "\n"
	if stdout.String() != want {
		t.Errorf("stdout %q, want %q", stdout.String(), want)
	}

	for _, name := range []string{"real/a.txt", "other/f.txt"} {
		if got := readTree(t, root, name); got != "a\n" {
			t.Errorf("%s: %q", name, got)
		}
	}

	if info, err := os.Lstat(fileLink); err != nil || info.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("file link replaced: %v, %v", info, err)
	}
}

func TestRunFixEncodingFileArgIgnoresExt(t *testing.T) {
	root := writeTree(t, map[string]string{"x.bin": "\xFF\xFEa\x00"})

	if code := runFixEncoding([]string{filepath.Join(root, "x.bin")}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("exit %d", code)
	}

	if got := readTree(t, root, "x.bin"); got != "a\n" {
		t.Fatalf("got %q", got)
	}
}

func TestRunFixEncodingExitCodes(t *testing.T) {
	dir := writeTree(t, map[string]string{"g.txt": "\xFF\xFEa\x00"})

	if code := runFixEncoding(nil, io.Discard, io.Discard); code != 2 {
		t.Errorf("no args: %d", code)
	}

	if code := runFixEncoding([]string{"-bogus", dir}, io.Discard, io.Discard); code != 2 {
		t.Errorf("bad flag: %d", code)
	}

	var stderr bytes.Buffer

	if code := runFixEncoding([]string{filepath.Join(dir, "missing"), filepath.Join(dir, "g.txt")}, io.Discard, &stderr); code != 1 {
		t.Errorf("missing path: %d", code)
	}

	if !strings.HasPrefix(stderr.String(), "Error: ") {
		t.Errorf("stderr %q", stderr.String())
	}

	if got := readTree(t, dir, "g.txt"); got != "a\n" {
		t.Errorf("later path not processed: %q", got)
	}
}

func TestFixFileEncodingKeepsMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows files have no permission bits beyond read-only")
	}

	root := writeTree(t, map[string]string{"m.txt": "\xFF\xFEa\x00"})
	path := filepath.Join(root, "m.txt")

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
