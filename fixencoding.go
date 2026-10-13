package main

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"golang.org/x/text/encoding"
	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/encoding/unicode/utf32"
	"golang.org/x/text/transform"
)

// detectBOMEncoding identifies UTF-16/UTF-32 content by its byte order mark.
// UTF-32 is checked first because its little endian mark starts with the
// UTF-16LE one. Anything else (including UTF-8 with or without BOM) returns nil.
func detectBOMEncoding(head []byte) (encoding.Encoding, string) {
	switch {
	case bytes.HasPrefix(head, []byte{0x00, 0x00, 0xFE, 0xFF}):
		return utf32.UTF32(utf32.BigEndian, utf32.UseBOM), "UTF-32BE"
	case bytes.HasPrefix(head, []byte{0xFF, 0xFE, 0x00, 0x00}):
		return utf32.UTF32(utf32.LittleEndian, utf32.UseBOM), "UTF-32LE"
	case bytes.HasPrefix(head, []byte{0xFE, 0xFF}):
		return unicode.UTF16(unicode.BigEndian, unicode.UseBOM), "UTF-16BE"
	case bytes.HasPrefix(head, []byte{0xFF, 0xFE}):
		return unicode.UTF16(unicode.LittleEndian, unicode.UseBOM), "UTF-16LE"
	}

	return nil, ""
}

// readBOMFile reads a file that starts with a UTF-16 or UTF-32 byte order
// mark, and returns its bytes, encoding and permissions. Only the first bytes
// of any other file are read, and its encoding is nil.
func readBOMFile(path string) ([]byte, encoding.Encoding, string, fs.FileMode, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, "", 0, err
	}

	defer f.Close()

	var head [4]byte
	n, err := io.ReadFull(f, head[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return nil, nil, "", 0, err
	}

	enc, name := detectBOMEncoding(head[:n])
	if enc == nil {
		return nil, nil, "", 0, nil
	}

	info, err := f.Stat()
	if err != nil {
		return nil, nil, "", 0, err
	}

	data, err := io.ReadAll(io.MultiReader(bytes.NewReader(head[:n]), f))
	if err != nil {
		return nil, nil, "", 0, err
	}

	return data, enc, name, info.Mode().Perm(), nil
}

// fixFileEncoding rewrites a UTF-16/UTF-32 file as trimmed UTF-8 with a single
// trailing newline. It returns the detected encoding name, or "" if the file
// was left untouched.
func fixFileEncoding(path string) (string, error) {
	data, enc, name, perm, err := readBOMFile(path)
	if enc == nil || err != nil {
		return "", err
	}

	decoded, _, err := transform.Bytes(enc.NewDecoder(), data)
	if err != nil {
		return "", fmt.Errorf("decode %s: %w", name, err)
	}

	decoded = bytes.TrimPrefix(decoded, []byte{0xEF, 0xBB, 0xBF})
	decoded = bytes.TrimSpace(decoded)
	decoded = append(decoded, '\n')

	return name, replaceFile(path, decoded, perm)
}

// runFixEncoding implements the fix-encoding subcommand and returns the exit code.
func runFixEncoding(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("fix-encoding", "Usage: DumpStrings fix-encoding [-ext txt,...] <path>...", stderr)
	extList := flags.String("ext", "txt", "comma separated file extensions to process in directories")

	if code, ok := parseFlags(flags, args); !ok {
		return code
	}

	if flags.NArg() == 0 {
		flags.Usage()
		return 2
	}

	exts := make(map[string]struct{})

	for _, ext := range strings.Split(*extList, ",") {
		if ext = strings.TrimPrefix(strings.TrimSpace(ext), "."); ext != "" {
			exts[ext] = struct{}{}
		}
	}

	hasExt := func(name string) bool {
		dot := strings.LastIndexByte(name, '.')
		if dot < 0 {
			return false
		}

		_, ok := exts[name[dot+1:]]

		return ok
	}

	process := func(path string) error {
		name, err := fixFileEncoding(path)
		if err != nil {
			fmt.Fprintf(stderr, "Warning: %s: %v\n", path, err)
		} else if name != "" {
			fmt.Fprintf(stdout, " %s - %s\n", name, path)
		}

		return nil
	}

	warn := func(err error) error {
		fmt.Fprintf(stderr, "Warning: %v\n", err)
		return nil
	}

	exitCode := 0

	for _, root := range flags.Args() {
		info, err := os.Stat(root)
		if err != nil {
			fmt.Fprintf(stderr, "Error: %v\n", err)
			exitCode = 1
			continue
		}

		if !info.IsDir() {
			process(root)
			continue
		}

		if err := walkFiles(root, hasExt, process, warn); err != nil {
			warn(err)
		}
	}

	return exitCode
}
