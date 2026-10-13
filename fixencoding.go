package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
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

// fixFileEncoding rewrites a UTF-16/UTF-32 file as trimmed UTF-8 with a single
// trailing newline. It returns the detected encoding name, or "" if the file
// was left untouched.
func fixFileEncoding(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}

	var head [4]byte
	n, err := io.ReadFull(f, head[:])
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		f.Close()
		return "", err
	}

	enc, name := detectBOMEncoding(head[:n])
	if enc == nil {
		f.Close()
		return "", nil
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return "", err
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return "", err
	}

	data, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		return "", err
	}

	decoded, _, err := transform.Bytes(enc.NewDecoder(), data)
	if err != nil {
		return "", fmt.Errorf("decode %s: %w", name, err)
	}

	decoded = bytes.TrimPrefix(decoded, []byte{0xEF, 0xBB, 0xBF})
	decoded = bytes.TrimSpace(decoded)
	decoded = append(decoded, '\n')

	return name, replaceFile(path, decoded, info.Mode().Perm())
}

// replaceFile writes data next to path and renames it over the original so a
// failed write never leaves a truncated file.
func replaceFile(path string, data []byte, perm fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".fix-encoding-*")
	if err != nil {
		return err
	}

	tmpName := tmp.Name()

	_, err = tmp.Write(data)

	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}

	if err == nil {
		err = os.Chmod(tmpName, perm)
	}

	if err == nil {
		err = os.Rename(tmpName, path)
	}

	if err != nil {
		os.Remove(tmpName)
	}

	return err
}

// runFixEncoding implements the fix-encoding subcommand and returns the exit code.
func runFixEncoding(args []string) int {
	flags := flag.NewFlagSet("fix-encoding", flag.ContinueOnError)
	extList := flags.String("ext", "txt", "comma separated file extensions to process in directories")

	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: DumpStrings fix-encoding [-ext txt,...] <path>...")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		return 2
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

	exitCode := 0

	process := func(path string) {
		name, err := fixFileEncoding(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %s: %v\n", path, err)
		} else if name != "" {
			fmt.Printf(" %s - %s\n", name, path)
		}
	}

	for _, root := range flags.Args() {
		info, err := os.Stat(root)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			exitCode = 1
			continue
		}

		if !info.IsDir() {
			process(root)
			continue
		}

		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: %v\n", err)

				if d != nil && d.IsDir() {
					return fs.SkipDir
				}

				return nil
			}

			if d.IsDir() {
				if path != root && (d.Name() == ".git" || d.Name() == "node_modules") {
					return fs.SkipDir
				}

				return nil
			}

			if !d.Type().IsRegular() {
				return nil
			}

			name := d.Name()
			dot := strings.LastIndexByte(name, '.')

			if dot < 0 {
				return nil
			}

			if _, ok := exts[name[dot+1:]]; ok {
				process(path)
			}

			return nil
		})

		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
		}
	}

	return exitCode
}
