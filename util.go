package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/ianlancetaylor/demangle"
)

// sortedUnique sorts lines in byte order and drops duplicates, in place.
func sortedUnique(lines []string) []string {
	slices.Sort(lines)

	return slices.Compact(lines)
}

// walkFiles calls fn with the path of every regular file under root whose name
// match accepts. Directories named .git or node_modules below root are skipped
// and symbolic links are not followed. A walk error goes to onErr: when onErr
// returns an error the walk stops with it, otherwise the entry is skipped.
func walkFiles(root string, match func(name string) bool, fn func(path string) error, onErr func(error) error) error {
	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if err := onErr(err); err != nil {
				return err
			}

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

		if d.Type().IsRegular() && match(d.Name()) {
			return fn(path)
		}

		return nil
	})
}

// replaceFile writes data next to path and renames it over the original so a
// failed write never leaves a truncated file.
func replaceFile(path string, data []byte, perm fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".DumpStrings-*")
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

var escapeReplacer = strings.NewReplacer(
	"\t", "\\t",
	"\v", "\\v",
	"\n", "\\n",
	"\r", "\\r",
	"\f", "\\f",
)

// maxDemangledLengthPow caps demangled output at 1<<16 bytes, which stops
// substitution chains from expanding exponentially.
const maxDemangledLengthPow = 16

// UtilDemangle demangles an Itanium symbol, returning name unchanged when it
// cannot be demangled. A leading '.' is kept and a leading '$' is dropped, and
// a trailing "@VERSION", "@@VERSION" or "@plt" is split off before demangling
// and re-appended.
func UtilDemangle(name string) (out string) {
	defer func() {
		if recover() != nil {
			out = name
		}
	}()

	sym := name
	prefix := ""

	switch {
	case strings.HasPrefix(sym, "."):
		prefix, sym = ".", sym[1:]
	case strings.HasPrefix(sym, "$"):
		sym = sym[1:]
	}

	// Mach-O adds an extra underscore to C++ symbols
	if strings.HasPrefix(sym, "__Z") {
		sym = sym[1:]
	}

	suffix := ""
	if i := strings.IndexByte(sym, '@'); i > 0 && isSymbolVersion(sym[i:]) {
		suffix = sym[i:]
		sym = sym[:i]
	}

	result, err := demangle.ToString(sym, demangle.LLVMStyle, demangle.MaxLength(maxDemangledLengthPow))
	if err != nil || len(result) >= 1<<maxDemangledLengthPow {
		return name
	}

	return prefix + result + suffix
}

// isSymbolVersion reports whether s is "@VERSION", "@@VERSION" or "@plt".
func isSymbolVersion(s string) bool {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "@"), "@")
	if s == "" {
		return false
	}

	for i := 0; i < len(s); i++ {
		c := s[i]

		if !(c == '_' || c == '.' || (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) {
			return false
		}
	}

	return true
}

func UtilEscape(str string) string {
	return escapeReplacer.Replace(str)
}

func UtilIsMajoritySymbols(str string) bool {
	letters := 0
	symbols := 0

	for _, char := range str {
		if unicode.IsLetter(char) || unicode.IsNumber(char) {
			letters++
		} else {
			symbols++
		}
	}

	return symbols >= letters
}
