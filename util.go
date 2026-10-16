package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/ianlancetaylor/demangle"
)

// sortedUnique sorts lines in byte order and drops duplicates, in place.
func sortedUnique(lines []string) []string {
	slices.Sort(lines)

	return slices.Compact(lines)
}

// walkFiles calls fn with the path of every regular file under root whose name
// match accepts. It skips directories named .git or node_modules below root.
// It does not follow symbolic links below root. It walks through a root that is
// a symbolic link, and still reports paths under root. A walk error goes to
// onErr. If onErr returns an error, the walk stops with it. Otherwise the walk
// skips the entry.
func walkFiles(root string, match func(name string) bool, fn func(path string) error, onErr func(error) error) error {
	walkRoot := root

	if info, err := os.Lstat(root); err == nil && info.Mode()&fs.ModeSymlink != 0 {
		if resolved, err := filepath.EvalSymlinks(root); err == nil {
			walkRoot = resolved
		}
	}

	return filepath.WalkDir(walkRoot, func(path string, d fs.DirEntry, err error) error {
		if path == walkRoot {
			path = root
		} else if walkRoot != root {
			rel, _ := filepath.Rel(walkRoot, path)
			path = filepath.Join(root, rel)
		}

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

// replaceFile writes data next to path and renames it over the original. This
// way a failed write never leaves a truncated file. When path is a symbolic
// link, it replaces the file that the link resolves to and keeps the link.
func replaceFile(path string, data []byte, perm fs.FileMode) error {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		path = resolved
	}

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

// maxDemangledLengthPow caps demangled output at 1<<16 bytes. This stops
// substitution chains from expanding exponentially.
const maxDemangledLengthPow = 16

// UtilDemangle demangles an Itanium symbol. It returns name unchanged when it
// cannot demangle it. It keeps a leading '.' and drops a leading '$'. It splits
// off a trailing "@VERSION", "@@VERSION" or "@plt" before demangling and
// appends it again afterwards.
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

// UtilIsMajoritySymbols reports whether at least half of the characters of str
// are not letters or digits. Every character of a printf conversion such as
// "%s" or "%-5.2f" counts as a letter, so short format strings are kept.
func UtilIsMajoritySymbols(str string) bool {
	letters := 0
	symbols := 0

	for i := 0; i < len(str); {
		if str[i] == '%' {
			if n := printfConversionLen(str[i:]); n > 0 {
				letters += n
				i += n
				continue
			}
		}

		char, size := utf8.DecodeRuneInString(str[i:])
		i += size

		if unicode.IsLetter(char) || unicode.IsNumber(char) {
			letters++
		} else {
			symbols++
		}
	}

	return symbols >= letters
}

// printfConversionLen returns the length of the printf conversion at the start
// of s, or 0 when s does not start with one.
func printfConversionLen(s string) int {
	if !strings.HasPrefix(s, "%") {
		return 0
	}

	i := 1

	for i < len(s) && strings.IndexByte("-+ #0", s[i]) >= 0 {
		i++
	}

	i = skipPrintfWidth(s, i)

	if i < len(s) && s[i] == '.' {
		i = skipPrintfWidth(s, i+1)
	}

	for i < len(s) && strings.IndexByte("hlLjztI", s[i]) >= 0 {
		i++
	}

	if strings.HasPrefix(s[i:], "32") || strings.HasPrefix(s[i:], "64") {
		i += 2
	}

	if i < len(s) && strings.IndexByte("diouxXeEfFgGaAcCsSpn%", s[i]) >= 0 {
		return i + 1
	}

	return 0
}

// skipPrintfWidth returns the offset past a width or precision at s[i], which
// is either '*' or a run of digits.
func skipPrintfWidth(s string, i int) int {
	if i < len(s) && s[i] == '*' {
		return i + 1
	}

	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}

	return i
}
