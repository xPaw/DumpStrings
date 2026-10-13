package main

import (
	"github.com/ianlancetaylor/demangle"
	"strings"
	"unicode"
)

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
// cannot be demangled. A leading '.' is kept, and a trailing "@VERSION",
// "@@VERSION" or "@plt" is split off before demangling and re-appended.
func UtilDemangle(name string) (out string) {
	defer func() {
		if recover() != nil {
			out = name
		}
	}()

	sym := name
	prefix := ""

	if len(sym) > 0 && (sym[0] == '.' || sym[0] == '$') {
		prefix = sym[:1]
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

	if prefix == "$" {
		prefix = ""
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
