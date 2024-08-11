package main

import (
	"bytes"
	"github.com/ianlancetaylor/demangle"
	"strings"
)

var charactersToEscape = map[string]string{
	"\t": "\\t",
	"\v": "\\v",
	"\n": "\\n",
	"\r": "\\r",
	"\f": "\\f",
}

// UtilDemangle will demangle a symbol by string, this is
// simply just a friendly wrapped around the demangle package
func UtilDemangle(name string) string {
	skip := 0
	if name[0] == '.' || name[0] == '$' {
		skip++
	}

	if strings.HasPrefix(name, "__Z") {
		skip++
	}

	result := demangle.Filter(name[skip:], demangle.LLVMStyle)

	if result == name[skip:] {
		return name
	}

	var out bytes.Buffer
	if name[0] == '.' {
		out.WriteByte('.')
	}
	out.WriteString(result)
	return out.String()
}

func UtilEscape(str string) string {
	//str = strings.TrimSpace(str)
	for char, escapedChar := range charactersToEscape {
		str = strings.ReplaceAll(str, char, escapedChar)
	}
	return str
}
