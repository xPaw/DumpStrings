package main

import (
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
func UtilDemangle(symbol *string) (string, error) {
	x, err := demangle.ToString(*symbol)
	if err != nil {
		return "", err
	}

	return x, nil
}

func UtilEscape(str string) string {
	//str = strings.TrimSpace(str)
	for char, escapedChar := range charactersToEscape {
		str = strings.ReplaceAll(str, char, escapedChar)
	}
	return str
}
