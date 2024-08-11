package main

import (
	"github.com/ianlancetaylor/demangle"
)

// UtilDemangle will demangle a symbol by string, this is
// simply just a friendly wrapped around the demangle package
func UtilDemangle(symbol *string) (string, error) {
	x, err := demangle.ToString(*symbol)
	if err != nil {
		return "", err
	}

	return x, nil
}

// UtilIsNice will validate to make sure that the string in question
// is of 'human readable' format
func UtilIsNice(str string) bool {
	length := len(str)
	spaces := 0

	for _, char := range str {
		if char == ' ' {
			spaces++
		}

		if char < ' ' && !(char == '\r' || char == '\n') || char > 127 {
			return false
		}
	}

	if spaces == length {
		return false
	}

	return true
}
