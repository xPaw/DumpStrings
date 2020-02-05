package main

import (
	"debug/elf"

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

// UtilUniqueSlice will remove all duplicate instances
// from the offset slice.
func UtilUniqueSlice(s []uint64) []uint64 {
	seen := make(map[uint64]struct{}, len(s))
	j := 0

	for _, v := range s {
		if _, ok := seen[v]; ok {
			continue
		}

		seen[v] = struct{}{}
		s[j] = v

		j++
	}

	return s[:j]
}

// UtilIsNice will validate to make sure that the string in question
// is of 'human readable' format
func UtilIsNice(str string) bool {
	length := len(str)

	spaces := 0
	for i := 0; i < length; i++ {
		if str[i] == ' ' {
			spaces++
		}

		if str[i] < ' ' && !(str[i] == '\r' || str[i] == '\n') {
			return false
		}
	}

	if spaces == length {
		return false
	}

	return true
}
