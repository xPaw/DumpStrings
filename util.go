package main

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
