package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
)

var (
	binaryOpt = flag.String("binary", "", "the path to the Mach-O you wish to parse")
	trimOpt   = flag.Bool("no-trim", false, "disable triming whitespace and trailing newlines")
	humanOpt  = flag.Bool("no-human", false, "don't validate that its a human readable string, this increases the amount of junk")
)

// ReadSection is the main logic here
// it combines all of the modules, etc.
func ReadSection(reader *MachoReader, section string) {
	sect := reader.ReaderParseSection(section)

	if sect != nil {
		nodes := reader.ReaderParseStrings(sect)

		for _, bytes := range nodes {
			str := string(bytes)

			if !*humanOpt {
				if !UtilIsNice(str) {
					continue
				}
			}

			if !*trimOpt {
				str = strings.TrimSpace(str)
				bad := []string{"\n", "\r"}
				for _, char := range bad {
					str = strings.Replace(str, char, "", -1)
				}
			}

			fmt.Println(str)
		}
	}
}

func main() {
	flag.Parse()

	if *binaryOpt == "" {
		flag.PrintDefaults()
		return
	}

	r, err := NewMachoReader(*binaryOpt)
	if err != nil {
		log.Fatal(err.Error())
	}

	defer r.Close()

	sections := []string{"__bss", "__const", "__cstring", "__cfstring", "__text", "__TEXT", "__objc_classname__TEXT"}

	for _, section := range sections {
		ReadSection(r, section)
	}
}
