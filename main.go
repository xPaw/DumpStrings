package main

import (
	"flag"
	"fmt"
	"log"
)

var (
	binaryOpt    = flag.String("binary", "", "the path to the binary you wish to parse")
	targetOpt    = flag.String("target", "", "the target type of the binary (macho/elf/pe)")
	demangleOpt  = flag.Bool("demangle", true, "demangle C++ symbols into their original source identifiers")
	minLengthOpt = flag.Int("min-length", 4, "minimum length of a string")
	sectionsOpt  = flag.Bool("print-sections", false, "print all the section names found in the binary")
)

func ReadSection(reader *FileReader, section string) {
	sect := reader.ReaderParseSection(section)

	if sect != nil {
		nodes := reader.ReaderParseStrings(sect)

		for _, bytes := range nodes {
			if len(bytes) < 1 {
				continue
			}

			str := string(bytes)

			if len(str) < *minLengthOpt {
				continue
			}

			str = UtilEscape(str)

			if *demangleOpt {
				str = UtilDemangle(str)
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

	r, err := NewFileReader(*binaryOpt, *targetOpt)
	if err != nil {
		log.Fatal(err.Error())
	}

	defer r.Close()

	if *sectionsOpt {
		r.PrintSections()
		return
	}

	var sections []string

	switch *targetOpt {
	case "macho":
		sections = []string{"__bss", "__const", "__cstring", "__cfstring", "__text", "__TEXT", "__objc_classname__TEXT", "__data"}
	case "elf":
		sections = []string{".dynstr", ".rodata", ".rdata", ".strtab", ".comment", ".note", ".stab", ".stabstr", ".note.ABI-tag", ".note.gnu.build-id"}
	case "pe":
		sections = []string{".data", ".rdata"}
	default:
		log.Fatal("Unknown target")
	}

	for _, section := range sections {
		ReadSection(r, section)
	}
}
