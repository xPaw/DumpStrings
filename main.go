package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
)

var (
	binaryOpt   = flag.String("binary", "", "the path to the ELF you wish to parse")
	demangleOpt = flag.Bool("demangle", true, "demangle C++ symbols into their original source identifiers")
	trimOpt     = flag.Bool("no-trim", false, "disable triming whitespace and trailing newlines")
	humanOpt    = flag.Bool("no-human", false, "don't validate that its a human readable string, this could increase the amount of junk.")
)

// ReadSection is the main logic here
// it combines all of the modules, etc.
func ReadSection(reader *ElfReader, section string) {
	var err error

	sect := reader.ReaderParseSection(section)

	if sect != nil {
		nodes := reader.ReaderParseStrings(sect)

		// Since maps in Go are unsorted, we're going to have to make
		// a slice of keys, then iterate over this and just use the index
		// from the map.
		keys := make([]uint64, len(nodes))
		for k, _ := range nodes {
			keys = append(keys, k)
		}

		keys = UtilUniqueSlice(keys)

		for _, off := range keys {
			str := string(nodes[off])

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

			if *demangleOpt {
				demangled, err := UtilDemangle(&str)
				if err == nil {
					str = demangled
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

	r, err := NewELFReader(*binaryOpt)
	if err != nil {
		log.Fatal(err.Error())
	}

	defer r.Close()

	fmt.Println(strings.Repeat("-", 16))

	sections := []string{".dynstr", ".rodata", ".rdata",
		".strtab", ".comment", ".note",
		".stab", ".stabstr", ".note.ABI-tag", ".note.gnu.build-id"}

	for _, section := range sections {
		ReadSection(r, section)
	}
}

