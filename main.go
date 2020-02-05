package main

import (
	"flag"
	"fmt"
	"log"
	"strings"

	"github.com/shawnsmithdev/zermelo"
)

var (
	demangleOpt = flag.Bool("demangle", true, "demangle C++ symbols into their original source identifiers, prettify found C++ symbols (optional)")
	binaryOpt   = flag.String("binary", "", "the path to the ELF you wish to parse")
	minOpt      = flag.Uint64("min", 0, "the minimum length of the string")
	trimOpt     = flag.Bool("no-trim", false, "disable triming whitespace and trailing newlines")
	humanOpt    = flag.Bool("no-human", false, "don't validate that its a human readable string, this could increase the amount of junk.")
)

// ReadSection is the main logic here
// it combines all of the modules, etc.
func ReadSection(reader *ElfReader, section string) {
	var err error
	var count uint64

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

		err = zermelo.Sort(keys)
		if err != nil {
			return
		}

		keys = UtilUniqueSlice(keys)

		for _, off := range keys {
			str := string(nodes[off])
			if uint64(len(str)) < *minOpt {
				continue
			}

			if !*humanOpt {
				if !UtilIsNice(str) {
					continue
				}
			}

			str = strings.TrimSpace(str)

			if !*trimOpt {
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

			count++
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

