# DumpStrings

The better `strings` utility for the reverse engineer.

`DumpStrings` will programmatically read an Macho-O (MacOS), ELF (Linux), and PE (Windows) binary's string sections within a given binary.
This is meant to be much like the `strings` UNIX utility, however is purpose built for Mach-O binaries. 

This means that you can get suitable information about the strings within the binary.
This utility also has the functionality to 'demangle' C++ symbols, iterate linked libraries.

This can prove extremely useful for quickly grabbing strings when analysing a binary.

# Building
```
git clone https://github.com/xPaw/DumpStrings
cd DumpStrings
go build
```

# Usage
```
Example: ./DumpStrings --binary=/bin/echo

  -binary string
        the path to the binary you wish to parse
  -demangle
        demangle C++ symbols into their original source identifiers (default true)
  -min-length int
        minimum length of a string (default 4)
  -print-sections
        print all the section names found in the binary
  -sym-length int
        maximum length of a string to filter out when the string contains majority of non a-Z characters (default 10)
  -target string
        the target type of the binary (macho/elf/pe)
```
