# elf-strings

The better `strings` utility for the reverse engineer.

`elf-strings` will programmatically read an ELF binary's string sections within a given binary.
This is meant to be much like the `strings` UNIX utility, however is purpose built for ELF binaries. 

This means that you can get suitable information about the strings within the binary.
This utility also has the functionality to 'demangle' C++ symbols, iterate linked libraries.

This can prove extremely useful for quickly grabbing strings when analysing a binary.

# Building
```
git clone https://github.com/xPaw/elf-strings
cd elf-strings
go build
```

# Usage
```
Example: ./elf-strings --binary=/bin/echo

  -binary string
        the path to the ELF you wish to parse
  -demangle
        demangle C++ symbols into their original source identifiers (default true)
  -no-human
        don't validate that its a human readable string, this increases the amount of junk
  -no-trim
        disable triming whitespace and trailing newlines
```
