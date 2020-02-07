# macho-strings

The better `strings` utility for the reverse engineer.

`macho-strings` will programmatically read an Macho-O/DWARF/MacOS binary's string sections within a given binary.
This is meant to be much like the `strings` UNIX utility, however is purpose built for Mach-O binaries. 

This means that you can get suitable information about the strings within the binary.
This utility also has the functionality to 'demangle' C++ symbols, iterate linked libraries.

This can prove extremely useful for quickly grabbing strings when analysing a binary.

# Building
```
git clone https://github.com/xPaw/macho-strings
cd macho-strings
go build
```

# Usage
```
Example: ./macho-strings --binary=/bin/echo

  -binary string
        the path to the Mach-O you wish to parse
  -demangle
        demangle C++ symbols into their original source identifiers (default true)
  -no-human
        don't validate that its a human readable string, this increases the amount of junk
  -no-trim
        disable triming whitespace and trailing newlines
```
