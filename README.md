# DumpStrings

The better `strings` utility for reverse engineers.

`DumpStrings` programmatically extracts strings from Mach-O (macOS), ELF (Linux), and PE (Windows) binary formats by parsing their string-containing sections. Unlike the traditional UNIX `strings` utility that scans the entire file, DumpStrings intelligently targets specific sections known to contain string data, providing more relevant results for binary analysis.

## Features

- **Multi-format support**: Handles Mach-O, ELF, and PE binary formats with automatic format detection
- **Section-aware parsing**: Targets specific sections containing strings rather than scanning entire files
- **C++ symbol demangling**: Automatically converts mangled C++ symbols back to readable form
- **Intelligent filtering**: Configurable filters for string length and symbol-heavy content
- **Section enumeration**: View all available sections in a binary for analysis

## Building

```bash
git clone https://github.com/xPaw/DumpStrings
cd DumpStrings
go build
```

## Usage

### Basic Usage

```bash
# Extract strings (format is auto-detected)
./DumpStrings --binary=/bin/echo

# Explicitly specify target format
./DumpStrings --binary=/bin/echo --target=elf
./DumpStrings --binary=/usr/bin/ls --target=macho
./DumpStrings --binary=program.exe --target=pe
```

### Advanced Options

```bash
# Show all available sections in a binary
./DumpStrings --binary=/bin/echo --print-sections

# Extract longer strings only (minimum 10 characters)
./DumpStrings --binary=/bin/echo --min-length=10

# Disable C++ symbol demangling
./DumpStrings --binary=/bin/echo --demangle=false

# Adjust symbol filtering (strings with mostly symbols, max 5 chars)
./DumpStrings --binary=/bin/echo --sym-length=5
```

## Command Line Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--binary` | string | | Path to the binary you wish to parse (required) |
| `--target` | string | | Target binary type: `macho`, `elf`, or `pe` (auto-detected if omitted) |
| `--demangle` | bool | true | Demangle C++ symbols into their original source identifiers |
| `--min-length` | int | 4 | Minimum length of a string to include in output |
| `--sym-length` | int | 10 | Maximum length for strings containing majority non-alphanumeric characters |
| `--print-sections` | bool | false | Print all section names found in the binary and exit |

## Output

DumpStrings outputs one string per line, with special characters escaped (e.g., `\n`, `\t`, `\r`). When demangling is enabled, C++ mangled symbols are automatically converted to their readable form.
