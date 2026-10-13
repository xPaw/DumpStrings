# DumpStrings

The better `strings` utility for reverse engineers.

`DumpStrings` programmatically extracts strings from Mach-O (macOS), ELF (Linux), and PE (Windows) binary formats by parsing their string-containing sections. Unlike the traditional UNIX `strings` utility that scans the entire file, DumpStrings intelligently targets specific sections known to contain string data, providing more relevant results for binary analysis.

## Features

- **Multi-format support**: Handles Mach-O (including fat binaries), ELF, and PE binary formats with automatic format detection
- **Section-aware parsing**: Targets specific sections containing strings rather than scanning entire files
- **C++ symbol demangling**: Automatically converts mangled C++ symbols back to readable form
- **Intelligent filtering**: Configurable filters for string length, symbol-heavy content, embedded protobuf descriptors and non-terminated data
- **Section enumeration**: View all available sections in a binary for analysis
- **Tracker helpers**: `dedupe` and `fix-encoding` subcommands for repositories that keep `*_strings.txt` dumps

## Building

```bash
git clone https://github.com/xPaw/DumpStrings
cd DumpStrings
go build
```

## Usage

```
DumpStrings dump [flags] <binary>
DumpStrings dedupe [-root .] [-dry-run] <config>
DumpStrings fix-encoding [-ext txt,...] <path>...
DumpStrings version
```

Run `DumpStrings <command> -h` for the flags of a command.

### dump

```bash
# Extract strings (format is auto-detected)
./DumpStrings dump /bin/echo

# Sorted unique lines, same as piping through LC_ALL=C sort -u
./DumpStrings dump -sort /bin/echo

# Force the format
./DumpStrings dump -format=elf /bin/echo

# Show all sections in a binary and how they are read
./DumpStrings dump -print-sections /bin/echo

# Longer strings only, no demangling
./DumpStrings dump -min-length=10 -demangle=false /bin/echo
```

| Flag | Default | Description |
|------|---------|-------------|
| `-format` | `auto` | Binary format: `auto`, `pe`, `elf` or `macho` |
| `-min-length` | `4` | Minimum length of a string to include in output |
| `-sym-length` | `10` | Strings up to this length that are mostly non-alphanumeric are dropped |
| `-demangle` | `true` | Demangle C++ symbols into their original source identifiers |
| `-protobufs` | `mask` | `mask` blanks serialized protobuf descriptors, `keep` reads them as ordinary data |
| `-terminated` | `auto` | End-of-string rule for data sections: `auto`, `on` or `off` |
| `-sort` | `false` | Print byte-order sorted unique lines instead of section order |
| `-print-sections` | `false` | Print every section with its type, address, size and how it is read, then exit |

Output is one string per line with `\t`, `\v`, `\n`, `\r` and `\f` escaped. Without `-sort`, lines come in section order; for a fat Mach-O every architecture is printed in turn, and `-sort` merges them.

Two filters remove noise that plain `strings` would print:

- **Protobuf masking**: serialized `FileDescriptorProto` blobs (they start with a `*.proto` file name) are blanked before extraction. Use `-protobufs=keep` to read them as ordinary data.
- **End-of-string rule**: in data sections (PE `.data`/`.rdata`, ELF `.rodata`/`.data`, Mach-O `__const`/`__data`) a run is kept only if a NUL byte follows it, it ends the section, or it sits inside text. This drops fragments of binary data that look like text. `auto` turns the rule off for Go and Rust binaries, whose strings are not NUL-terminated (a note is printed on stderr); use `-terminated=off` to disable it everywhere or `on` to force it.

Exit codes: `0` success, `1` the file is unreadable, unsupported, fails to parse or has no readable sections, `2` usage error (usage is printed on stderr). Problems with a single section, such as truncation, are warnings on stderr and the readable bytes are still dumped. `-h` prints usage and exits `0`.

### dedupe

Removes lines that already appear in reference files from the `*_strings.txt` files in a tree, so a statically linked library shows up in one file only.

```
# strings_dedupe.conf
# A blank line ends a step; steps run in order.
ref game/bin/win64/engine2_strings.txt
ref game/bin/win64/tier0_strings.txt
ref DumpSource2/.stringsignore
target *

ref game/bin/win64/toolframework2_strings.txt
target game/bin/win64/hammer_strings.txt
target game/bin/win64/assetbrowser_strings.txt
```

```bash
./DumpStrings dedupe -root path/to/repo path/to/repo/strings_dedupe.conf
```

- `ref` lines name files whose lines are removed from the targets; they are never modified. `target *` means every `*_strings.txt` under the root (skipping `.git` and `node_modules`); `ref` lines must come before `target` lines, and `target *` cannot be mixed with explicit targets. Paths are relative to `-root`, use `/` and may not contain `..`.
- A missing `ref` prints `::warning::Dedupe file not found: <path>` and is skipped; a missing explicit target is skipped silently.
- Only changed files are rewritten, in byte-order sorted order. The set of all lines is checked to be unchanged before anything is written.
- `-dry-run` reports what would change without writing.
- Exit codes: `0` success, `1` unreadable or invalid config, `2` the self-check failed (nothing written) or a usage error.

### fix-encoding

Converts UTF-16 and UTF-32 text files (detected by BOM) to UTF-8, trims surrounding whitespace and ends the file with a single newline. Files that need no change are left alone.

```bash
./DumpStrings fix-encoding -ext txt,xml,cfg path/to/dir other.txt
```

Directories are walked recursively (skipping `.git` and `node_modules`) and files are picked by `-ext` (default `txt`, case-sensitive); files named directly are always processed. Problems with a single file are warnings on stderr. Exit codes: `0` success, `1` an argument path does not exist, `2` usage error.

### version

Prints `DumpStrings <version>` on the first line (the module version, else the VCS revision, else `(devel)`) and the Go version on the second.
