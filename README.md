# DumpStrings

The better `strings` utility for reverse engineers.

`DumpStrings` programmatically extracts strings from Mach-O (macOS), ELF (Linux), and PE (Windows) binary formats. It parses their string-containing sections. The traditional UNIX `strings` utility scans the entire file. DumpStrings targets specific sections known to contain string data. This gives more relevant results for binary analysis.

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
| `-mask-protobufs` | `false` | Blank serialized protobuf descriptors (.proto file descriptors embedded by protoc) before extracting strings |
| `-terminated` | `auto` | End-of-string rule for data sections: `auto`, `on` or `off` |
| `-sort` | `false` | Print byte-order sorted unique lines instead of section order |
| `-print-sections` | `false` | Print every section with its type, address, size and how it is read, then exit |

Output is one string per line with `\t`, `\v`, `\n`, `\r` and `\f` escaped. Without `-sort`, lines come in section order. For a fat Mach-O, DumpStrings prints every architecture in turn, and `-sort` merges them.

These filters remove noise that plain `strings` would print, the first of them opt-in:

- **Protobuf masking** (`-mask-protobufs`, off by default): serialized `FileDescriptorProto` blobs (they start with a `*.proto` file name) are blanked before extraction. Without the flag they are read as ordinary data.
- **Unwind data** (x86-64 PE): the exception unwind data that the exception directory lists is blanked. This is because its bytes form short lines that change with every build. The whole span from the first unwind info to the end of the last is blanked when nothing refers into it and unwind infos fill at least half of it. This also blanks the handler data between the unwind infos. Otherwise only the unwind infos are blanked.
- **Relocated pointers** (PE): the addresses that base relocations patch are blanked. These bytes are never text. But 64-bit executables load at `0x140000000`, so the low bytes of a pointer can form lines like `036@` that change with every build. The NUL bytes of a pointer stay. Each other byte becomes a byte that is neither NUL nor text, so a constant just before a pointer does not get a terminator.
- **Constant prefixes** (PE): compilers align string literals to 4 bytes. So the printable high bytes of a constant stored just before a string glue onto it (`?CDOTA_Name` for `00 00 80 3F` + `CDOTA_Name`). A run starts at the next 4-byte aligned offset inside it when all of these conditions hold:
  - The run starts off 4-byte alignment.
  - Nothing refers to its start.
  - A base relocation or a RIP-relative `lea` refers to that offset.
- **End-of-string rule**: in data sections, a run is kept only if a NUL byte follows it, it ends the section or it sits inside text. The data sections are PE `.data`/`.rdata`, PE `.text` when a non-.NET PE has no `.rdata`, ELF `.rodata`/`.data` and Mach-O `__const`/`__data`. This drops fragments of binary data that look like text. `auto` turns the rule off for Go and Rust binaries, whose strings are not NUL-terminated. It prints a note on stderr. Use `-terminated=off` to disable the rule everywhere. Use `on` to force it.

Exit codes: `0` success, `1` the file is unreadable, unsupported, fails to parse or has no readable sections, `2` usage error. `-print-sections` still lists the sections of such a file and exits `0`. A usage error prints the usage on stderr. Problems with a single section, such as truncation, are warnings on stderr. DumpStrings still dumps the readable bytes. `-h` prints usage and exits `0`.

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

- `ref` lines name files whose lines are removed from the targets. DumpStrings never modifies these files. `target *` means every `*_strings.txt` under the root (skipping `.git` and `node_modules`). `ref` lines must come before `target` lines. You cannot mix `target *` with explicit targets. Paths are relative to `-root`, use `/` and may not contain `..`.
- A missing `ref` prints `::warning::Dedupe file not found: <path>`, and DumpStrings skips it. DumpStrings skips a missing explicit target silently.
- DumpStrings rewrites only changed files, in byte-order sorted order. Before it writes anything, it checks that the set of all lines is unchanged.
- `-dry-run` reports what would change without writing.
- Exit codes: `0` success, `1` unreadable or invalid config, `2` usage error, `3` the self-check failed (nothing written).

### fix-encoding

Converts UTF-16 and UTF-32 text files (detected by BOM) to UTF-8, trims surrounding whitespace and ends the file with a single newline. It leaves files that need no change alone.

```bash
./DumpStrings fix-encoding -ext txt,xml,cfg path/to/dir other.txt
```

DumpStrings walks directories recursively (skipping `.git` and `node_modules`) and picks files by `-ext` (default `txt`, case-sensitive). It always processes files named directly. Problems with a single file are warnings on stderr. Exit codes: `0` success, `1` an argument path does not exist, `2` usage error.

### version

Prints `DumpStrings <version>` on the first line (the module version, else the VCS revision, else `(devel)`) and the Go version on the second.
