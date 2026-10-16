package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
)

const usageText = `Usage: DumpStrings <command> [arguments]

Commands:
  dump          extract strings from a PE, ELF or Mach-O binary
  dedupe        remove lines shared with reference files from *_strings.txt files
  fix-encoding  convert UTF-16 and UTF-32 text files to UTF-8
  version       print the version

Run "DumpStrings <command> -h" for the flags of a command.
`

func main() {
	os.Exit(runMain(os.Args[1:], os.Stdout, os.Stderr))
}

// runMain dispatches a subcommand and returns the process exit code.
func runMain(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usageText)
		return 2
	}

	switch args[0] {
	case "dump":
		return runDump(args[1:], stdout, stderr)
	case "dedupe":
		return runDedupe(args[1:], stdout, stderr)
	case "fix-encoding":
		return runFixEncoding(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "DumpStrings %s\n%s\n", buildVersion(), runtime.Version())
		return 0
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stderr, usageText)
		return 0
	}

	fmt.Fprintf(stderr, "DumpStrings: unknown command %q\n\n%s", args[0], usageText)

	return 2
}

// buildVersion returns the module version, else the VCS revision the binary
// was built from, else "(devel)".
func buildVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "(devel)"
	}

	if v := info.Main.Version; v != "" && v != "(devel)" {
		return v
	}

	revision, modified := "", false

	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}

	if revision == "" {
		return "(devel)"
	}

	if len(revision) > 12 {
		revision = revision[:12]
	}

	if modified {
		revision += "-dirty"
	}

	return revision
}

// newFlagSet returns the flag set of a subcommand. Its usage function prints
// the usage line and then the flag defaults to stderr.
func newFlagSet(name, usage string, stderr io.Writer) *flag.FlagSet {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, usage)
		flags.PrintDefaults()
	}

	return flags
}

// parseFlags parses the flags of a subcommand. If parsing ends the command, it
// returns false and the exit code: 0 for -h, 2 for a bad flag.
func parseFlags(flags *flag.FlagSet, args []string) (int, bool) {
	err := flags.Parse(args)

	switch {
	case err == nil:
		return 0, true
	case errors.Is(err, flag.ErrHelp):
		return 0, false
	}

	return 2, false
}

// dumpConfig holds the dump flags that choose how the file is parsed and how
// its lines are printed.
type dumpConfig struct {
	format        string
	terminated    string
	printSections bool
	sorted        bool
}

// runDump implements `dump [flags] <binary>` and returns the exit code.
func runDump(args []string, stdout, stderr io.Writer) int {
	var opts Options
	var cfg dumpConfig

	flags := newFlagSet("dump", "Usage: DumpStrings dump [flags] <binary>", stderr)
	flags.StringVar(&cfg.format, "format", "auto", "binary format: auto, pe, elf or macho")
	flags.BoolVar(&opts.Demangle, "demangle", true, "demangle C++ symbols into their original source identifiers")
	flags.IntVar(&opts.MinLength, "min-length", 4, "minimum length of a string")
	flags.IntVar(&opts.SymLength, "sym-length", 10, "maximum length of a string that is dropped when most of its characters are not a-Z")
	flags.BoolVar(&cfg.printSections, "print-sections", false, "print every section with its type, flags, address, size and how it is read")
	flags.BoolVar(&opts.MaskProtobufs, "mask-protobufs", false, "blank serialized protobuf descriptors (.proto file descriptors embedded by protoc) before extracting strings")
	flags.StringVar(&cfg.terminated, "terminated", "auto", "keep only data section strings that end in a NUL byte or lie in text: auto (off for Go and Rust binaries), on or off")
	flags.BoolVar(&cfg.sorted, "sort", false, "print byte-order sorted unique lines instead of section order")

	if code, ok := parseFlags(flags, args); !ok {
		return code
	}

	usageError := func(format string, a ...any) int {
		fmt.Fprintf(stderr, format, a...)
		flags.Usage()

		return 2
	}

	switch cfg.format {
	case "auto", "pe", "elf", "macho":
	default:
		return usageError("invalid -format value %q: must be auto, pe, elf or macho\n", cfg.format)
	}

	switch cfg.terminated {
	case "auto", "on", "off":
	default:
		return usageError("invalid -terminated value %q: must be auto, on or off\n", cfg.terminated)
	}

	if flags.NArg() != 1 {
		return usageError("dump takes exactly one binary but got %d arguments\n", flags.NArg())
	}

	path := flags.Arg(0)
	out := bufio.NewWriterSize(stdout, 1<<16)
	err := run(path, opts, cfg, out, stderr)

	if flushErr := out.Flush(); err == nil {
		err = flushErr
	}

	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", path, err)
		return 1
	}

	return 0
}

// run dumps one file to out. When cfg.sorted is set, it sorts the lines and
// removes duplicates. It returns a panic while parsing or dumping as an error.
func run(path string, opts Options, cfg dumpConfig, out *bufio.Writer, stderr io.Writer) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic: %v", r)
		}
	}()

	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	warn := func(format string, args ...any) {
		fmt.Fprintf(stderr, "%s: warning: %s\n", path, fmt.Sprintf(format, args...))
	}

	b, err := Parse(data, cfg.format, warn)
	if err != nil {
		return err
	}

	if cfg.printSections {
		PrintSections(out, b)
		return nil
	}

	if !b.Readable {
		return errors.New("no readable sections")
	}

	terminated, toolchain := ResolveTerminated(cfg.terminated, data)
	if toolchain != "" {
		fmt.Fprintf(stderr, "%s: note: %s binary, end-of-string rule off\n", path, toolchain)
	}

	opts.Terminated = terminated

	emit := func(line string) {
		out.WriteString(line)
		out.WriteString("\n")
	}

	var lines []string

	sink := emit
	if cfg.sorted {
		sink = func(line string) { lines = append(lines, line) }
	}

	d := Dumper{opts: opts, sink: sink}
	d.Dump(b)

	for _, line := range sortedUnique(lines) {
		emit(line)
	}

	return nil
}
