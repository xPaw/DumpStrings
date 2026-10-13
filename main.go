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
	"slices"
	"sort"
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
		return runDedupe(args[1:])
	case "fix-encoding":
		return runFixEncoding(args[1:])
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

// runDump implements `dump [flags] <binary>` and returns the exit code.
func runDump(args []string, stdout, stderr io.Writer) int {
	var opts Options

	flags := flag.NewFlagSet("dump", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: DumpStrings dump [flags] <binary>")
		flags.PrintDefaults()
	}

	format := flags.String("format", "auto", "binary format: auto, pe, elf or macho")
	flags.BoolVar(&opts.Demangle, "demangle", true, "demangle C++ symbols into their original source identifiers")
	flags.IntVar(&opts.MinLength, "min-length", 4, "minimum length of a string")
	flags.IntVar(&opts.SymLength, "sym-length", 10, "maximum length of a string to filter out when the string contains majority of non a-Z characters")
	flags.BoolVar(&opts.PrintSections, "print-sections", false, "print every section with its type, flags, address, size and how it is read")
	flags.BoolVar(&opts.MaskProtobufs, "mask-protobufs", false, "blank serialized protobuf descriptors (.proto file descriptors embedded by protoc) before extracting strings")
	flags.StringVar(&opts.Terminated, "terminated", "auto", "keep only data section strings that end in a NUL byte or lie in text: auto (off for Go and Rust binaries), on or off")
	sorted := flags.Bool("sort", false, "print byte-order sorted unique lines instead of section order")

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		return 2
	}

	usageError := func(format string, a ...any) int {
		fmt.Fprintf(stderr, format, a...)
		flags.Usage()

		return 2
	}

	switch *format {
	case "auto":
	case "pe", "elf", "macho":
		opts.Format = *format
	default:
		return usageError("invalid -format value %q: want auto, pe, elf or macho\n", *format)
	}

	if opts.Terminated != "auto" && opts.Terminated != "on" && opts.Terminated != "off" {
		return usageError("invalid -terminated value %q: want auto, on or off\n", opts.Terminated)
	}

	if flags.NArg() != 1 {
		return usageError("dump takes exactly one binary, got %d arguments\n", flags.NArg())
	}

	path := flags.Arg(0)
	out := bufio.NewWriterSize(stdout, 1<<16)
	err := run(path, opts, *sorted, out, stderr)

	if flushErr := out.Flush(); err == nil {
		err = flushErr
	}

	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", path, err)
		return 1
	}

	return 0
}

// run dumps one file to out, sorted and deduplicated when sorted is set. A
// panic while parsing or dumping is returned as an error.
func run(path string, opts Options, sorted bool, out *bufio.Writer, stderr io.Writer) (err error) {
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

	b, err := Parse(data, opts.Format, warn)
	if err != nil {
		return err
	}

	if opts.PrintSections {
		PrintSections(out, b)
		return nil
	}

	// Masking blanks bytes of data in place, so the markers are looked up
	// before dumping.
	terminated, toolchain := ResolveTerminated(opts.Terminated, data)
	if toolchain != "" {
		fmt.Fprintf(stderr, "%s: note: %s binary, end-of-string rule off\n", path, toolchain)
	}

	sink := lineSink(out)

	var lines []string

	if sorted {
		sink = func(line string) { lines = append(lines, line) }
	}

	d := Dumper{opts: opts, sink: sink, terminated: terminated}
	d.Dump(b)

	if sorted {
		sort.Strings(lines)

		for _, line := range slices.Compact(lines) {
			out.WriteString(line)
			out.WriteString("\n")
		}
	}

	return nil
}

// lineSink returns a sink that writes each line to w followed by a newline.
func lineSink(w io.StringWriter) Sink {
	return func(line string) {
		w.WriteString(line)
		w.WriteString("\n")
	}
}
