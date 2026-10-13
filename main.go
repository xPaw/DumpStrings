package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	var opts Options

	binaryPath := flag.String("binary", "", "the path to the binary you wish to parse")
	flag.StringVar(&opts.Format, "target", "", "the target type of the binary (macho/elf/pe)")
	flag.BoolVar(&opts.Demangle, "demangle", true, "demangle C++ symbols into their original source identifiers")
	flag.IntVar(&opts.MinLength, "min-length", 4, "minimum length of a string")
	flag.IntVar(&opts.SymLength, "sym-length", 10, "maximum length of a string to filter out when the string contains majority of non a-Z characters")
	flag.BoolVar(&opts.PrintSections, "print-sections", false, "print every section with its type, flags, address, size and how it is read")
	flag.Parse()

	if *binaryPath == "" {
		flag.PrintDefaults()
		return
	}

	out := bufio.NewWriterSize(os.Stdout, 1<<16)
	err := run(*binaryPath, opts, out)

	if flushErr := out.Flush(); err == nil {
		err = flushErr
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", *binaryPath, err)
		os.Exit(1)
	}
}

// run dumps one file to out. A panic while parsing or dumping is returned as
// an error.
func run(path string, opts Options, out *bufio.Writer) (err error) {
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
		fmt.Fprintf(os.Stderr, "%s: warning: %s\n", path, fmt.Sprintf(format, args...))
	}

	b, err := Parse(data, opts.Format, warn)
	if err != nil {
		return err
	}

	if opts.PrintSections {
		PrintSections(out, b)
		return nil
	}

	d := Dumper{opts: opts, sink: lineSink(out)}
	d.Dump(b)

	return nil
}

// lineSink returns a sink that writes each line to w followed by a newline.
func lineSink(w io.StringWriter) Sink {
	return func(line string) {
		w.WriteString(line)
		w.WriteString("\n")
	}
}
