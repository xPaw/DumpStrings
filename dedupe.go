package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

type dedupeStep struct {
	refs    []string
	targets []string
	star    bool
}

type dedupeFile struct {
	lines   []string
	mode    fs.FileMode
	changed bool
}

// runDedupe implements `dedupe [-root .] [-dry-run] <config>` and returns the process exit code.
func runDedupe(args []string) int {
	flags := flag.NewFlagSet("dedupe", flag.ContinueOnError)
	root := flags.String("root", ".", "directory the config paths are relative to")
	dryRun := flags.Bool("dry-run", false, "report what would change without writing")

	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: DumpStrings dedupe [-root dir] [-dry-run] <config>")
		flags.PrintDefaults()
	}

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}

		return 2
	}

	if flags.NArg() != 1 {
		flags.Usage()
		return 2
	}

	return dedupeRun(*root, flags.Arg(0), *dryRun, os.Stdout, os.Stderr, nil)
}

// dedupeRun does the work of runDedupe; beforeCheck, when set, runs just before the
// self-check and may modify the loaded files.
func dedupeRun(root, configPath string, dryRun bool, stdout, stderr io.Writer, beforeCheck func(map[string]*dedupeFile)) int {
	conf, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Fprintf(stderr, "dedupe: %v\n", err)
		return 1
	}

	steps, err := parseDedupeConfig(conf)
	if err != nil {
		fmt.Fprintf(stderr, "dedupe: %s: %v\n", configPath, err)
		return 1
	}

	need := map[string]struct{}{}
	needStar := false

	for _, step := range steps {
		needStar = needStar || step.star

		for _, p := range step.refs {
			need[p] = struct{}{}
		}

		for _, p := range step.targets {
			need[p] = struct{}{}
		}
	}

	if needStar {
		found, err := findStringsFiles(root)
		if err != nil {
			fmt.Fprintf(stderr, "dedupe: %v\n", err)
			return 1
		}

		for _, p := range found {
			need[p] = struct{}{}
		}
	}

	files := make(map[string]*dedupeFile, len(need))
	before := map[string]struct{}{}

	for p := range need {
		f, err := loadDedupeFile(root, p)
		if err != nil {
			fmt.Fprintf(stderr, "dedupe: %v\n", err)
			return 1
		}

		if f == nil {
			continue
		}

		files[p] = f

		for _, l := range f.lines {
			before[l] = struct{}{}
		}
	}

	var star []string

	if needStar {
		for p := range files {
			if strings.HasSuffix(p, "_strings.txt") {
				star = append(star, p)
			}
		}

		sort.Strings(star)
	}

	for i, step := range steps {
		applyDedupeStep(i+1, step, star, files, stdout)
	}

	if beforeCheck != nil {
		beforeCheck(files)
	}

	if !unionUnchanged(before, files) {
		fmt.Fprintln(stderr, "dedupe: self-check failed: the set of all lines changed, nothing was written")
		return 2
	}

	if dryRun {
		return 0
	}

	var changed []string

	for p, f := range files {
		if f.changed {
			changed = append(changed, p)
		}
	}

	sort.Strings(changed)

	for _, p := range changed {
		if err := writeDedupeFile(root, p, files[p]); err != nil {
			fmt.Fprintf(stderr, "dedupe: %v\n", err)
			return 1
		}
	}

	return 0
}

// parseDedupeConfig parses the step list. Blank lines separate steps and comment lines are
// ignored entirely, so they neither start nor end a step.
func parseDedupeConfig(data []byte) ([]dedupeStep, error) {
	var steps []dedupeStep
	var cur dedupeStep
	inStep := false

	flush := func() {
		if inStep {
			steps = append(steps, cur)
		}

		cur = dedupeStep{}
		inStep = false
	}

	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		lineNo := i + 1

		if line == "" {
			flush()
			continue
		}

		if line[0] == '#' {
			continue
		}

		keyword, rest, _ := strings.Cut(line, " ")
		if keyword == line {
			keyword, rest, _ = strings.Cut(line, "\t")
		}

		rest = strings.TrimSpace(rest)

		switch keyword {
		case "ref":
			if len(cur.targets) > 0 || cur.star {
				return nil, fmt.Errorf("line %d: ref after target in the same step", lineNo)
			}

			p, err := cleanDedupePath(rest)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}

			cur.refs = append(cur.refs, p)
		case "target":
			if rest == "*" {
				if len(cur.targets) > 0 {
					return nil, fmt.Errorf("line %d: target * mixed with explicit targets", lineNo)
				}

				cur.star = true
			} else {
				if cur.star {
					return nil, fmt.Errorf("line %d: target * mixed with explicit targets", lineNo)
				}

				p, err := cleanDedupePath(rest)
				if err != nil {
					return nil, fmt.Errorf("line %d: %w", lineNo, err)
				}

				cur.targets = append(cur.targets, p)
			}
		default:
			return nil, fmt.Errorf("line %d: unknown keyword %q", lineNo, keyword)
		}

		inStep = true
	}

	flush()

	return steps, nil
}

// cleanDedupePath validates a root-relative slash path and returns its cleaned form.
func cleanDedupePath(p string) (string, error) {
	if p == "" {
		return "", errors.New("missing path")
	}

	if strings.ContainsAny(p, "\\:") || strings.HasPrefix(p, "/") || filepath.IsAbs(p) {
		return "", fmt.Errorf("path %q must be relative and use /", p)
	}

	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return "", fmt.Errorf("path %q must not contain ..", p)
		}
	}

	return path.Clean(p), nil
}

// findStringsFiles lists every *_strings.txt under root as a slash path, skipping .git and node_modules.
func findStringsFiles(root string) ([]string, error) {
	var found []string

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}

			return nil
		}

		if d.Type().IsRegular() && strings.HasSuffix(d.Name(), "_strings.txt") {
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}

			found = append(found, filepath.ToSlash(rel))
		}

		return nil
	})

	return found, err
}

// loadDedupeFile reads a file as a byte-order sorted set of lines. A missing or non-regular file gives nil.
func loadDedupeFile(root, rel string) (*dedupeFile, error) {
	full := filepath.Join(root, filepath.FromSlash(rel))

	info, err := os.Stat(full)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}

		return nil, err
	}

	if !info.Mode().IsRegular() {
		return nil, nil
	}

	data, err := os.ReadFile(full)
	if err != nil {
		return nil, err
	}

	return &dedupeFile{lines: splitDedupeLines(data), mode: info.Mode().Perm()}, nil
}

// splitDedupeLines splits on \n, drops the trailing empty element and returns sorted unique lines.
func splitDedupeLines(data []byte) []string {
	lines := make([]string, 0, bytes.Count(data, []byte{'\n'})+1)

	for len(data) > 0 {
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			lines = append(lines, string(data))
			break
		}

		lines = append(lines, string(data[:i]))
		data = data[i+1:]
	}

	slices.Sort(lines)

	return slices.Compact(lines)
}

// applyDedupeStep removes the union of the step's reference lines from every target that is not a reference of the step.
func applyDedupeStep(n int, step dedupeStep, star []string, files map[string]*dedupeFile, stdout io.Writer) {
	isRef := make(map[string]struct{}, len(step.refs))
	union := map[string]struct{}{}
	present := make([]string, 0, len(step.refs))

	for _, p := range step.refs {
		isRef[p] = struct{}{}

		f := files[p]
		if f == nil {
			fmt.Fprintf(stdout, "::warning::Dedupe file not found: %s\n", p)
			continue
		}

		present = append(present, p)

		for _, l := range f.lines {
			union[l] = struct{}{}
		}
	}

	targetsChanged := 0
	removed := 0

	if len(present) > 0 {
		targets := step.targets
		if step.star {
			targets = star
		}

		for _, p := range targets {
			f := files[p]
			if f == nil {
				continue
			}

			if _, ok := isRef[p]; ok {
				continue
			}

			kept := f.lines[:0]

			for _, l := range f.lines {
				if _, hit := union[l]; !hit {
					kept = append(kept, l)
				}
			}

			if d := len(f.lines) - len(kept); d > 0 {
				targetsChanged++
				f.changed = true
				removed += d
			}

			f.lines = kept
		}
	}

	fmt.Fprintf(stdout, "step %d: refs [%s], %d targets changed, %d lines removed\n", n, strings.Join(present, ", "), targetsChanged, removed)
}

// unionUnchanged reports whether the set of all lines over every loaded file still equals before.
func unionUnchanged(before map[string]struct{}, files map[string]*dedupeFile) bool {
	after := make(map[string]struct{}, len(before))

	for _, f := range files {
		for _, l := range f.lines {
			if _, ok := before[l]; !ok {
				return false
			}

			after[l] = struct{}{}
		}
	}

	return len(after) == len(before)
}

// writeDedupeFile replaces the file through a temporary file in the same directory.
func writeDedupeFile(root, rel string, f *dedupeFile) error {
	full := filepath.Join(root, filepath.FromSlash(rel))
	tmp := full + ".tmp"

	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.mode)
	if err != nil {
		return err
	}

	w := bufio.NewWriterSize(out, 1<<20)

	for _, l := range f.lines {
		w.WriteString(l)
		w.WriteByte('\n')
	}

	err = w.Flush()

	if cerr := out.Close(); err == nil {
		err = cerr
	}

	if err == nil {
		err = os.Rename(tmp, full)
	}

	if err != nil {
		os.Remove(tmp)
	}

	return err
}
