package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// stringsFileSuffix ends the name of every file `target *` selects.
const stringsFileSuffix = "_strings.txt"

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

// dedupeJob is a parsed config with every file its steps read or change.
type dedupeJob struct {
	steps []dedupeStep

	// star lists the loaded *_strings.txt files in order, for `target *`.
	star []string

	files map[string]*dedupeFile

	// before is the set of all lines over every loaded file.
	before map[string]struct{}
}

// runDedupe implements `dedupe [-root .] [-dry-run] <config>` and returns the process exit code.
func runDedupe(args []string, stdout, stderr io.Writer) int {
	flags := newFlagSet("dedupe", "Usage: DumpStrings dedupe [-root dir] [-dry-run] <config>", stderr)
	root := flags.String("root", ".", "directory the config paths are relative to")
	dryRun := flags.Bool("dry-run", false, "report what would change without writing")

	if code, ok := parseFlags(flags, args); !ok {
		return code
	}

	if flags.NArg() != 1 {
		flags.Usage()
		return 2
	}

	return dedupeRun(*root, flags.Arg(0), *dryRun, stdout, stderr)
}

// dedupeRun does the work of runDedupe.
func dedupeRun(root, configPath string, dryRun bool, stdout, stderr io.Writer) int {
	job, err := loadDedupeJob(root, configPath)
	if err != nil {
		return dedupeFail(stderr, err)
	}

	return job.run(root, dryRun, stdout, stderr)
}

// dedupeFail reports err and returns the exit code of a failed run.
func dedupeFail(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "dedupe: %v\n", err)
	return 1
}

// run applies the steps and, unless dryRun is set or the self-check fails,
// writes the changed files under root. It returns the process exit code.
func (job *dedupeJob) run(root string, dryRun bool, stdout, stderr io.Writer) int {
	job.apply(stdout)

	if !job.unchanged() {
		fmt.Fprintln(stderr, "dedupe: self-check failed: the set of all lines changed, nothing was written")
		return 3
	}

	if dryRun {
		return 0
	}

	if err := job.write(root); err != nil {
		return dedupeFail(stderr, err)
	}

	return 0
}

// loadDedupeJob parses the config and loads every file its steps name, and
// every *_strings.txt under root when a step targets them all.
func loadDedupeJob(root, configPath string) (*dedupeJob, error) {
	conf, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	steps, err := parseDedupeConfig(conf)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", configPath, err)
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
			return nil, err
		}

		for _, p := range found {
			need[p] = struct{}{}
		}
	}

	job := &dedupeJob{
		steps:  steps,
		files:  make(map[string]*dedupeFile, len(need)),
		before: map[string]struct{}{},
	}

	for p := range need {
		f, err := loadDedupeFile(root, p)
		if err != nil {
			return nil, err
		}

		if f == nil {
			continue
		}

		job.files[p] = f

		for _, l := range f.lines {
			job.before[l] = struct{}{}
		}
	}

	if needStar {
		for p := range job.files {
			if strings.HasSuffix(p, stringsFileSuffix) {
				job.star = append(job.star, p)
			}
		}

		sort.Strings(job.star)
	}

	return job, nil
}

// apply runs every step in order and reports each one to stdout.
func (job *dedupeJob) apply(stdout io.Writer) {
	for i, step := range job.steps {
		applyDedupeStep(i+1, step, job.star, job.files, stdout)
	}
}

// unchanged reports whether the set of all lines over every loaded file still
// equals the set before the steps ran.
func (job *dedupeJob) unchanged() bool {
	after := make(map[string]struct{}, len(job.before))

	for _, f := range job.files {
		for _, l := range f.lines {
			if _, ok := job.before[l]; !ok {
				return false
			}

			after[l] = struct{}{}
		}
	}

	return len(after) == len(job.before)
}

// write replaces every changed file, in path order.
func (job *dedupeJob) write(root string) error {
	var changed []string

	for p, f := range job.files {
		if f.changed {
			changed = append(changed, p)
		}
	}

	sort.Strings(changed)

	for _, p := range changed {
		f := job.files[p]

		var data bytes.Buffer

		for _, l := range f.lines {
			data.WriteString(l)
			data.WriteByte('\n')
		}

		if err := replaceFile(filepath.Join(root, filepath.FromSlash(p)), data.Bytes(), f.mode); err != nil {
			return err
		}
	}

	return nil
}

// parseDedupeConfig parses the step list. Blank lines separate steps and comment lines are
// ignored entirely, so they neither start nor end a step.
func parseDedupeConfig(data []byte) ([]dedupeStep, error) {
	var steps []dedupeStep
	var cur dedupeStep

	flush := func() {
		if len(cur.refs) > 0 || len(cur.targets) > 0 || cur.star {
			steps = append(steps, cur)
		}

		cur = dedupeStep{}
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

		keyword, rest := line, ""
		if sep := strings.IndexAny(line, " \t"); sep >= 0 {
			keyword, rest = line[:sep], strings.TrimSpace(line[sep+1:])
		}

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
			star := rest == "*"
			if (star && len(cur.targets) > 0) || (!star && cur.star) {
				return nil, fmt.Errorf("line %d: target * mixed with explicit targets", lineNo)
			}

			if star {
				cur.star = true
				break
			}

			p, err := cleanDedupePath(rest)
			if err != nil {
				return nil, fmt.Errorf("line %d: %w", lineNo, err)
			}

			cur.targets = append(cur.targets, p)
		default:
			return nil, fmt.Errorf("line %d: unknown keyword %q", lineNo, keyword)
		}
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

	isStrings := func(name string) bool { return strings.HasSuffix(name, stringsFileSuffix) }
	stop := func(err error) error { return err }

	err := walkFiles(root, isStrings, func(p string) error {
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}

		found = append(found, filepath.ToSlash(rel))

		return nil
	}, stop)

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
// The lines share one copy of data.
func splitDedupeLines(data []byte) []string {
	s := string(data)
	lines := make([]string, 0, strings.Count(s, "\n")+1)

	for len(s) > 0 {
		i := strings.IndexByte(s, '\n')
		if i < 0 {
			lines = append(lines, s)
			break
		}

		lines = append(lines, s[:i])
		s = s[i+1:]
	}

	return sortedUnique(lines)
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
