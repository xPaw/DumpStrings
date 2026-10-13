package main

import (
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// writeConf writes a dedupe config to a temporary file and returns its path.
func writeConf(t *testing.T, conf string) string {
	t.Helper()

	return filepath.Join(writeTree(t, map[string]string{"strings_dedupe.conf": conf}), "strings_dedupe.conf")
}

func runConf(t *testing.T, root, conf string, dry bool) (int, string, string) {
	t.Helper()

	var out, errOut bytes.Buffer
	code := dedupeRun(root, writeConf(t, conf), dry, &out, &errOut)

	return code, out.String(), errOut.String()
}

func TestParseErrors(t *testing.T) {
	bad := map[string]string{
		"ref after target":       "ref a\ntarget b\nref c\n",
		"ref after star":         "target *\nref c\n",
		"star after explicit":    "ref a\ntarget b\ntarget *\n",
		"explicit after star":    "ref a\ntarget *\ntarget b\n",
		"unknown keyword":        "ref a\nsource b\n",
		"dotdot":                 "ref a/../../b\ntarget *\n",
		"dotdot target":          "ref a\ntarget ../b\n",
		"absolute":               "ref /etc/passwd\n",
		"windows absolute":       "ref C:/x\n",
		"backslash":              "ref a\\b\n",
		"missing path":           "ref\n",
		"keyword without space":  "refa\n",
		"keyword case sensitive": "REF a\n",
	}

	for name, conf := range bad {
		if _, err := parseDedupeConfig([]byte(conf)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}

	root := t.TempDir()
	var out, errOut bytes.Buffer

	if code := dedupeRun(root, filepath.Join(root, "missing.conf"), false, &out, &errOut); code != 1 {
		t.Errorf("unreadable config: exit %d, want 1", code)
	}

	code, _, _ := runConf(t, root, "ref a\ntarget b\nref c\n", false)
	if code != 1 {
		t.Errorf("bad config: exit %d, want 1", code)
	}

	steps, err := parseDedupeConfig([]byte("ref\ta\ntarget *\ntarget *\n"))
	if err != nil || len(steps) != 1 || steps[0].refs[0] != "a" || !steps[0].star {
		t.Errorf("tab separator and repeated target *: %+v %v", steps, err)
	}
}

func TestParseSteps(t *testing.T) {
	conf := "# header\n\n\nref a\n# comment inside\nref b\n\n# between\n\ntarget x\n"
	_, err := parseDedupeConfig([]byte(conf))
	if err != nil {
		t.Fatalf("a blank line must end the step: %v", err)
	}

	steps, err := parseDedupeConfig([]byte("ref a\r\n# c\r\nref b\r\ntarget *\r\n\r\n\r\nref c\r\ntarget d\r\ntarget e\r\n"))
	if err != nil {
		t.Fatal(err)
	}

	if len(steps) != 2 || len(steps[0].refs) != 2 || !steps[0].star || len(steps[1].targets) != 2 {
		t.Fatalf("unexpected steps: %+v", steps)
	}

	steps, err = parseDedupeConfig([]byte("ref a\n# comment\ntarget b\n"))
	if err != nil || len(steps) != 1 || len(steps[0].targets) != 1 {
		t.Fatalf("a comment must not end a step: %+v %v", steps, err)
	}
}

func TestOrderingSemantics(t *testing.T) {
	root := writeTree(t, map[string]string{
		"engine_strings.txt": "a\nb\n",
		"mod_strings.txt":    "b\nc\nd\n",
		"tool_strings.txt":   "a\nc\ne\n",
		"other_strings.txt":  "a\nd\nz\n",
	})

	conf := "ref engine_strings.txt\ntarget *\n\nref mod_strings.txt\ntarget tool_strings.txt\ntarget engine_strings.txt\n"
	code, out, errOut := runConf(t, root, conf, false)

	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}

	want := map[string]string{
		"engine_strings.txt": "a\nb\n",
		"mod_strings.txt":    "c\nd\n",
		"tool_strings.txt":   "e\n",
		"other_strings.txt":  "d\nz\n",
	}

	for name, content := range want {
		if got := readTree(t, root, name); got != content {
			t.Errorf("%s: got %q want %q", name, got, content)
		}
	}

	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "3 targets changed, 3 lines removed") || !strings.Contains(lines[1], "1 targets changed, 1 lines removed") {
		t.Errorf("unexpected output:\n%s", out)
	}
}

func TestSharedLineKeptInEarlierRef(t *testing.T) {
	root := writeTree(t, map[string]string{
		"r1_strings.txt": "x\ny\n",
		"r2_strings.txt": "y\nz\n",
		"t_strings.txt":  "x\ny\nz\nw\n",
	})

	conf := "ref r1_strings.txt\ntarget r2_strings.txt\ntarget t_strings.txt\n\nref r2_strings.txt\ntarget t_strings.txt\n"

	if code, _, errOut := runConf(t, root, conf, false); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}

	if got := readTree(t, root, "r2_strings.txt"); got != "z\n" {
		t.Errorf("r2: %q", got)
	}

	if got := readTree(t, root, "t_strings.txt"); got != "w\n" {
		t.Errorf("t: %q", got)
	}
}

func TestMissingRefsAndTargets(t *testing.T) {
	root := writeTree(t, map[string]string{
		"a_strings.txt": "1\n2\n",
		"b_strings.txt": "2\n3\n",
	})

	conf := "ref nope_strings.txt\ntarget a_strings.txt\n\nref a_strings.txt\nref nope2_strings.txt\ntarget b_strings.txt\ntarget gone_strings.txt\n"
	code, out, errOut := runConf(t, root, conf, false)

	if code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}

	if !strings.Contains(out, "::warning::Dedupe file not found: nope_strings.txt\n") || !strings.Contains(out, "::warning::Dedupe file not found: nope2_strings.txt\n") {
		t.Errorf("missing warnings:\n%s", out)
	}

	if strings.Contains(out, "gone_strings.txt") {
		t.Errorf("missing target must be silent:\n%s", out)
	}

	if got := readTree(t, root, "a_strings.txt"); got != "1\n2\n" {
		t.Errorf("step without refs changed a: %q", got)
	}

	if got := readTree(t, root, "b_strings.txt"); got != "3\n" {
		t.Errorf("b: %q", got)
	}
}

func TestStarSkipsGitAndNodeModules(t *testing.T) {
	root := writeTree(t, map[string]string{
		"r_strings.txt":                   "a\n",
		"d/x_strings.txt":                 "a\nb\n",
		".git/y_strings.txt":              "a\nb\n",
		"d/node_modules/z_strings.txt":    "a\nb\n",
		"d/not_a_strings_file.txt":        "a\nb\n",
		"d/sub/with space_strings.txt":    "a\nc\n",
		"DumpSource2/.stringsignore":      "b\n",
		"d/sub/.hidden_strings.txt":       "a\nq\n",
		"d/sub/noeol_strings.txt":         "a\nlast",
		"d/sub/dup_strings.txt":           "q\nq\na\n",
		"d/sub/unchanged_strings.txt":     "z\nq\nq\n",
		"d/sub/crlf_strings.txt":          "a\r\nb\r\n",
		"d/sub/emptyline_strings.txt":     "\na\n",
		"d/sub/empty_strings.txt":         "",
		"d/sub/binary_strings.txt":        "\xff\xfe\nb\na\n",
		"d/sub/binary_ref_strings.txt":    "\xff\xfe\n",
		"d/sub/dir_strings.txt/keep.txt":  "a\n",
		"d/sub/another_strings.txt.extra": "a\n",
	})

	conf := "ref r_strings.txt\nref DumpSource2/.stringsignore\ntarget *\n"

	if code, _, errOut := runConf(t, root, conf, false); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}

	same := []string{".git/y_strings.txt", "d/node_modules/z_strings.txt", "d/not_a_strings_file.txt", "d/sub/another_strings.txt.extra", "r_strings.txt"}
	for _, name := range same {
		want := "a\nb\n"
		if name == "r_strings.txt" {
			want = "a\n"
		} else if name == "d/sub/another_strings.txt.extra" {
			want = "a\n"
		}

		if got := readTree(t, root, name); got != want {
			t.Errorf("%s was touched: %q", name, got)
		}
	}

	want := map[string]string{
		"d/x_strings.txt":              "",
		"d/sub/with space_strings.txt": "c\n",
		"d/sub/.hidden_strings.txt":    "q\n",
		"d/sub/noeol_strings.txt":      "last\n",
		"d/sub/dup_strings.txt":        "q\n",
		"d/sub/unchanged_strings.txt":  "z\nq\nq\n",
		"d/sub/crlf_strings.txt":       "a\r\nb\r\n",
		"d/sub/emptyline_strings.txt":  "\n",
		"d/sub/empty_strings.txt":      "",
		"d/sub/binary_strings.txt":     "\xff\xfe\n",
	}

	for name, content := range want {
		if got := readTree(t, root, name); got != content {
			t.Errorf("%s: got %q want %q", name, got, content)
		}
	}

	if got := readTree(t, root, "d/sub/binary_ref_strings.txt"); got != "\xff\xfe\n" {
		t.Errorf("binary_ref: %q", got)
	}
}

func TestByteOrderSort(t *testing.T) {
	root := writeTree(t, map[string]string{
		"r_strings.txt": "gone\n",
		"t_strings.txt": "\xc3\xa9\nz\nZ\n\xff\ngone\n\x01\na\n\xf0\x9f\x98\x80\n\xee\x80\x80\n",
	})

	if code, _, errOut := runConf(t, root, "ref r_strings.txt\ntarget t_strings.txt\n", false); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}

	want := "\x01\nZ\na\nz\n\xc3\xa9\n\xee\x80\x80\n\xf0\x9f\x98\x80\n\xff\n"
	if got := readTree(t, root, "t_strings.txt"); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestOnlyChangedFilesWritten(t *testing.T) {
	root := writeTree(t, map[string]string{
		"r_strings.txt": "a\n",
		"c_strings.txt": "a\nb\n",
		"u_strings.txt": "z\nb\n",
	})

	old := time.Now().Add(-time.Hour)
	for _, name := range []string{"c_strings.txt", "u_strings.txt"} {
		if err := os.Chtimes(filepath.Join(root, name), old, old); err != nil {
			t.Fatal(err)
		}
	}

	if code, _, errOut := runConf(t, root, "ref r_strings.txt\ntarget *\n", false); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut)
	}

	cInfo, _ := os.Stat(filepath.Join(root, "c_strings.txt"))
	uInfo, _ := os.Stat(filepath.Join(root, "u_strings.txt"))

	if !cInfo.ModTime().After(old.Add(time.Minute)) {
		t.Error("changed file was not rewritten")
	}

	if uInfo.ModTime().After(old.Add(time.Minute)) {
		t.Error("unchanged file was rewritten")
	}

	if got := readTree(t, root, "u_strings.txt"); got != "z\nb\n" {
		t.Errorf("unchanged file content: %q", got)
	}

	if entries, _ := os.ReadDir(root); len(entries) != 3 {
		t.Errorf("%d files left in the tree, want 3", len(entries))
	}
}

func TestDryRun(t *testing.T) {
	root := writeTree(t, map[string]string{
		"r_strings.txt": "a\n",
		"t_strings.txt": "a\nb\n",
	})

	code, out, _ := runConf(t, root, "ref r_strings.txt\ntarget *\n", true)
	if code != 0 || !strings.Contains(out, "1 targets changed, 1 lines removed") {
		t.Errorf("exit %d output %q", code, out)
	}

	if got := readTree(t, root, "t_strings.txt"); got != "a\nb\n" {
		t.Errorf("dry run wrote: %q", got)
	}
}

func TestSelfCheckFailure(t *testing.T) {
	files := map[string]string{
		"ref_strings.txt": "a\n",
		"t_strings.txt":   "a\nb\nc\n",
		"u_strings.txt":   "c\n",
	}

	changes := map[string]func(map[string]*dedupeFile){
		"none": func(map[string]*dedupeFile) {},
		"line lost": func(f map[string]*dedupeFile) {
			f["t_strings.txt"].lines = []string{"c"}
		},
		"line gained": func(f map[string]*dedupeFile) {
			f["u_strings.txt"].lines = append(f["u_strings.txt"].lines, "new")
		},
	}

	for name, change := range changes {
		job, err := loadDedupeJob(writeTree(t, files), writeConf(t, "ref ref_strings.txt\ntarget *\n"))
		if err != nil {
			t.Fatal(err)
		}

		job.apply(io.Discard)
		change(job.files)

		if got, want := job.unchanged(), name == "none"; got != want {
			t.Errorf("%s: unchanged = %v, want %v", name, got, want)
		}
	}
}

func TestSelfCheckFailureExitCode(t *testing.T) {
	root := writeTree(t, map[string]string{
		"r_strings.txt": "a\n",
		"t_strings.txt": "a\nb\n",
	})

	job, err := loadDedupeJob(root, writeConf(t, "ref r_strings.txt\ntarget *\n"))
	if err != nil {
		t.Fatal(err)
	}

	job.before["lost line"] = struct{}{}

	var errOut bytes.Buffer

	if code := job.run(root, false, io.Discard, &errOut); code != 3 || !strings.Contains(errOut.String(), "self-check failed") {
		t.Errorf("exit %d, stderr %q", code, errOut.String())
	}

	if got := readTree(t, root, "t_strings.txt"); got != "a\nb\n" {
		t.Errorf("failed self-check wrote: %q", got)
	}
}

func TestDedupeSymlinks(t *testing.T) {
	root := writeTree(t, map[string]string{
		"real/r_strings.txt": "a\n",
		"real/t_strings.txt": "a\nb\n",
		"elsewhere/u.txt":    "a\nc\n",
	})

	link := filepath.Join(root, "link")
	uLink := filepath.Join(root, "real", "u_strings.txt")

	symlink(t, filepath.Join(root, "real"), link)
	symlink(t, filepath.Join(root, "elsewhere", "u.txt"), uLink)

	var out bytes.Buffer

	code := dedupeRun(link, writeConf(t, "ref r_strings.txt\ntarget *\n\nref r_strings.txt\ntarget u_strings.txt\n"), false, &out, io.Discard)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}

	for name, want := range map[string]string{"real/t_strings.txt": "b\n", "elsewhere/u.txt": "c\n"} {
		if got := readTree(t, root, name); got != want {
			t.Errorf("%s: %q, want %q", name, got, want)
		}
	}

	if info, err := os.Lstat(uLink); err != nil || info.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("target link replaced: %v, %v", info, err)
	}

	// u_strings.txt is a target of step 1 as an explicitly loaded file, not
	// through the walk.
	if !strings.Contains(out.String(), "step 1: refs [r_strings.txt], 2 targets changed, 2 lines removed\n") {
		t.Errorf("stdout %q", out.String())
	}
}

func TestSelfCheckCoversRefOnlyFiles(t *testing.T) {
	root := writeTree(t, map[string]string{
		"ignore":        "q\n",
		"r_strings.txt": "a\n",
		"t_strings.txt": "a\nb\n",
	})

	job, err := loadDedupeJob(root, writeConf(t, "ref r_strings.txt\nref ignore\ntarget *\n"))
	if err != nil {
		t.Fatal(err)
	}

	job.apply(io.Discard)
	job.files["ignore"].lines = nil

	if job.unchanged() {
		t.Error("lost lines of a reference-only file passed the self-check")
	}
}

func TestRunDedupeFlags(t *testing.T) {
	root := writeTree(t, map[string]string{
		"r_strings.txt": "a\n",
		"t_strings.txt": "a\nb\n",
	})

	conf := filepath.Join(root, "c.conf")
	if err := os.WriteFile(conf, []byte("ref r_strings.txt\ntarget *\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if code := runDedupe([]string{"-bogus", conf}, io.Discard, io.Discard); code != 2 {
		t.Errorf("bad flag: %d", code)
	}

	if code := runDedupe(nil, io.Discard, io.Discard); code != 2 {
		t.Errorf("no config: %d", code)
	}

	if code := runDedupe([]string{"-root", root, "-dry-run", conf}, io.Discard, io.Discard); code != 0 {
		t.Errorf("dry run: %d", code)
	}

	if got := readTree(t, root, "t_strings.txt"); got != "a\nb\n" {
		t.Errorf("dry run wrote: %q", got)
	}

	if code := runDedupe([]string{"-root", root, conf}, io.Discard, io.Discard); code != 0 {
		t.Errorf("run: %d", code)
	}

	if got := readTree(t, root, "t_strings.txt"); got != "b\n" {
		t.Errorf("run result: %q", got)
	}
}
