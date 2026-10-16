package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

// writeTree writes files, keyed by slash path, under a new temporary
// directory and returns it.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()

	root := t.TempDir()

	for name, content := range files {
		full := filepath.Join(root, filepath.FromSlash(name))

		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	return root
}

// readTree returns the content of the file at slash path name under root.
func readTree(t *testing.T, root, name string) string {
	t.Helper()

	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}

	return string(data)
}

// symlink creates a symbolic link at link that points to target. It skips the
// test when the system does not allow it.
func symlink(t *testing.T, target, link string) {
	t.Helper()

	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symbolic links: %v", err)
	}
}

func TestReplaceFileThroughSymlink(t *testing.T) {
	root := writeTree(t, map[string]string{"real/target.txt": "old\n"})
	link := filepath.Join(root, "links", "link.txt")

	if err := os.Mkdir(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}

	symlink(t, filepath.Join("..", "real", "target.txt"), link)

	if err := replaceFile(link, []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if info, err := os.Lstat(link); err != nil || info.Mode()&fs.ModeSymlink == 0 {
		t.Errorf("link replaced: %v, %v", info, err)
	}

	if got := readTree(t, root, "real/target.txt"); got != "new\n" {
		t.Errorf("target content %q", got)
	}

	for _, dir := range []string{"real", "links"} {
		if entries, _ := os.ReadDir(filepath.Join(root, dir)); len(entries) != 1 {
			t.Errorf("%s holds %d entries, want 1", dir, len(entries))
		}
	}
}

func TestWalkFilesSymlinkRoot(t *testing.T) {
	root := writeTree(t, map[string]string{
		"real/a.txt":      "",
		"real/sub/b.txt":  "",
		"outside/c.txt":   "",
		"real/.git/d.txt": "",
	})

	symlink(t, filepath.Join(root, "outside"), filepath.Join(root, "real", "inner"))
	symlink(t, filepath.Join(root, "real"), filepath.Join(root, "link"))

	walk := func(start string) []string {
		var got []string

		err := walkFiles(start, func(string) bool { return true }, func(p string) error {
			got = append(got, p)
			return nil
		}, func(err error) error { return err })
		if err != nil {
			t.Fatal(err)
		}

		slices.Sort(got)

		return got
	}

	for _, start := range []string{filepath.Join(root, "real"), filepath.Join(root, "link")} {
		want := []string{filepath.Join(start, "a.txt"), filepath.Join(start, "sub", "b.txt")}

		if got := walk(start); !reflect.DeepEqual(got, want) {
			t.Errorf("walk %s = %q, want %q", start, got, want)
		}
	}
}

func TestUtilDemangle(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"main", "main"},
		{"$", "$"},
		{"_ZdlPv", "operator delete(void*)"},
		{"_ZdlPv@@GLIBCXX_3.4", "operator delete(void*)@@GLIBCXX_3.4"},
		{"_ZNSo3putEc@GLIBCXX_3.4", "std::ostream::put(char)@GLIBCXX_3.4"},
		{"_Znwm@plt", "operator new(unsigned long)@plt"},
		{"._ZN3FooC2Ev", ".Foo::Foo()"},
		{".__ZN3FooC2Ev", ".Foo::Foo()"},
		{"__ZN3FooC2Ev", "Foo::Foo()"},
		{"$_ZN3FooC2Ev", "Foo::Foo()"},
		{".$_ZN3FooC2Ev", ".$_ZN3FooC2Ev"},
		{"foo@plt", "foo@plt"},
		{"_ZNDwA_eE1aE", "a throw(long double ( throw(long double [])) [])"},
		{"_ZcvUlT_E_", "_ZcvUlT_E_"},
	}

	for _, test := range tests {
		if got := UtilDemangle(test.in); got != test.want {
			t.Errorf("UtilDemangle(%q) = %q, want %q", test.in, got, test.want)
		}
	}
}

func TestSortedUnique(t *testing.T) {
	got := sortedUnique([]string{"b", "\xff", "a", "b", "B", ""})
	want := []string{"", "B", "a", "b", "\xff"}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("sortedUnique = %q, want %q", got, want)
	}

	if got := sortedUnique(nil); len(got) != 0 {
		t.Errorf("sortedUnique(nil) = %q", got)
	}
}
