package main

import (
	"os"
	"path/filepath"
	"reflect"
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
