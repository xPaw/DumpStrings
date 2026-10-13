package main

import "testing"

func TestUtilDemangle(t *testing.T) {
	tests := []struct{ in, want string }{
		{"", ""},
		{"main", "main"},
		{"_ZdlPv", "operator delete(void*)"},
		{"_ZdlPv@@GLIBCXX_3.4", "operator delete(void*)@@GLIBCXX_3.4"},
		{"_ZNSo3putEc@GLIBCXX_3.4", "std::ostream::put(char)@GLIBCXX_3.4"},
		{"_Znwm@plt", "operator new(unsigned long)@plt"},
		{"._ZN3FooC2Ev", ".Foo::Foo()"},
		{".__ZN3FooC2Ev", ".Foo::Foo()"},
		{"__ZN3FooC2Ev", "Foo::Foo()"},
		{"$_ZN3FooC2Ev", "Foo::Foo()"},
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
