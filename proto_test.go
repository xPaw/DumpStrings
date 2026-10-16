package main

import (
	"bytes"
	"testing"
)

func pbField(tag byte, payload []byte) []byte {
	return append([]byte{tag, byte(len(payload))}, payload...)
}

func descriptor(name string) []byte {
	msg := pbField(0x1a, append(pbField(0x0a, []byte("Thing")), pbField(0x12, pbField(0x0a, []byte("field_name")))...))
	b := pbField(0x0a, []byte(name))
	b = append(b, pbField(0x12, []byte("my.pkg"))...)

	return append(b, msg...)
}

// mask returns MaskProtobufs(d) and fails when d was modified.
func mask(t *testing.T, d []byte) []byte {
	t.Helper()

	orig := bytes.Clone(d)
	got := MaskProtobufs(d)

	if !bytes.Equal(d, orig) {
		t.Fatalf("input modified: %q", d)
	}

	return got
}

func TestMaskProtobufsNulTerminated(t *testing.T) {
	blob := descriptor("my/thing.proto")
	data := append([]byte("hello\x00"), blob...)
	data = append(data, 0)
	data = append(data, []byte("tail string\x00")...)

	got := mask(t, data)
	want := bytes.Clone(data)
	clear(want[6 : 6+len(blob)])

	if !bytes.Equal(got, want) {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestMaskProtobufsSectionEnd(t *testing.T) {
	blob := descriptor("a.proto")
	got := mask(t, blob)

	if !bytes.Equal(got, make([]byte, len(blob))) {
		t.Fatalf("not masked: %q", got)
	}
}

func TestMaskProtobufsNonNulTerminator(t *testing.T) {
	data := append(descriptor("a.proto"), 0x0a, 'q')
	got := mask(t, data)

	// Without a descriptor, d itself is returned.
	if !bytes.Equal(got, data) || &got[0] != &data[0] {
		t.Fatalf("masked despite non-NUL end: %q", got)
	}
}

func TestMaskProtobufsHyphen(t *testing.T) {
	data := append(descriptor("steam-foo/a_b.proto"), 0)
	got := mask(t, data)

	if !bytes.Equal(got, make([]byte, len(data))) {
		t.Fatalf("not masked: %q", got)
	}
}

func TestMaskProtobufsBadName(t *testing.T) {
	for _, name := range []string{"a b.proto", "A.PROTO", ".proto", "a.protox"} {
		data := append(descriptor(name), 0)
		if got := mask(t, data); !bytes.Equal(got, data) {
			t.Errorf("%q masked", name)
		}
	}
}

func TestMaskProtobufsTwoByteLength(t *testing.T) {
	name := bytes.Repeat([]byte("a"), 200)
	name = append(name, ".proto"...)

	data := []byte{0x0a, byte(len(name)&0x7f) | 0x80, byte(len(name) >> 7)}
	data = append(data, name...)
	data = append(data, pbField(0x12, []byte("pkg"))...)
	data = append(data, 0)

	got := mask(t, data)

	if !bytes.Equal(got, make([]byte, len(data))) {
		t.Fatalf("not masked: %q", got)
	}
}

func TestMaskProtobufsTruncated(t *testing.T) {
	blob := descriptor("a.proto")
	data := append(bytes.Clone(blob[:len(blob)-3]), 0)
	got := mask(t, data)

	// A truncated trailing field stops the walk before it, and the byte there
	// is not NUL.
	if !bytes.Equal(got, data) {
		t.Fatalf("masked truncated blob: %q", got)
	}

	data = []byte{0x0a, 20, 'a', '.', 'p', 'r', 'o', 't', 'o'}
	if got := mask(t, data); !bytes.Equal(got, data) {
		t.Fatalf("masked truncated name: %q", got)
	}
}

func TestMaskProtobufsGroup(t *testing.T) {
	// field 5 start-group, field 6 varint inside, field 5 end-group.
	blob := append(pbField(0x0a, []byte("g.proto")), 0x2b, 0x30, 0x01, 0x2c)
	data := append(bytes.Clone(blob), 0)

	got := mask(t, data)
	if !bytes.Equal(got, make([]byte, len(data))) {
		t.Fatalf("group blob not masked: %q", got)
	}

	// A mismatched end-group stops the walk before the group, and the byte there
	// is not NUL.
	bad := append(pbField(0x0a, []byte("g.proto")), 0x2b, 0x30, 0x01, 0x34, 0)
	if got := mask(t, bad); !bytes.Equal(got, bad) {
		t.Fatalf("masked mismatched group: %q", got)
	}

	deep := pbField(0x0a, []byte("g.proto"))
	for range 200 {
		deep = append(deep, 0x2b)
	}

	deep = append(deep, 0)
	if got := mask(t, deep); !bytes.Equal(got, deep) {
		t.Fatalf("masked deeply nested group")
	}
}

func TestMaskProtobufsSecondField1(t *testing.T) {
	data := append(descriptor("a.proto"), pbField(0x0a, []byte("b"))...)
	data = append(data, 0)

	// The walk stops at the second field 1, which is not a NUL.
	if got := mask(t, data); !bytes.Equal(got, data) {
		t.Fatalf("masked: %q", got)
	}
}

func TestMaskProtobufsGarbage(t *testing.T) {
	for _, data := range [][]byte{
		{0x0a},
		{0x0a, 0x80},
		{0x0a, 0x80, 0x80, 'x'},
		{0x0a, 0xff, 0xff, 0xff},
		{0x0a, 0x0a, 0x0a, 0x0a, 0x0a},
		bytes.Repeat([]byte{0x0a, 0x07}, 50),
	} {
		if got := mask(t, data); !bytes.Equal(got, data) {
			t.Errorf("masked garbage %x", data)
		}
	}
}

func TestPbSkip(t *testing.T) {
	tests := []struct {
		name  string
		d     []byte
		wire  uint64
		depth int
		want  int
		ok    bool
	}{
		{"fixed64", make([]byte, 8), 1, 0, 8, true},
		{"fixed64 truncated", make([]byte, 7), 1, 0, 0, false},
		{"fixed32", make([]byte, 4), 5, 0, 4, true},
		{"fixed32 truncated", make([]byte, 3), 5, 0, 0, false},
		{"fixed32 empty", nil, 5, 0, 0, false},
		{"varint", []byte{0x80, 0x01}, 0, 0, 2, true},
		{"varint truncated", []byte{0x80}, 0, 0, 1, false},
		{"length-delimited", []byte{2, 'a', 'b'}, 2, 0, 3, true},
		{"length-delimited truncated", []byte{3, 'a', 'b'}, 2, 0, 0, false},
		{"wire 4", []byte{0}, 4, 0, 0, false},
		{"wire 6", make([]byte, 8), 6, 0, 0, false},
		{"wire 7", make([]byte, 8), 7, 0, 0, false},
		{"group too deep", []byte{0x2c}, 3, maxGroupDepth, 0, false},
	}

	for _, test := range tests {
		got, ok := pbSkip(test.d, 0, test.wire, 5, test.depth)
		if got != test.want || ok != test.ok {
			t.Errorf("%s: pbSkip = %d, %v, want %d, %v", test.name, got, ok, test.want, test.ok)
		}
	}
}
