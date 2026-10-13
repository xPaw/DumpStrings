package main

import "bytes"

// maxGroupDepth bounds the nesting of protobuf groups the walker follows.
const maxGroupDepth = 64

// pbVarint reads a varint of at most maxLen bytes at d[p].
func pbVarint(d []byte, p, maxLen int) (v uint64, next int, ok bool) {
	for i := 0; i < maxLen; i++ {
		if p >= len(d) {
			return 0, p, false
		}

		c := d[p]
		p++
		v |= uint64(c&0x7f) << (7 * uint(i))

		if c&0x80 == 0 {
			return v, p, true
		}
	}

	return 0, p, false
}

// pbSkip skips the value of a field with the given wire type and returns the
// position after it. Group fields end at the end-group tag of the same field.
func pbSkip(d []byte, p int, wire, field uint64, depth int) (int, bool) {
	switch wire {
	case 0:
		_, p, ok := pbVarint(d, p, 10)
		return p, ok
	case 1:
		if len(d)-p < 8 {
			return p, false
		}

		return p + 8, true
	case 5:
		if len(d)-p < 4 {
			return p, false
		}

		return p + 4, true
	case 2:
		n, q, ok := pbVarint(d, p, 5)
		if !ok || n > uint64(len(d)-q) {
			return p, false
		}

		return q + int(n), true
	case 3:
		if depth >= maxGroupDepth {
			return p, false
		}

		for {
			tag, q, ok := pbVarint(d, p, 5)
			if !ok || tag>>3 == 0 {
				return p, false
			}

			if tag&7 == 4 {
				return q, tag>>3 == field
			}

			if p, ok = pbSkip(d, q, tag&7, tag>>3, depth+1); !ok {
				return p, false
			}
		}
	}

	return p, false
}

// pbConsume walks the fields of one message starting at d[start], which holds
// field 1, and returns the position where the message ends: end of data, a
// tag that does not parse, field 0, an unknown or stray wire type, or a second
// field 1.
func pbConsume(d []byte, start int) int {
	p := start
	seen1 := false

	for p < len(d) {
		tag, q, ok := pbVarint(d, p, 5)
		if !ok || tag>>3 == 0 {
			return p
		}

		if tag>>3 == 1 {
			if seen1 {
				return p
			}

			seen1 = true
		}

		next, ok := pbSkip(d, q, tag&7, tag>>3, 0)
		if !ok {
			return p
		}

		p = next
	}

	return p
}

// isProtoName reports whether name matches ^[a-zA-Z_0-9\/.-]+\.proto$.
func isProtoName(name []byte) bool {
	const suffix = ".proto"

	if len(name) <= len(suffix) || !bytes.HasSuffix(name, []byte(suffix)) {
		return false
	}

	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '_', c == '\\', c == '/', c == '.', c == '-':
		default:
			return false
		}
	}

	return true
}

// MaskProtobufs returns d with every serialized FileDescriptorProto
// zero-filled, found as field 1 (a .proto file name) followed by a well-formed
// message that is terminated by a NUL byte or the end of d. d is not modified:
// it is returned as is when it holds no descriptor, and copied otherwise.
func MaskProtobufs(d []byte) []byte {
	var masked []byte

	i := 0

	for {
		j := bytes.IndexByte(d[i:], 0x0a)
		if j < 0 || i+j+1 >= len(d) {
			break
		}

		i += j

		n := int(d[i+1] & 0x7f)
		hdr := 2

		if d[i+1]&0x80 != 0 {
			if i+2 >= len(d) || d[i+2]&0x80 != 0 {
				i++
				continue
			}

			n |= int(d[i+2]) << 7
			hdr = 3
		}

		if n <= len(d)-i-hdr && isProtoName(d[i+hdr:i+hdr+n]) {
			end := pbConsume(d, i)

			if end > i && (end == len(d) || d[end] == 0) {
				// The search only moves forward, so it goes on in d.
				if masked == nil {
					masked = bytes.Clone(d)
				}

				clear(masked[i:end])
				i = end

				continue
			}
		}

		i++
	}

	if masked == nil {
		return d
	}

	return masked
}
