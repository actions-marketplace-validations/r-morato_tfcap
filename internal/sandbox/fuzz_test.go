package sandbox

import "testing"

// The sandbox listeners parse whatever the sandboxed plan sends them.

func FuzzParseQuestion(f *testing.F) {
	f.Add([]byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'a', 'b', 'c', 0, 0, 1, 0, 1})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		name, _, end, ok := parseQuestion(b)
		if ok && (end > len(b) || len(name) > len(b)) {
			t.Fatalf("out of range: end %d, name %d, input %d", end, len(name), len(b))
		}
	})
}

func FuzzParseClientHello(f *testing.F) {
	f.Add(make([]byte, 64))
	f.Add([]byte{1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = parseClientHello(b)
	})
}

func FuzzLeaks(f *testing.F) {
	h := &Honey{Canary: "0123456789abcdef01234567"}
	f.Add("GET /?k=0123456789abcdef01234567")
	f.Fuzz(func(t *testing.T, s string) {
		h.Leaks(s)
	})
}
