package output

import "testing"

func TestVerLabel(t *testing.T) {
	cases := []struct{ src, ver, want string }{
		{"acme/net/aws", "1.4.1", "1.4.1"},
		{"git::https://example.com/m.git?ref=v1.1.0", "", "ref=v1.1.0"},
		{"./local", "", "./local"},
	}
	for _, c := range cases {
		if got := verLabel(c.src, c.ver); got != c.want {
			t.Errorf("verLabel(%q, %q) = %q, want %q", c.src, c.ver, got, c.want)
		}
	}
}
