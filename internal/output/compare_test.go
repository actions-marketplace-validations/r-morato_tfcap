package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/r-morato/tfcap/internal/lock"
)

func TestCompareURL(t *testing.T) {
	const (
		a = "1111111111111111111111111111111111111111"
		b = "2222222222222222222222222222222222222222"
	)
	git := "git::https://github.com/acme/terraform-net.git//modules/vpc?ref="
	cases := []struct {
		name string
		m    lock.ModuleStatus
		want string
	}{
		{"upgrade, commits known",
			lock.ModuleStatus{Status: lock.StatusUpgraded, LockedSource: git + "v1.0.0", Source: git + "v1.1.0", LockedCommit: a, CurrentCommit: b},
			"https://github.com/acme/terraform-net/compare/" + a + "..." + b},
		{"upgrade, refs only",
			lock.ModuleStatus{Status: lock.StatusUpgraded, LockedSource: git + "v1.0.0", Source: git + "v1.1.0"},
			"https://github.com/acme/terraform-net/compare/v1.0.0...v1.1.0"},
		{"moved tag: same ref, different commit",
			lock.ModuleStatus{Status: lock.StatusMutated, Source: git + "v1.0.0", LockedCommit: a, CurrentCommit: b},
			"https://github.com/acme/terraform-net/compare/" + a + "..." + b},
		{"moved tag without commits: nothing to compare",
			lock.ModuleStatus{Status: lock.StatusMutated, Source: git + "v1.0.0"}, ""},
		{"registry module",
			lock.ModuleStatus{Status: lock.StatusUpgraded, LockedSource: "terraform-aws-modules/vpc/aws", Source: "terraform-aws-modules/vpc/aws", LockedCommit: a, CurrentCommit: b}, ""},
		{"moved to another repository",
			lock.ModuleStatus{Status: lock.StatusUpgraded, LockedSource: git + "v1.0.0", Source: "github.com/other/net?ref=v2.0.0"}, ""},
		{"unchanged",
			lock.ModuleStatus{Status: lock.StatusOK, Source: git + "v1.0.0", LockedCommit: a, CurrentCommit: a}, ""},
		{"short github source",
			lock.ModuleStatus{Status: lock.StatusUpgraded, LockedSource: "github.com/acme/net?ref=v1", Source: "github.com/acme/net?ref=v2"},
			"https://github.com/acme/net/compare/v1...v2"},
	}
	for _, c := range cases {
		if got := CompareURL(c.m); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestVerifyShowsCompareLink(t *testing.T) {
	v := &lock.Result{Modules: []lock.ModuleStatus{{Key: "net", Status: lock.StatusUpgraded,
		LockedSource: "github.com/acme/net?ref=v1", Source: "github.com/acme/net?ref=v2"}}}
	var md, txt bytes.Buffer
	VerifyMarkdown(&md, v)
	Verify(&txt, v, Style{})
	want := "https://github.com/acme/net/compare/v1...v2"
	if !strings.Contains(md.String(), "([code changes]("+want+"))") {
		t.Errorf("markdown missing link:\n%s", md.String())
	}
	if !strings.Contains(txt.String(), "code changes: "+want) {
		t.Errorf("text missing link:\n%s", txt.String())
	}
}
