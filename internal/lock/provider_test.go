package lock

import (
	"strings"
	"testing"

	"github.com/r-morato/tfcap/internal/model"
	"github.com/r-morato/tfcap/internal/rules"
)

const (
	zhA = "zh:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	zhB = "zh:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func provRep(ps ...model.ProviderLock) *model.Report { return &model.Report{ProviderLocks: ps} }

func pl(addr, ver string, hs ...string) model.ProviderLock {
	return model.ProviderLock{Address: addr, Version: ver, Hashes: hs, Line: 4}
}

func TestProviderVerify(t *testing.T) {
	const aws = "registry.terraform.io/hashicorp/aws"
	f := Build(provRep(pl(aws, "6.0.0", "h1:one=", zhA)))
	if !f.ProvidersLocked || len(f.Providers) != 1 {
		t.Fatalf("build: %+v", f)
	}
	cases := []struct {
		name   string
		rep    *model.Report
		status string
		rule   string
	}{
		{"unchanged", provRep(pl(aws, "6.0.0", "h1:one=", zhA)), "ok", ""},
		{"more h1 platforms", provRep(pl(aws, "6.0.0", "h1:one=", "h1:two=", zhA)), "ok", ""},
		{"upgraded", provRep(pl(aws, "6.1.0", "h1:x=", zhB)), "upgraded", rules.ProvUpgraded},
		{"mutated", provRep(pl(aws, "6.0.0", "h1:one=", zhB)), "mutated", rules.ProvMutated},
		{"no shared hash", provRep(pl(aws, "6.0.0", "h1:zzz=")), "mutated", rules.ProvMutated},
	}
	for _, c := range cases {
		res := Verify(f, c.rep)
		if len(res.Providers) != 1 || res.Providers[0].Status != c.status {
			t.Errorf("%s: providers %+v", c.name, res.Providers)
			continue
		}
		if c.rule == "" && len(res.Findings) != 0 || c.rule != "" && (len(res.Findings) != 1 || res.Findings[0].RuleID != rules.Get(c.rule).ID) {
			t.Errorf("%s: findings %+v", c.name, res.Findings)
		}
	}
	// zh-free locks with disjoint h1 sets cannot describe the same release.
	f2 := Build(provRep(pl(aws, "6.0.0", "h1:one=")))
	if r := Verify(f2, provRep(pl(aws, "6.0.0", "h1:other="))); r.Providers[0].Status != "mutated" {
		t.Errorf("h1 disjoint: %+v", r.Providers)
	}
	res := Verify(f, provRep(pl("registry.terraform.io/hashicorp/random", "3.0.0", zhA)))
	if len(res.Providers) != 2 || res.Providers[0].Status != "removed" || res.Providers[1].Status != "new" {
		t.Errorf("new/removed: %+v", res.Providers)
	}
	if !strings.Contains(res.Findings[0].Message, "New provider") {
		t.Errorf("new msg: %+v", res.Findings)
	}
	old := &File{Schema: Schema, Modules: []Entry{}}
	if r := Verify(old, provRep(pl(aws, "6.0.0", zhA))); len(r.Providers) != 0 || len(r.Findings) != 0 {
		t.Errorf("legacy lock should skip providers: %+v", r)
	}
}
