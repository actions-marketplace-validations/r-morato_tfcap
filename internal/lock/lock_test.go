package lock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r-morato/tfcap/internal/model"
)

func TestValidate(t *testing.T) {
	good := `{"schema":"tfcap/lock/v1","modules":[{"key":"network","source":"acme/network/aws","version":"1.0.0",` +
		`"hash":"tfcap1:` + strings.Repeat("a", 64) + `","capabilities":[{"fp":"0123456789abcdef","rule":"TFCAP-EXEC-001"}]}]}`
	cases := map[string]struct {
		body string
		ok   bool
	}{
		"valid":           {good, true},
		"unknown field":   {strings.Replace(good, `"schema"`, `"evil":1,"schema"`, 1), false},
		"bad hash":        {strings.Replace(good, strings.Repeat("a", 64), "zz", 1), false},
		"bad rule":        {strings.Replace(good, "TFCAP-EXEC-001", "rm -rf /", 1), false},
		"wrong schema":    {strings.Replace(good, "tfcap/lock/v1", "tfcap/lock/v9", 1), false},
		"duplicate key":   {strings.Replace(good, `]}`, `,{"key":"network","source":"x","hash":"tfcap1:`+strings.Repeat("b", 64)+`","capabilities":[]}]}`, 1), false},
		"trailing object": {good + `{}`, false},
	}
	dir := t.TempDir()
	for name, tc := range cases {
		p := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".json")
		os.WriteFile(p, []byte(tc.body), 0o644)
		err := Validate(p)
		if (err == nil) != tc.ok {
			t.Errorf("%s: Validate() error = %v, want ok=%v", name, err, tc.ok)
		}
	}
}

func TestVerifyCarriesCommits(t *testing.T) {
	const a, b = "1111111111111111111111111111111111111111", "2222222222222222222222222222222222222222"
	src := "git::https://github.com/acme/net.git?ref=v1"
	locked := &model.Report{Modules: []model.Module{{Key: "net", Source: src, ThirdParty: true, Hash: "tfcap1:aa", Commit: a}}}
	f := Build(locked)
	now := &model.Report{Modules: []model.Module{{Key: "net", Source: src, ThirdParty: true, Hash: "tfcap1:bb", Commit: b}}}
	m := Verify(f, now).Modules[0]
	if m.Status != StatusMutated || m.LockedCommit != a || m.CurrentCommit != b {
		t.Errorf("got %+v", m)
	}
}
