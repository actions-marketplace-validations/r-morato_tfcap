package reputation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/r-morato/tfcap/internal/model"
	"github.com/r-morato/tfcap/internal/rules"
)

func TestCheck(t *testing.T) {
	now := time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)
	var sawToken, leakedToken bool
	mux := http.NewServeMux()
	mux.HandleFunc("/reg/v1/modules/acme/vpc/aws/1.0.0", func(w http.ResponseWriter, r *http.Request) {
		leakedToken = leakedToken || r.Header.Get("Authorization") != ""
		w.Write([]byte(`{"source":"https://github.com/acme/terraform-aws-vpc","published_at":"2026-10-15T10:00:00Z"}`))
	})
	mux.HandleFunc("/reg/v1/modules/gone/mod/aws/2.0.0", http.NotFound)
	mux.HandleFunc("/gh/repos/acme/terraform-aws-vpc", func(w http.ResponseWriter, r *http.Request) {
		sawToken = r.Header.Get("Authorization") == "Bearer tok"
		w.Write([]byte(`{"full_name":"acme/terraform-aws-vpc","archived":true,"created_at":"2026-09-01T00:00:00Z"}`))
	})
	mux.HandleFunc("/gh/repos/old/name", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/gh/repositories/1")
		w.WriteHeader(http.StatusMovedPermanently)
		w.Write([]byte(`{"message":"Moved Permanently","url":"x"}`))
	})
	mux.HandleFunc("/gh/repos/deleted/thing", http.NotFound)
	mux.HandleFunc("/gh/repos/good/mod", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"full_name":"good/mod","created_at":"2019-01-01T00:00:00Z"}`))
	})
	mux.HandleFunc("/sc/projects/github.com/acme/terraform-aws-vpc", func(w http.ResponseWriter, r *http.Request) {
		leakedToken = leakedToken || r.Header.Get("Authorization") != ""
		w.Write([]byte(`{"score":2.5}`))
	})
	mux.HandleFunc("/sc/projects/github.com/good/mod", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"score":8.1}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := New("tok")
	c.Registry, c.GitHub, c.Scorecard = srv.URL+"/reg", srv.URL+"/gh", srv.URL+"/sc"
	c.Now = func() time.Time { return now }

	rep := &model.Report{Modules: []model.Module{
		{Key: "vpc", Source: "registry.terraform.io/acme/vpc/aws", Version: "1.0.0", Kind: model.SourceRegistry, ThirdParty: true,
			Anchor: &model.Location{File: "main.tf", Line: 3}},
		{Key: "gone", Source: "gone/mod/aws", Version: "2.0.0", Kind: model.SourceRegistry, ThirdParty: true},
		{Key: "moved", Source: "git::https://github.com/old/name.git?ref=v1", Kind: model.SourceGit, ThirdParty: true},
		{Key: "deleted", Source: "github.com/deleted/thing", Kind: model.SourceGit, ThirdParty: true},
		{Key: "good", Source: "git::https://github.com/good/mod.git?ref=v1", Kind: model.SourceGit, ThirdParty: true},
		{Key: "mine", Source: "./local", Kind: model.SourceLocal},
	}}
	caps, warns := c.Check(context.Background(), rep)
	if len(warns) != 0 {
		t.Errorf("warnings: %v", warns)
	}
	got := map[string]string{}
	for _, cp := range caps {
		got[cp.Module+" "+cp.RuleID] = cp.Message
	}
	for _, want := range []string{
		"vpc " + rules.RepFreshRelease, "vpc " + rules.RepRepoArchived, "vpc " + rules.RepRepoYoung, "vpc " + rules.RepLowScorecard,
		"gone " + rules.RepUnknownModule, "moved " + rules.RepRepoMoved, "deleted " + rules.RepRepoMissing,
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("missing %s; got %v", want, got)
		}
	}
	for k := range got {
		if strings.HasPrefix(k, "good ") || strings.HasPrefix(k, "mine ") {
			t.Errorf("unexpected finding %s", k)
		}
	}
	if !sawToken || leakedToken {
		t.Errorf("token sent to GitHub: %v; leaked elsewhere: %v", sawToken, leakedToken)
	}
	if caps[0].File != "main.tf" || caps[0].Line != 3 {
		t.Errorf("finding not anchored to the module block: %+v", caps[0])
	}
}

func TestCheckNetworkErrorIsWarning(t *testing.T) {
	c := New("")
	c.Registry, c.GitHub, c.Scorecard = "http://127.0.0.1:1", "http://127.0.0.1:1", "http://127.0.0.1:1"
	rep := &model.Report{Modules: []model.Module{{Key: "x", Source: "github.com/a/b", Kind: model.SourceGit, ThirdParty: true}}}
	caps, warns := c.Check(context.Background(), rep)
	if len(caps) != 0 || len(warns) != 1 {
		t.Errorf("caps %v warns %v", caps, warns)
	}
}
