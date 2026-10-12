package analyze

import (
	"testing"

	"github.com/r-morato/tfcap/internal/model"
)

func TestClassifySource(t *testing.T) {
	cases := map[string]struct {
		kind     model.SourceKind
		ref      string
		insecure bool
	}{
		"./modules/x":                   {kind: model.SourceLocal},
		"../shared":                     {kind: model.SourceLocal},
		"terraform-aws-modules/vpc/aws": {kind: model.SourceRegistry},
		"terraform-aws-modules/vpc/aws//modules/x": {kind: model.SourceRegistry},
		"app.terraform.io/acme/vpc/aws":            {kind: model.SourceRegistry},
		"github.com/acme/mod":                      {kind: model.SourceGit},
		"github.com/acme/mod?ref=v1.0.0":           {kind: model.SourceGit, ref: "v1.0.0"},
		"git::https://example.com/m.git?ref=main":  {kind: model.SourceGit, ref: "main"},
		"git@github.com:acme/mod.git":              {kind: model.SourceGit},
		"git::ssh://git@example.com/m.git":         {kind: model.SourceGit},
		"git::http://example.com/m.git":            {kind: model.SourceGit, insecure: true},
		"https://example.com/m.zip":                {kind: model.SourceHTTP},
		"http://example.com/m.zip":                 {kind: model.SourceHTTP, insecure: true},
		"s3::https://s3.amazonaws.com/b/m.zip":     {kind: model.SourceBucket},
		"gcs::https://www.googleapis.com/b/m.zip":  {kind: model.SourceBucket},
	}
	for src, want := range cases {
		got := ClassifySource(src)
		if got.Kind != want.kind || got.Ref != want.ref || got.Insecure != want.insecure {
			t.Errorf("ClassifySource(%q) = %+v, want %+v", src, got, want)
		}
	}
}

func TestTyposquat(t *testing.T) {
	squats := map[string]string{
		"kreuzwenker/docker":   "kreuzwerker/docker",
		"kreuz-werker/docker":  "kreuzwerker/docker",
		"kreuzwerker/docker":   "",
		"hashicorp/aws":        "",
		"hashlcorp/aws":        "hashicorp/aws",
		"hashicrop/random":     "hashicorp/random",
		"integration/github":   "integrations/github",
		"cloudflare/cloudfare": "cloudflare/cloudflare",
		"integrations/github":  "",
		"opentofu/aws":         "",
		"datadog/datadog":      "",
		"mycorp/internal":      "",
	}
	for src, want := range squats {
		got, ok := Typosquat(ParseProviderSource(src, ""))
		if want == "" && ok {
			t.Errorf("%s flagged as typosquat of %s", src, got)
		}
		if want != "" && (!ok || got != want) {
			t.Errorf("%s: got (%q, %v), want %q", src, got, ok, want)
		}
	}
}

func TestParseProviderSource(t *testing.T) {
	p := ParseProviderSource("", "aws")
	if p.Short() != "hashicorp/aws" || p.Host != defaultRegistry {
		t.Errorf("legacy: %+v", p)
	}
	p = ParseProviderSource("registry.opentofu.org/opentofu/aws", "")
	if p.Host != "registry.opentofu.org" || p.Short() != "opentofu/aws" {
		t.Errorf("full: %+v", p)
	}
}

func TestExactVersion(t *testing.T) {
	for v, want := range map[string]bool{
		"1.2.3": true, "= 1.2.3": true, "v1.2.3": true, "1.2.3-beta.1": true,
		"~> 1.2": false, ">= 1.0": false, "": false, "1.2": false,
	} {
		if IsExactVersion(v) != want {
			t.Errorf("IsExactVersion(%q) != %v", v, want)
		}
	}
}
