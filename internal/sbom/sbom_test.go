package sbom

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/r-morato/tfcap/internal/model"
)

func TestBuild(t *testing.T) {
	rep := &model.Report{
		Modules: []model.Module{
			{Key: "", Kind: model.SourceLocal},
			{Key: "vpc", Source: "terraform-aws-modules/vpc/aws", Version: "6.0.1", Kind: model.SourceRegistry, ThirdParty: true, Hash: "tfcap1:aa"},
			{Key: "vpc.sub", Source: "./modules/sub", Kind: model.SourceLocal, ThirdParty: true},
			{Key: "lambda", Source: "git::https://github.com/terraform-aws-modules/terraform-aws-lambda.git?ref=v8.0.0",
				Kind: model.SourceGit, ThirdParty: true, Commit: "0123456789abcdef0123456789abcdef01234567"},
		},
		Capabilities: []model.Capability{{Module: "lambda", Severity: model.Medium}, {Module: "lambda", Severity: model.Medium}},
		ProviderLocks: []model.ProviderLock{{Address: "registry.terraform.io/hashicorp/aws", Version: "6.2.0",
			Hashes: []string{"h1:abc=", "zh:" + strings.Repeat("a", 64)}}},
	}
	b := Build(rep, "infra", "1.0.0", time.Unix(0, 0))
	var buf bytes.Buffer
	if err := Write(&buf, b); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	for _, want := range []string{
		`"specVersion": "1.6"`,
		`"timestamp": "1970-01-01T00:00:00Z"`,
		`"purl": "pkg:github/terraform-aws-modules/terraform-aws-lambda@0123456789abcdef0123456789abcdef01234567"`,
		`"name": "vpc/aws"`,
		`"group": "terraform-aws-modules"`,
		`"https://registry.terraform.io/modules/terraform-aws-modules/vpc/aws/6.0.1"`,
		`"tfcap:capabilities:medium"`,
		`"purl": "pkg:terraform-provider/hashicorp/aws@6.2.0?registry=registry.terraform.io"`,
		`"alg": "SHA-256"`,
		`"ref": "module:vpc"`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s", want)
		}
	}
	if len(b.Components) != 4 {
		t.Errorf("components = %d", len(b.Components))
	}
	for _, d := range b.Dependencies {
		if d.Ref == "module:vpc" && (len(d.DependsOn) != 1 || d.DependsOn[0] != "module:vpc.sub") {
			t.Errorf("vpc deps: %v", d.DependsOn)
		}
	}
	// Serial is stable regardless of timestamp.
	if Build(rep, "infra", "1.0.0", time.Now()).SerialNumber != b.SerialNumber {
		t.Error("serial depends on timestamp")
	}
}
