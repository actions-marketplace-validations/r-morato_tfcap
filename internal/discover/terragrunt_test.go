package discover

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/r-morato/tfcap/internal/rules"
)

func writeFiles(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTerragrunt(t *testing.T) {
	root := t.TempDir()
	unit := `terraform {
  source = "git::https://example.com/acme/mods.git//net?ref=v1.0.0"
}
generate "provider" {
  path     = "provider.tf"
  contents = "x"
}
`
	writeFiles(t, root, map[string]string{
		"terragrunt.hcl": unit,
		".terragrunt-cache/a/b/.terragrunt-source-version": "x",
		".terragrunt-cache/a/b/net/terragrunt.hcl":         unit,
		".terragrunt-cache/a/b/net/provider.tf":            `resource "null_resource" "own" { provisioner "local-exec" { command = "echo hi" } }`,
		".terragrunt-cache/a/b/net/main.tf":                `data "external" "x" { program = ["sh", "-c", "env"] }`,
	})
	rep, err := Scan(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var mod bool
	for _, m := range rep.Modules {
		if m.Key == TerragruntKey {
			mod = m.ThirdParty && m.Hash != "" && m.Anchor != nil && m.Anchor.File == "terragrunt.hcl"
		}
	}
	if !mod {
		t.Fatalf("terragrunt module missing or incomplete: %+v", rep.Modules)
	}
	got := map[string]string{}
	for _, c := range rep.Capabilities {
		got[c.RuleID] = c.Module
	}
	if got[rules.ExecExternalData] != TerragruntKey {
		t.Errorf("external data in module code not attributed to the terragrunt module: %v", got)
	}
	if _, ok := got[rules.ExecLocal]; ok {
		t.Errorf("generated provider.tf (your code) was attributed to the module: %v", got)
	}
	if got[rules.SrcGitMutableRef] != "" {
		t.Errorf("source finding should be on the unit: %v", got)
	}
	// Editing your own unit must not change the module hash.
	h1, _ := hashDirExcluding(filepath.Join(root, ".terragrunt-cache/a/b/net"), map[string]bool{"terragrunt.hcl": true, "provider.tf": true})
	writeFiles(t, root, map[string]string{".terragrunt-cache/a/b/net/terragrunt.hcl": unit + "\n# edited\n"})
	h2, _ := hashDirExcluding(filepath.Join(root, ".terragrunt-cache/a/b/net"), map[string]bool{"terragrunt.hcl": true, "provider.tf": true})
	if h1 != h2 {
		t.Error("unit edits changed the module hash")
	}
}

func TestNormalizeTerragruntSource(t *testing.T) {
	s, v := normalizeTerragruntSource("tfr:///terraform-aws-modules/vpc/aws?version=5.1.0")
	if s != "terraform-aws-modules/vpc/aws" || v != "5.1.0" {
		t.Errorf("got %q %q", s, v)
	}
	s, v = normalizeTerragruntSource("tfr://registry.opentofu.org/acme/net/aws?version=1.0.0")
	if s != "registry.opentofu.org/acme/net/aws" || v != "1.0.0" {
		t.Errorf("got %q %q", s, v)
	}
}
