package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/r-morato/tfcap/internal/model"
	"github.com/r-morato/tfcap/internal/rules"
)

var day = time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)

func write(t *testing.T, src string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), FileName)
	if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadErrors(t *testing.T) {
	for name, src := range map[string]string{
		"no rules":   `allow { reason = "x"  approved_by = "@a"  expires = "2026-12-01"  rules = [] }`,
		"no reason":  `allow { rules = ["TFCAP-NET-003"]  approved_by = "@a"  expires = "2026-12-01" }`,
		"bad date":   `allow { rules = ["TFCAP-NET-003"]  reason = "x"  approved_by = "@a"  expires = "soon" }`,
		"too far":    `allow { rules = ["TFCAP-NET-003"]  reason = "x"  approved_by = "@a"  expires = "2030-01-01" }`,
		"unknown":    `allow { rules = ["TFCAP-NET-003"]  reason = "x"  approved_by = "@a"  expires = "2026-12-01"  severity = "low" }`,
		"expression": `allow { rules = ["TFCAP-NET-003"]  reason = var.x  approved_by = "@a"  expires = "2026-12-01" }`,
		"top attr":   `fail_on = "high"`,
		"other blk":  `deny { }`,
	} {
		if _, err := Load(write(t, src), day); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if p, err := Load(filepath.Join(t.TempDir(), "missing.hcl"), day); p != nil || err != nil {
		t.Errorf("missing file: %v %v", p, err)
	}
}

func TestApply(t *testing.T) {
	p, err := Load(write(t, `
allow {
  module      = "module.network"
  rules       = ["TFCAP-NET-003"]
  detail      = "host:*.amazonaws.com"
  reason      = "Talks to AWS APIs"
  approved_by = "@alice"
  expires     = "2026-10-25"
}
allow {
  rules       = ["TFCAP-EXEC-*"]
  reason      = "old waiver"
  approved_by = "@bob"
  expires     = "2026-10-01"
}
allow {
  rules       = ["*"]
  reason      = "tries to waive everything"
  approved_by = "@mallory"
  expires     = "2026-12-01"
  module      = "evil"
}
`), day)
	if err != nil {
		t.Fatal(err)
	}
	caps := []model.Capability{
		{RuleID: "TFCAP-NET-003", Module: "network", Detail: "host:sts.amazonaws.com"},
		{RuleID: "TFCAP-NET-003", Module: "network", Detail: "host:evil.example"},
		{RuleID: "TFCAP-NET-003", Module: "other", Detail: "host:sts.amazonaws.com"},
		{RuleID: "TFCAP-EXEC-001", Module: "network"},
		{RuleID: "TFCAP-FS-001", Module: "evil"},
		{RuleID: rules.SrcContentChanged, Module: "evil"},
		{RuleID: rules.ProvMutated, Module: "evil"},
	}
	o := p.Apply(caps, day)
	if len(o.Accepted) != 2 || o.Accepted[0].ApprovedBy != "@alice" || o.Accepted[1].RuleID != "TFCAP-FS-001" {
		t.Errorf("accepted: %+v", o.Accepted)
	}
	if len(o.Kept) != 5 {
		t.Errorf("kept %d: %+v", len(o.Kept), o.Kept)
	}
	w := strings.Join(o.Warnings, "\n")
	if !strings.Contains(w, "expired on 2026-10-01") || !strings.Contains(w, "expires on 2026-10-25") {
		t.Errorf("warnings: %s", w)
	}
	// The day after expiry, the exception no longer applies.
	if o := p.Apply(caps[:1], time.Date(2026, 10, 26, 0, 0, 1, 0, time.UTC)); len(o.Accepted) != 0 {
		t.Errorf("expired exception still applied: %+v", o.Accepted)
	}
	// Still valid on the expiry day itself.
	if o := p.Apply(caps[:1], time.Date(2026, 10, 25, 23, 0, 0, 0, time.UTC)); len(o.Accepted) != 1 {
		t.Errorf("exception should hold through its expiry day")
	}
	var nilPolicy *Policy
	if o := nilPolicy.Apply(caps, day); len(o.Kept) != len(caps) {
		t.Errorf("nil policy should keep everything")
	}
}
