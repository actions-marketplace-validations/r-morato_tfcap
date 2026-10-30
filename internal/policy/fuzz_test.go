package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/r-morato/tfcap/internal/model"
)

// FuzzLoad: tfcap.hcl is read from the repository under review.
func FuzzLoad(f *testing.F) {
	f.Add(`allow { rules = ["TFCAP-NET-*"]  reason = "r"  approved_by = "@a"  expires = "2026-12-01"  module = "module.x"  detail = "host:*" }`)
	f.Add(`allow { }`)
	f.Add(`deny "x" { }`)
	f.Fuzz(func(t *testing.T, src string) {
		p := filepath.Join(t.TempDir(), FileName)
		if err := os.WriteFile(p, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		pol, err := Load(p, day)
		if err != nil {
			return
		}
		pol.Apply([]model.Capability{{RuleID: "TFCAP-NET-003", Module: "x", Detail: "host:a"}}, day)
	})
}
