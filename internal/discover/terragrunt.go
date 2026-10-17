package discover

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/r-morato/tfcap/internal/analyze"
	"github.com/r-morato/tfcap/internal/model"
	"github.com/r-morato/tfcap/internal/rules"
)

// TerragruntKey is the module key given to the module a terragrunt.hcl
// pulls in through terraform.source.
const TerragruntKey = "terragrunt"

// terragruntSource reads terraform { source = "..." } from terragrunt.hcl.
// ok is false when there is no source; a non-literal source is returned
// with literal false.
func terragruntSource(dir string) (src string, line int, literal, ok bool) {
	b, err := os.ReadFile(filepath.Join(dir, "terragrunt.hcl"))
	if err != nil {
		return "", 0, false, false
	}
	f, diags := hclsyntax.ParseConfig(b, "terragrunt.hcl", hcl.InitialPos)
	if diags.HasErrors() {
		return "", 0, false, false
	}
	for _, blk := range f.Body.(*hclsyntax.Body).Blocks {
		if blk.Type != "terraform" {
			continue
		}
		at, found := blk.Body.Attributes["source"]
		if !found {
			continue
		}
		line = at.SrcRange.Start.Line
		v, d := at.Expr.Value(nil)
		if d.HasErrors() || v.Type() != cty.String || v.IsNull() {
			return "", line, false, true
		}
		return v.AsString(), line, true, true
	}
	return "", 0, false, false
}

// normalizeTerragruntSource turns Terragrunt's tfr:// registry syntax into
// a Terraform registry source plus version.
func normalizeTerragruntSource(src string) (source, version string) {
	rest, ok := strings.CutPrefix(src, "tfr://")
	if !ok {
		return src, ""
	}
	u, err := url.Parse("tfr://" + rest)
	if err != nil {
		return src, ""
	}
	host := u.Host
	path := strings.TrimPrefix(u.Path, "/")
	source = path
	if host != "" {
		source = host + "/" + path
	}
	return source, u.Query().Get("version")
}

// terragruntWorkDir finds the module copy Terragrunt downloaded for this
// unit: .terragrunt-cache/<a>/<b>/<subdir>. With several candidates, the
// most recently updated one is used.
func terragruntWorkDir(dir, source string) (workDir, repoDir string) {
	cands, _ := filepath.Glob(filepath.Join(dir, ".terragrunt-cache", "*", "*", ".terragrunt-source-version"))
	var best os.FileInfo
	for _, c := range cands {
		st, err := os.Stat(c)
		if err != nil {
			continue
		}
		if best == nil || st.ModTime().After(best.ModTime()) {
			best, repoDir = st, filepath.Dir(c)
		}
	}
	if repoDir == "" {
		return "", ""
	}
	workDir = repoDir
	if sub := subdir(source); sub != "" {
		workDir = filepath.Join(repoDir, filepath.FromSlash(sub))
	}
	if st, err := os.Stat(workDir); err != nil || !st.IsDir() {
		return "", ""
	}
	return workDir, repoDir
}

// subdir returns the //sub/dir part of a module source.
func subdir(src string) string {
	s := src
	if i := strings.Index(s, "::"); i >= 0 {
		s = s[i+2:]
	}
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	i := strings.Index(s, "//")
	if i < 0 {
		return ""
	}
	sub := s[i+2:]
	if j := strings.IndexAny(sub, "?#"); j >= 0 {
		sub = sub[:j]
	}
	return strings.Trim(sub, "/")
}

// scanTerragrunt adds the module a terragrunt.hcl pulls in. It runs a
// nested scan of Terragrunt's working copy, treats everything there as
// third-party under the key "terragrunt", and leaves out files Terragrunt
// copied or generated from the unit itself (they are your code).
func (s *scanner) scanTerragrunt() {
	raw, line, literal, ok := terragruntSource(s.root)
	if !ok {
		return
	}
	addr := "terraform.source"
	if !literal {
		s.rep.Errors = append(s.rep.Errors, "terragrunt.hcl: terraform.source is an expression; tfcap only follows literal sources")
		return
	}
	source, version := normalizeTerragruntSource(raw)
	for _, c := range analyze.SourceFindings("", "terragrunt.hcl", addr, line, source, version) {
		s.addCap(c, false)
	}
	kind := analyze.ClassifySource(source).Kind
	if kind == model.SourceLocal {
		return // your own code; reviewed like any local module
	}
	workDir, repoDir := terragruntWorkDir(s.root, source)
	if workDir == "" {
		r := rules.Get(rules.SrcNotDownloaded)
		s.rep.Modules = append(s.rep.Modules, model.Module{Key: TerragruntKey, Source: source, Version: version, Kind: kind, ThirdParty: true,
			Anchor: &model.Location{File: "terragrunt.hcl", Line: line}})
		s.addCap(model.Capability{RuleID: r.ID, Severity: r.Severity, Phase: r.Phase, Module: TerragruntKey, Address: "module." + TerragruntKey,
			Message: "Terragrunt module " + source + " is not downloaded: run `terragrunt init` first", Detail: "src:" + source}, true)
		return
	}
	own := map[string]bool{}
	if es, err := os.ReadDir(s.root); err == nil {
		for _, e := range es {
			if !e.IsDir() {
				own[e.Name()] = true
			}
		}
	}
	// Generated files (generate blocks) are written into the working copy
	// but are not in the unit dir; they are listed in the module manifest.
	for _, g := range terragruntGenerated(s.root) {
		own[g] = true
	}
	sub, err := Scan(workDir, Options{Version: s.opts.Version, inTerragrunt: true})
	if err != nil {
		s.rep.Errors = append(s.rep.Errors, "terragrunt: "+err.Error())
		return
	}
	prefix := func(k string) string {
		if k == "" {
			return TerragruntKey
		}
		return TerragruntKey + "." + k
	}
	for _, m := range sub.Modules {
		m.Key = prefix(m.Key)
		m.ThirdParty = true
		m.Dir = s.rel(filepath.Join(workDir, m.Dir))
		if m.Key == TerragruntKey {
			m.Source, m.Version, m.Kind = source, version, kind
			m.Hash, _ = hashDirExcluding(workDir, own)
			m.Commit = gitCommit(workDir, filepath.Dir(repoDir))
			m.Anchor = &model.Location{File: "terragrunt.hcl", Line: line}
		} else if m.Anchor != nil {
			m.Anchor = &model.Location{File: "terragrunt.hcl", Line: line}
		}
		m.Call = nil
		s.rep.Modules = append(s.rep.Modules, m)
	}
	for _, c := range sub.Capabilities {
		if c.Module == "" && own[c.File] {
			continue // copied or generated from the unit: your code
		}
		c.Module = prefix(c.Module)
		s.addCap(c, true)
	}
	for _, e := range sub.Errors {
		s.rep.Errors = append(s.rep.Errors, "terragrunt: "+e)
	}
	if len(s.rep.ProviderLocks) == 0 {
		s.rep.ProviderLocks = sub.ProviderLocks
	}
}

// terragruntGenerated lists file names declared by generate blocks.
func terragruntGenerated(dir string) []string {
	b, err := os.ReadFile(filepath.Join(dir, "terragrunt.hcl"))
	if err != nil {
		return nil
	}
	f, diags := hclsyntax.ParseConfig(b, "terragrunt.hcl", hcl.InitialPos)
	if diags.HasErrors() {
		return nil
	}
	var out []string
	for _, blk := range f.Body.(*hclsyntax.Body).Blocks {
		if blk.Type != "generate" {
			continue
		}
		if at, ok := blk.Body.Attributes["path"]; ok {
			if v, d := at.Expr.Value(nil); !d.HasErrors() && v.Type() == cty.String && !v.IsNull() {
				out = append(out, filepath.Base(v.AsString()))
			}
		}
	}
	return out
}
