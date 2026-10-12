// Package discover finds every module that makes up a Terraform
// configuration: the root module, local child modules, and remote modules
// that `terraform init` has downloaded into .terraform/modules.
package discover

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/r-morato/tfcap/internal/analyze"
	"github.com/r-morato/tfcap/internal/model"
	"github.com/r-morato/tfcap/internal/rules"
)

// manifest mirrors .terraform/modules/modules.json, which both Terraform
// and OpenTofu write during init.
type manifest struct {
	Modules []struct {
		Key     string `json:"Key"`
		Source  string `json:"Source"`
		Version string `json:"Version"`
		Dir     string `json:"Dir"`
	} `json:"Modules"`
}

// Options control discovery and scanning.
type Options struct {
	// DataDir overrides the .terraform directory (TF_DATA_DIR).
	DataDir string
	// ThirdPartyOnly drops capabilities from first-party modules.
	ThirdPartyOnly bool
	// Version is stamped into the report.
	Version string
}

// Scan discovers and analyzes every module under root.
func Scan(root string, opts Options) (*model.Report, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if st, err := os.Stat(abs); err != nil || !st.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}
	dataDir := opts.DataDir
	if dataDir == "" {
		dataDir = os.Getenv("TF_DATA_DIR")
	}
	if dataDir == "" {
		dataDir = ".terraform"
	}
	if !filepath.IsAbs(dataDir) {
		dataDir = filepath.Join(abs, dataDir)
	}

	rep := &model.Report{Schema: model.ReportSchema, Tool: "tfcap", Version: opts.Version, Root: root}
	s := &scanner{root: abs, rep: rep, opts: opts, done: map[string]bool{}}

	if m, err := readManifest(filepath.Join(dataDir, "modules", "modules.json")); err == nil {
		s.fromManifest(m)
	} else {
		s.walkLocal("", abs, model.SourceRoot, ".", "", false)
	}
	rep.Sort()
	return rep, nil
}

type scanner struct {
	root string
	rep  *model.Report
	opts Options
	done map[string]bool
}

func readManifest(p string) (*manifest, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var m manifest
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("parse %s: %w", p, err)
	}
	return &m, nil
}

func (s *scanner) fromManifest(m *manifest) {
	sources := map[string]string{}
	for _, e := range m.Modules {
		sources[e.Key] = e.Source
	}
	for _, e := range m.Modules {
		kind := model.SourceRoot
		if e.Key != "" {
			kind = analyze.ClassifySource(e.Source).Kind
		}
		third := isThirdParty(e.Key, sources)
		dir := e.Dir
		if !filepath.IsAbs(dir) {
			dir = filepath.Join(s.root, filepath.FromSlash(dir))
		}
		s.analyzeModule(e.Key, e.Source, e.Version, kind, dir, third)
	}
}

// isThirdParty reports whether key, or any ancestor of key, came from a
// non-local source. A local submodule of a registry module is still
// third-party code.
func isThirdParty(key string, sources map[string]string) bool {
	if key == "" {
		return false
	}
	parts := strings.Split(key, ".")
	for i := 1; i <= len(parts); i++ {
		k := strings.Join(parts[:i], ".")
		src, ok := sources[k]
		if !ok {
			continue
		}
		kind := analyze.ClassifySource(src).Kind
		if kind != model.SourceLocal && kind != model.SourceRoot {
			return true
		}
	}
	return false
}

// walkLocal is used when no manifest exists (init not run): analyze the
// root and follow local module calls; report remote ones as unanalyzed.
func (s *scanner) walkLocal(key, dir string, kind model.SourceKind, source, version string, third bool) {
	res := s.analyzeModule(key, source, version, kind, dir, third)
	if res == nil {
		return
	}
	for _, c := range res.Calls {
		childKey := c.Name
		if key != "" {
			childKey = key + "." + c.Name
		}
		info := analyze.ClassifySource(c.Source)
		if info.Kind == model.SourceLocal {
			s.walkLocal(childKey, filepath.Join(dir, filepath.FromSlash(c.Source)), model.SourceLocal, c.Source, "", third)
			continue
		}
		r := rules.Get(rules.SrcNotDownloaded)
		s.addCap(model.Capability{
			RuleID: r.ID, Severity: r.Severity, Phase: r.Phase, Module: key, Address: "module." + c.Name,
			File: c.File, Line: c.Line, Message: "Remote module not analyzed (run `terraform init` first): " + c.Source,
			Detail: "src:" + c.Source,
		}, third)
	}
}

func (s *scanner) analyzeModule(key, source, version string, kind model.SourceKind, dir string, third bool) *analyze.Result {
	if s.done[key] {
		return nil
	}
	s.done[key] = true
	mod := model.Module{Key: key, Source: source, Version: version, Kind: kind, Dir: s.rel(dir), ThirdParty: third}
	res, err := analyze.Dir(dir, key, analyze.Options{ThirdParty: third})
	if err != nil {
		s.rep.Errors = append(s.rep.Errors, fmt.Sprintf("module %q: %v", displayKey(key), err))
		s.rep.Modules = append(s.rep.Modules, mod)
		return nil
	}
	mod.Files = res.Files
	mod.Providers = res.Providers
	if third {
		mod.Hash, _ = HashDir(dir)
	}
	s.rep.Modules = append(s.rep.Modules, mod)
	for _, e := range res.Errors {
		s.rep.Errors = append(s.rep.Errors, fmt.Sprintf("module %q: %s", displayKey(key), e))
	}
	for _, c := range res.Capabilities {
		s.addCap(c, third)
	}
	return res
}

func (s *scanner) addCap(c model.Capability, third bool) {
	if s.opts.ThirdPartyOnly && !third {
		return
	}
	s.rep.Capabilities = append(s.rep.Capabilities, c)
}

func (s *scanner) rel(dir string) string {
	r, err := filepath.Rel(s.root, dir)
	if err != nil {
		return dir
	}
	return filepath.ToSlash(r)
}

func displayKey(k string) string {
	if k == "" {
		return "(root)"
	}
	return k
}

// HashDir returns a stable content hash of a module directory: sha256 over
// sorted relative paths and file contents, ignoring VCS and Terraform
// working directories. It is independent of mtimes, permissions and CRLF
// vs LF line endings.
func HashDir(dir string) (string, error) {
	var files []string
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != dir && (d.Name() == ".git" || d.Name() == ".terraform") {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type().IsRegular() {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	sort.Strings(files)
	h := sha256.New()
	for _, f := range files {
		rel, _ := filepath.Rel(dir, f)
		b, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}
		// Normalize line endings so the hash is the same on Windows
		// checkouts with core.autocrlf.
		b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
		fmt.Fprintf(h, "%s\x00%d\x00", filepath.ToSlash(rel), len(b))
		h.Write(b)
	}
	return "tfcap1:" + hex.EncodeToString(h.Sum(nil)), nil
}
