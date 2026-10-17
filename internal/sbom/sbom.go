// Package sbom renders a CycloneDX 1.6 bill of materials for a Terraform
// configuration: third-party modules (with their content hash and resolved
// commit) and providers (with the checksums from .terraform.lock.hcl).
package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/r-morato/tfcap/internal/analyze"
	"github.com/r-morato/tfcap/internal/model"
)

// BOM is the subset of CycloneDX 1.6 that tfcap emits.
type BOM struct {
	BOMFormat    string       `json:"bomFormat"`
	SpecVersion  string       `json:"specVersion"`
	SerialNumber string       `json:"serialNumber"`
	Version      int          `json:"version"`
	Metadata     Metadata     `json:"metadata"`
	Components   []Component  `json:"components"`
	Dependencies []Dependency `json:"dependencies"`
}

type Metadata struct {
	Timestamp string     `json:"timestamp,omitempty"`
	Tools     Tools      `json:"tools"`
	Component Component  `json:"component"`
	Props     []Property `json:"properties,omitempty"`
}

type Tools struct {
	Components []Component `json:"components"`
}

type Component struct {
	Type        string        `json:"type"`
	BOMRef      string        `json:"bom-ref,omitempty"`
	Group       string        `json:"group,omitempty"`
	Name        string        `json:"name"`
	Version     string        `json:"version,omitempty"`
	Description string        `json:"description,omitempty"`
	Purl        string        `json:"purl,omitempty"`
	Hashes      []Hash        `json:"hashes,omitempty"`
	ExtRefs     []ExternalRef `json:"externalReferences,omitempty"`
	Properties  []Property    `json:"properties,omitempty"`
	Scope       string        `json:"scope,omitempty"`
	Supplier    *Supplier     `json:"supplier,omitempty"`
}

type Supplier struct {
	Name string `json:"name"`
}

type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type ExternalRef struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Dependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn"`
}

var githubRe = regexp.MustCompile(`(?i)github\.com[/:]([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+?)(\.git)?([/?#]|$)`)

// Build creates the BOM. name labels the root component (usually the
// directory name); ts is the timestamp, or zero to omit it.
func Build(rep *model.Report, name, toolVersion string, ts time.Time) *BOM {
	root := Component{Type: "application", BOMRef: "root", Name: name,
		Description: "Terraform/OpenTofu configuration"}
	b := &BOM{BOMFormat: "CycloneDX", SpecVersion: "1.6", Version: 1,
		Metadata: Metadata{
			Tools: Tools{Components: []Component{{Type: "application", Name: "tfcap", Version: toolVersion,
				ExtRefs: []ExternalRef{{"vcs", "https://github.com/r-morato/tfcap"}}}}},
			Component: root,
		},
		Components: []Component{}, Dependencies: []Dependency{}}
	if !ts.IsZero() {
		b.Metadata.Timestamp = ts.UTC().Format(time.RFC3339)
	}
	deps := map[string][]string{"root": {}}
	caps := map[string]map[model.Severity]int{}
	for _, c := range rep.Capabilities {
		if caps[c.Module] == nil {
			caps[c.Module] = map[model.Severity]int{}
		}
		caps[c.Module][c.Severity]++
	}
	for _, m := range rep.Modules {
		if !m.ThirdParty {
			continue
		}
		ref := "module:" + m.Key
		comp := Component{Type: "library", BOMRef: ref, Name: m.Source, Version: m.Version, Scope: "required"}
		props := []Property{
			{"tfcap:module:key", m.Key},
			{"tfcap:module:address", "module." + strings.ReplaceAll(m.Key, ".", ".module.")},
			{"tfcap:source:kind", string(m.Kind)},
		}
		if m.Hash != "" {
			// tfcap1: is SHA-256 over the module's normalized file tree,
			// not over an archive, so it is a property rather than a hash.
			props = append(props, Property{"tfcap:content-hash", m.Hash})
		}
		if m.Commit != "" {
			props = append(props, Property{"tfcap:git:commit", m.Commit})
		}
		if cs := caps[m.Key]; len(cs) > 0 {
			for _, sev := range []model.Severity{model.Critical, model.High, model.Medium, model.Low, model.Info} {
				if n := cs[sev]; n > 0 {
					props = append(props, Property{"tfcap:capabilities:" + sev.String(), fmt.Sprint(n)})
				}
			}
		}
		src := analyze.ClassifySource(m.Source)
		if gm := githubRe.FindStringSubmatch(m.Source); gm != nil && (m.Kind == model.SourceGit) {
			ver := m.Commit
			if ver == "" {
				ver = src.Ref
			}
			comp.Purl = purl("github", strings.ToLower(gm[1]), strings.ToLower(gm[2]), ver)
			if sub := subdir(m.Source); sub != "" {
				comp.Purl += "#" + sub
			}
			comp.ExtRefs = append(comp.ExtRefs, ExternalRef{"vcs", "https://github.com/" + gm[1] + "/" + gm[2]})
			if comp.Version == "" {
				comp.Version = ver
			}
		}
		if m.Kind == model.SourceRegistry {
			parts := strings.Split(strings.SplitN(m.Source, "//", 2)[0], "/")
			if len(parts) == 3 {
				parts = append([]string{"registry.terraform.io"}, parts...)
			}
			if len(parts) == 4 {
				comp.Group = parts[1]
				comp.Name = parts[2] + "/" + parts[3]
				comp.Supplier = &Supplier{Name: parts[1]}
				props = append(props, Property{"tfcap:registry", parts[0]})
				if parts[0] == "registry.terraform.io" || parts[0] == "registry.opentofu.org" {
					comp.ExtRefs = append(comp.ExtRefs, ExternalRef{"distribution",
						"https://" + parts[0] + "/modules/" + strings.Join(parts[1:], "/") + "/" + m.Version})
				}
			}
		}
		comp.Properties = props
		b.Components = append(b.Components, comp)
		parent := "root"
		if i := strings.LastIndex(m.Key, "."); i >= 0 {
			parent = "module:" + m.Key[:i]
		}
		deps[parent] = append(deps[parent], ref)
		if _, ok := deps[ref]; !ok {
			deps[ref] = []string{}
		}
	}
	for _, p := range rep.ProviderLocks {
		ref := "provider:" + p.Address
		parts := strings.Split(p.Address, "/")
		comp := Component{Type: "library", BOMRef: ref, Name: p.Address, Version: p.Version, Scope: "required"}
		if len(parts) == 3 {
			comp.Group, comp.Name = parts[1], parts[2]
			comp.Supplier = &Supplier{Name: parts[1]}
			comp.Purl = purl("terraform-provider", parts[1], parts[2], p.Version) + "?registry=" + parts[0]
		}
		props := []Property{{"tfcap:provider:address", p.Address}}
		for _, h := range p.Hashes {
			if zh, ok := strings.CutPrefix(h, "zh:"); ok {
				// zh: is the SHA-256 of one platform's release zip.
				comp.Hashes = append(comp.Hashes, Hash{"SHA-256", zh})
				continue
			}
			props = append(props, Property{"tfcap:provider:hash", h})
		}
		comp.Properties = props
		b.Components = append(b.Components, comp)
		deps["root"] = append(deps["root"], ref)
		deps[ref] = []string{}
	}
	refs := make([]string, 0, len(deps))
	for r := range deps {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	for _, r := range refs {
		d := deps[r]
		sort.Strings(d)
		b.Dependencies = append(b.Dependencies, Dependency{Ref: r, DependsOn: d})
	}
	b.SerialNumber = serial(b)
	return b
}

// purl builds a package URL. terraform-provider is not a registered purl
// type, so consumers that only know registered types will ignore it.
func purl(typ, ns, name, ver string) string {
	s := "pkg:" + typ + "/" + ns + "/" + name
	if ver != "" {
		s += "@" + strings.ReplaceAll(ver, "/", "%2F")
	}
	return s
}

// subdir returns the //sub/dir part of a module source, if any.
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

// serial derives a stable UUID from the BOM contents (ignoring the
// timestamp), so the same configuration always yields the same serial.
func serial(b *BOM) string {
	c := *b
	c.Metadata.Timestamp = ""
	c.SerialNumber = ""
	j, _ := json.Marshal(c)
	h := sha256.Sum256(j)
	h[6] = h[6]&0x0f | 0x50 // version 5 style
	h[8] = h[8]&0x3f | 0x80
	x := hex.EncodeToString(h[:16])
	return fmt.Sprintf("urn:uuid:%s-%s-%s-%s-%s", x[:8], x[8:12], x[12:16], x[16:20], x[20:32])
}

// Write renders the BOM as indented JSON.
func Write(w io.Writer, b *BOM) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(b)
}
