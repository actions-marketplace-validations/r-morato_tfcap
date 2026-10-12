// Package diff compares two capability reports, typically the base and
// head of a pull request, and reports capabilities that appeared or
// disappeared.
package diff

import (
	"sort"

	"github.com/r-morato/tfcap/internal/model"
)

// ModuleChange is a module whose source or version differs between reports.
type ModuleChange struct {
	Key         string `json:"key"`
	FromSource  string `json:"from_source,omitempty"`
	ToSource    string `json:"to_source,omitempty"`
	FromVersion string `json:"from_version,omitempty"`
	ToVersion   string `json:"to_version,omitempty"`
	FromHash    string `json:"from_hash,omitempty"`
	ToHash      string `json:"to_hash,omitempty"`
	Status      string `json:"status"` // added, removed, changed
}

// Result is the difference between two reports.
type Result struct {
	Schema  string             `json:"schema"`
	Added   []model.Capability `json:"added"`
	Removed []model.Capability `json:"removed"`
	Modules []ModuleChange     `json:"modules"`
}

const Schema = "tfcap/diff/v1"

// Compare returns capabilities in head that are not in base (Added) and
// vice versa (Removed). Capabilities are matched by fingerprint, which
// ignores line numbers and module versions.
func Compare(base, head *model.Report) *Result {
	r := &Result{Schema: Schema, Added: []model.Capability{}, Removed: []model.Capability{}, Modules: []ModuleChange{}}
	bset := index(base.Capabilities)
	hset := index(head.Capabilities)
	for fp, c := range hset {
		if _, ok := bset[fp]; !ok {
			r.Added = append(r.Added, c)
		}
	}
	for fp, c := range bset {
		if _, ok := hset[fp]; !ok {
			r.Removed = append(r.Removed, c)
		}
	}
	sortCaps(r.Added)
	sortCaps(r.Removed)

	bm := map[string]model.Module{}
	for _, m := range base.Modules {
		bm[m.Key] = m
	}
	hm := map[string]model.Module{}
	for _, m := range head.Modules {
		hm[m.Key] = m
	}
	for k, h := range hm {
		b, ok := bm[k]
		switch {
		case !ok:
			r.Modules = append(r.Modules, ModuleChange{Key: k, ToSource: h.Source, ToVersion: h.Version, ToHash: h.Hash, Status: "added"})
		case b.Source != h.Source || b.Version != h.Version || (b.Hash != "" && h.Hash != "" && b.Hash != h.Hash):
			r.Modules = append(r.Modules, ModuleChange{Key: k, FromSource: b.Source, ToSource: h.Source,
				FromVersion: b.Version, ToVersion: h.Version, FromHash: b.Hash, ToHash: h.Hash, Status: "changed"})
		}
	}
	for k, b := range bm {
		if _, ok := hm[k]; !ok {
			r.Modules = append(r.Modules, ModuleChange{Key: k, FromSource: b.Source, FromVersion: b.Version, FromHash: b.Hash, Status: "removed"})
		}
	}
	sort.Slice(r.Modules, func(i, j int) bool { return r.Modules[i].Key < r.Modules[j].Key })
	return r
}

func index(caps []model.Capability) map[string]model.Capability {
	m := make(map[string]model.Capability, len(caps))
	for _, c := range caps {
		fp := c.Fingerprint()
		if prev, ok := m[fp]; !ok || c.Severity > prev.Severity {
			m[fp] = c
		}
	}
	return m
}

func sortCaps(cs []model.Capability) {
	sort.SliceStable(cs, func(i, j int) bool {
		a, b := cs[i], cs[j]
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
}
