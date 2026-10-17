// Package pin rewrites module sources in first-party Terraform files to
// immutable references: git modules to the commit they resolved to, and
// (optionally) registry modules to the exact version that was installed.
package pin

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/r-morato/tfcap/internal/analyze"
	"github.com/r-morato/tfcap/internal/model"
)

// Change is one rewrite.
type Change struct {
	Module string `json:"module"`
	File   string `json:"file"`
	Line   int    `json:"line"`
	From   string `json:"from"`
	To     string `json:"to"`
	Note   string `json:"note,omitempty"`
}

// Options control which modules are pinned.
type Options struct {
	ExactRegistry bool // also pin registry version constraints to the installed version
}

type edit struct {
	start, end int
	text       string
	comment    string
}

// Plan works out the changes without writing anything. Skipped modules are
// returned as notes (for example a dynamic source, or a missing commit).
func Plan(root string, rep *model.Report, opts Options) (changes []Change, notes []string, edits map[string][]edit) {
	edits = map[string][]edit{}
	for _, m := range rep.Modules {
		if !m.ThirdParty || m.Call == nil {
			continue
		}
		key := "module." + strings.ReplaceAll(m.Key, ".", ".module.")
		file := filepath.Join(root, filepath.FromSlash(m.Call.File))
		src, err := os.ReadFile(file)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s: cannot read %s: %v", key, m.Call.File, err))
			continue
		}
		info := analyze.ClassifySource(m.Call.Source)
		switch info.Kind {
		case model.SourceGit:
			if analyze.IsSHA(info.Ref) {
				continue
			}
			if m.Commit == "" {
				notes = append(notes, key+": no commit recorded (run terraform init, which keeps the module's git metadata)")
				continue
			}
			if !isLiteral(src, m.Call.SourceStart, m.Call.SourceEnd, m.Call.Source) {
				notes = append(notes, key+": source is not a plain string, pin it by hand")
				continue
			}
			newSrc := withRef(m.Call.Source, m.Commit)
			was := "default branch"
			if info.Ref != "" {
				was = "ref=" + info.Ref
			}
			edits[file] = append(edits[file], edit{m.Call.SourceStart, m.Call.SourceEnd, strconv.Quote(newSrc), "tfcap pin: was " + was})
			changes = append(changes, Change{Module: key, File: m.Call.File, Line: lineOf(src, m.Call.SourceStart), From: m.Call.Source, To: newSrc, Note: was})
		case model.SourceRegistry:
			if !opts.ExactRegistry || analyze.IsExactVersion(m.Call.Version) || m.Version == "" {
				continue
			}
			if m.Call.VersionEnd == 0 {
				notes = append(notes, fmt.Sprintf("%s: no version argument; add version = %q", key, m.Version))
				continue
			}
			if !isLiteral(src, m.Call.VersionStart, m.Call.VersionEnd, m.Call.Version) {
				notes = append(notes, key+": version is not a plain string, pin it by hand")
				continue
			}
			edits[file] = append(edits[file], edit{m.Call.VersionStart, m.Call.VersionEnd, strconv.Quote(m.Version), "tfcap pin: was " + m.Call.Version})
			changes = append(changes, Change{Module: key, File: m.Call.File, Line: lineOf(src, m.Call.VersionStart), From: m.Call.Version, To: m.Version})
		}
	}
	sort.Slice(changes, func(i, j int) bool { return changes[i].File+changes[i].Module < changes[j].File+changes[j].Module })
	return changes, notes, edits
}

// Apply writes planned edits.
func Apply(edits map[string][]edit) error {
	for file, es := range edits {
		src, err := os.ReadFile(file)
		if err != nil {
			return err
		}
		sort.Slice(es, func(i, j int) bool { return es[i].start > es[j].start })
		for _, e := range es {
			lineEnd := bytes.IndexByte(src[e.end:], '\n')
			if lineEnd < 0 {
				lineEnd = len(src) - e.end
			}
			rest := src[e.end : e.end+lineEnd]
			var buf bytes.Buffer
			buf.Write(src[:e.start])
			buf.WriteString(e.text)
			buf.Write(rest)
			if !bytes.Contains(rest, []byte("#")) && !bytes.Contains(rest, []byte("//")) {
				buf.WriteString(" # " + e.comment)
			}
			buf.Write(src[e.end+lineEnd:])
			src = buf.Bytes()
		}
		st, err := os.Stat(file)
		if err != nil {
			return err
		}
		if err := os.WriteFile(file, src, st.Mode().Perm()); err != nil {
			return err
		}
	}
	return nil
}

func isLiteral(src []byte, start, end int, value string) bool {
	if end <= start || end > len(src) {
		return false
	}
	return string(src[start:end]) == strconv.Quote(value)
}

func lineOf(src []byte, off int) int { return bytes.Count(src[:off], []byte("\n")) + 1 }

// withRef sets the ref query parameter of a git source, keeping any
// //subdir and other parameters.
func withRef(src, ref string) string {
	base, query, _ := strings.Cut(src, "?")
	q, err := url.ParseQuery(query)
	if err != nil {
		q = url.Values{}
	}
	q.Set("ref", ref)
	// url.Values.Encode sorts keys; keep it readable for the common case.
	if len(q) == 1 {
		return base + "?ref=" + ref
	}
	return base + "?" + q.Encode()
}
