// Package output renders tfcap results as text, JSON, Markdown and SARIF.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"

	"github.com/r-morato/tfcap/internal/analyze"
	"github.com/r-morato/tfcap/internal/diff"
	"github.com/r-morato/tfcap/internal/lock"
	"github.com/r-morato/tfcap/internal/model"
	"github.com/r-morato/tfcap/internal/rules"
)

// Style controls terminal rendering.
type Style struct {
	Color bool
}

const (
	reset  = "\x1b[0m"
	bold   = "\x1b[1m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	yellow = "\x1b[33m"
	blue   = "\x1b[34m"
	green  = "\x1b[32m"
	mag    = "\x1b[35m"
)

func (s Style) c(code, text string) string {
	if !s.Color {
		return text
	}
	return code + text + reset
}

func (s Style) sev(v model.Severity) string {
	label := fmt.Sprintf("%-8s", strings.ToUpper(v.String()))
	switch v {
	case model.Critical:
		return s.c(bold+mag, label)
	case model.High:
		return s.c(bold+red, label)
	case model.Medium:
		return s.c(yellow, label)
	case model.Low:
		return s.c(blue, label)
	}
	return s.c(dim, label)
}

func displayKey(k string) string {
	if k == "" {
		return "(root)"
	}
	return "module." + strings.ReplaceAll(k, ".", ".module.")
}

// JSON writes v as indented JSON.
func JSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// ---- scan ----

// Report renders a scan report as human-readable text.
func Report(w io.Writer, rep *model.Report, st Style) {
	byMod := map[string][]model.Capability{}
	for _, c := range rep.Capabilities {
		byMod[c.Module] = append(byMod[c.Module], c)
	}
	counts := map[model.Severity]int{}
	for _, m := range rep.Modules {
		caps := byMod[m.Key]
		header := displayKey(m.Key)
		meta := []string{}
		if m.Source != "" && m.Key != "" {
			src := m.Source
			if m.Version != "" {
				src += "@" + m.Version
			}
			meta = append(meta, src)
		}
		if m.ThirdParty {
			meta = append(meta, "third-party")
		}
		fmt.Fprintf(w, "%s %s\n", st.c(bold, header), st.c(dim, strings.Join(meta, " · ")))
		if len(caps) == 0 {
			fmt.Fprintf(w, "  %s\n\n", st.c(green, "no capabilities detected"))
			continue
		}
		for _, c := range caps {
			counts[c.Severity]++
			loc := c.File
			if c.Line > 0 {
				loc = fmt.Sprintf("%s:%d", c.File, c.Line)
			}
			fmt.Fprintf(w, "  %s %s %s\n", st.sev(c.Severity), st.c(dim, fmt.Sprintf("[%s]", c.Phase)), c.Message)
			fmt.Fprintf(w, "           %s %s\n", st.c(dim, c.RuleID), st.c(dim, joinNonEmpty(" ", c.Address, loc)))
			if len(c.Tags) > 0 {
				fmt.Fprintf(w, "           %s\n", st.c(dim, "tags: "+strings.Join(c.Tags, ", ")))
			}
		}
		fmt.Fprintln(w)
	}
	for _, e := range rep.Errors {
		fmt.Fprintf(w, "%s %s\n", st.c(red, "error:"), e)
	}
	fmt.Fprintln(w, checkedLine(rep, st))
	if len(rep.Capabilities) == 0 {
		fmt.Fprintln(w, st.c(green, "No capabilities found."))
	} else {
		fmt.Fprintf(w, "%s %s\n", plural(len(rep.Capabilities), "capability", "capabilities"), summary(counts, st))
	}
	acceptedLine(w, rep.Accepted, st)
	if n := countRule(rep.Capabilities, rules.SrcNotDownloaded); n > 0 {
		fmt.Fprintln(w, st.c(yellow, fmt.Sprintf("%s not analyzed because it is not downloaded: run `terraform init` (or `tofu init`) first.",
			plural(n, "remote module", "remote modules"))))
	}
}

// checkedLine says what was examined, so a clean result is visibly a real
// check rather than an empty run.
func checkedLine(rep *model.Report, st Style) string {
	third, files := 0, 0
	provs := map[string]bool{}
	for _, m := range rep.Modules {
		if m.ThirdParty {
			third++
		}
		files += m.Files
		for _, p := range m.Providers {
			provs[strings.ToLower(p.Source)] = true
		}
	}
	squat := map[string]bool{}
	for _, c := range rep.Capabilities {
		if c.RuleID == rules.ProvTyposquat {
			squat[strings.TrimPrefix(c.Detail, "provider:")] = true
		}
	}
	names := make([]string, 0, len(provs))
	for p := range provs {
		short := p
		if parts := strings.Split(p, "/"); len(parts) == 3 {
			short = parts[1] + "/" + parts[2]
		}
		if squat[short] {
			names = append(names, st.c(bold+mag, short+" ✗ typosquat"))
		} else {
			names = append(names, short+" ✓")
		}
	}
	sort.Strings(names)
	line := fmt.Sprintf("Checked %s (%d third-party, %s)", plural(len(rep.Modules), "module", "modules"), third, plural(files, "file", "files"))
	if len(names) > 0 {
		line += fmt.Sprintf(" and %s: %s", plural(len(names), "provider", "providers"), strings.Join(names, ", "))
	}
	return st.c(dim, line+".")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func countRule(caps []model.Capability, id string) int {
	n := 0
	for _, c := range caps {
		if c.RuleID == id {
			n++
		}
	}
	return n
}

func summary(counts map[model.Severity]int, st Style) string {
	var parts []string
	for s := model.Critical; s >= model.Info; s-- {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], s))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

func joinNonEmpty(sep string, parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, sep)
}

// ---- diff ----

// Diff renders a diff as text.
func Diff(w io.Writer, d *diff.Result, st Style) {
	if len(d.Modules) > 0 {
		fmt.Fprintln(w, st.c(bold, "Module changes"))
		for _, m := range d.Modules {
			fmt.Fprintf(w, "  %-8s %s %s\n", m.Status, displayKey(m.Key), st.c(dim, moduleChangeText(m)))
		}
		fmt.Fprintln(w)
	}
	if len(d.Added) == 0 {
		fmt.Fprintln(w, st.c(green, "No new capabilities."))
	} else {
		fmt.Fprintln(w, st.c(bold, fmt.Sprintf("New capabilities (%d)", len(d.Added))))
		for _, c := range d.Added {
			fmt.Fprintf(w, "  %s %s %s\n", st.c(green, "+"), st.sev(c.Severity), c.Message)
			fmt.Fprintf(w, "             %s\n", st.c(dim, joinNonEmpty(" ", c.RuleID, displayKey(c.Module), c.Address, fmt.Sprintf("%s:%d", c.File, c.Line))))
		}
	}
	if len(d.Removed) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, st.c(bold, fmt.Sprintf("Removed capabilities (%d)", len(d.Removed))))
		for _, c := range d.Removed {
			fmt.Fprintf(w, "  %s %s %s\n", st.c(red, "-"), st.sev(c.Severity), c.Message)
		}
	}
}

func moduleChangeText(m diff.ModuleChange) string {
	from := m.FromSource
	if m.FromVersion != "" {
		from += "@" + m.FromVersion
	}
	to := m.ToSource
	if m.ToVersion != "" {
		to += "@" + m.ToVersion
	}
	switch m.Status {
	case "added":
		return to
	case "removed":
		return from
	}
	if from == to && m.FromHash != m.ToHash {
		return from + " (content changed, same version)"
	}
	return from + " → " + to
}

// DiffMarkdown renders a diff for a pull-request comment.
func DiffMarkdown(w io.Writer, d *diff.Result) {
	fmt.Fprintln(w, "<!-- tfcap -->")
	fmt.Fprintln(w, "### tfcap: module capability changes")
	fmt.Fprintln(w)
	if len(d.Modules) > 0 {
		fmt.Fprintln(w, "| Module | Change |")
		fmt.Fprintln(w, "|---|---|")
		for _, m := range d.Modules {
			fmt.Fprintf(w, "| `%s` | %s: %s |\n", displayKey(m.Key), m.Status, mdEscape(moduleChangeText(m)))
		}
		fmt.Fprintln(w)
	}
	capsTable(w, "New capabilities", d.Added, true)
	if len(d.Removed) > 0 {
		fmt.Fprintf(w, "<details><summary>%d capabilities removed</summary>\n\n", len(d.Removed))
		capsTable(w, "", d.Removed, false)
		fmt.Fprintln(w, "</details>")
	}
}

func capsTable(w io.Writer, title string, caps []model.Capability, emptyNote bool) {
	if title != "" {
		fmt.Fprintf(w, "**%s (%d)**\n\n", title, len(caps))
	}
	if len(caps) == 0 {
		if emptyNote {
			fmt.Fprintln(w, "✅ None. Module behavior is unchanged.")
			fmt.Fprintln(w)
		}
		return
	}
	fmt.Fprintln(w, "| Severity | Phase | Capability | Where |")
	fmt.Fprintln(w, "|---|---|---|---|")
	for _, c := range caps {
		fmt.Fprintf(w, "| %s %s | %s | %s<br><sub>%s</sub> | `%s` %s |\n",
			sevEmoji(c.Severity), c.Severity, c.Phase, mdEscape(c.Message), c.RuleID,
			displayKey(c.Module), mdEscape(joinNonEmpty(" ", c.Address, fmt.Sprintf("%s:%d", c.File, c.Line))))
	}
	fmt.Fprintln(w)
}

func sevEmoji(s model.Severity) string {
	switch s {
	case model.Critical:
		return "🟣"
	case model.High:
		return "🔴"
	case model.Medium:
		return "🟠"
	case model.Low:
		return "🔵"
	}
	return "⚪"
}

func mdEscape(s string) string {
	return strings.NewReplacer("|", "\\|", "\n", " ", "<", "&lt;", ">", "&gt;").Replace(s)
}

// ---- verify ----

// Verify renders a lock verification result as text.
func Verify(w io.Writer, v *lock.Result, st Style) {
	for _, m := range v.Modules {
		var label string
		switch m.Status {
		case lock.StatusOK:
			label = st.c(green, "ok      ")
		case lock.StatusMutated:
			label = st.c(bold+mag, "MUTATED ")
		case lock.StatusUpgraded:
			label = st.c(yellow, "upgraded")
		case lock.StatusNew:
			label = st.c(yellow, "new     ")
		default:
			label = st.c(dim, fmt.Sprintf("%-8s", m.Status))
		}
		extra := m.Source
		if m.Status == lock.StatusUpgraded {
			extra = fmt.Sprintf("%s → %s", verLabel(m.LockedSource, m.LockedVer), verLabel(m.Source, m.CurrentVer))
		}
		fmt.Fprintf(w, "%s %s %s\n", label, displayKey(m.Key), st.c(dim, extra))
	}
	okProviders := 0
	for _, p := range v.Providers {
		switch p.Status {
		case "ok":
			okProviders++
		case "mutated":
			fmt.Fprintf(w, "%s provider %s %s\n", st.c(bold+mag, "MUTATED "), p.Address, st.c(dim, p.CurrentVersion))
		case "upgraded":
			fmt.Fprintf(w, "%s provider %s %s\n", st.c(yellow, "upgraded"), p.Address, st.c(dim, p.LockedVersion+" → "+p.CurrentVersion))
		default:
			fmt.Fprintf(w, "%s provider %s %s\n", st.c(yellow, fmt.Sprintf("%-8s", p.Status)), p.Address, st.c(dim, p.CurrentVersion+p.LockedVersion))
		}
	}
	if okProviders > 0 {
		fmt.Fprintf(w, "%s %s\n", st.c(green, "ok      "), st.c(dim, plural(okProviders, "provider", "providers")+" unchanged"))
	}
	fmt.Fprintln(w)
	acceptedLine(w, v.Accepted, st)
	if len(v.Findings) == 0 {
		fmt.Fprintln(w, st.c(green, "All third-party module capabilities match the lock."))
		return
	}
	fmt.Fprintln(w, st.c(bold, fmt.Sprintf("Unreviewed capabilities (%d)", len(v.Findings))))
	for _, c := range v.Findings {
		fmt.Fprintf(w, "  %s %s\n", st.sev(c.Severity), c.Message)
		fmt.Fprintf(w, "           %s\n", st.c(dim, joinNonEmpty(" ", c.RuleID, displayKey(c.Module), c.Address)))
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, st.c(dim, "Review the changes, then run `tfcap lock` to accept them."))
}

// VerifyMarkdown renders a verification result for a PR comment.
func VerifyMarkdown(w io.Writer, v *lock.Result) {
	fmt.Fprintln(w, "<!-- tfcap -->")
	fmt.Fprintln(w, "### tfcap: module lock verification")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "| Module | Status | Version |")
	fmt.Fprintln(w, "|---|---|---|")
	for _, m := range v.Modules {
		ver := verLabel(m.Source, m.CurrentVer)
		if m.Status == lock.StatusUpgraded {
			ver = verLabel(m.LockedSource, m.LockedVer) + " → " + verLabel(m.Source, m.CurrentVer)
		}
		status := m.Status
		if status == lock.StatusMutated {
			status = "🟣 **MUTATED**"
		}
		fmt.Fprintf(w, "| `%s` | %s | %s |\n", displayKey(m.Key), status, mdEscape(ver))
	}
	for _, p := range v.Providers {
		if p.Status == "ok" {
			continue
		}
		status := p.Status
		if status == "mutated" {
			status = "🟣 **MUTATED**"
		}
		ver := p.CurrentVersion
		if p.Status == "upgraded" {
			ver = p.LockedVersion + " → " + p.CurrentVersion
		}
		fmt.Fprintf(w, "| provider `%s` | %s | %s |\n", p.Address, status, mdEscape(ver))
	}
	fmt.Fprintln(w)
	capsTable(w, "Unreviewed capabilities", v.Findings, true)
	if len(v.Accepted) > 0 {
		fmt.Fprintf(w, "\n<details><summary>%s accepted by tfcap.hcl</summary>\n\n", plural(len(v.Accepted), "finding", "findings"))
		fmt.Fprintln(w, "| Severity | Rule | Where | Approved by | Expires | Reason |")
		fmt.Fprintln(w, "|---|---|---|---|---|---|")
		for _, a := range v.Accepted {
			fmt.Fprintf(w, "| %s | `%s` | %s | %s | %s | %s |\n", a.Severity, a.RuleID,
				mdEscape(joinNonEmpty(" ", displayKey(a.Module), a.Address)), mdEscape(a.ApprovedBy), a.Expires, mdEscape(a.Reason))
		}
		fmt.Fprintln(w, "\n</details>")
	}
}

// acceptedLine notes findings hidden by policy exceptions, so a quiet
// result never hides the fact that something was waived.
func acceptedLine(w io.Writer, acc []model.Accepted, st Style) {
	if len(acc) == 0 {
		return
	}
	fmt.Fprintln(w, st.c(dim, fmt.Sprintf("%s accepted by tfcap.hcl exceptions (use --no-policy to show them).",
		plural(len(acc), "finding", "findings"))))
}

// verLabel shows a registry version, or a git ref when the version lives
// in the source string, or the source itself as a last resort.
func verLabel(src, ver string) string {
	if ver != "" {
		return ver
	}
	if ref := analyze.ClassifySource(src).Ref; ref != "" {
		return "ref=" + ref
	}
	return src
}

// ---- rules ----

// Rules lists the rule catalog.
func Rules(w io.Writer, markdown bool) {
	all := rules.All()
	if markdown {
		fmt.Fprintln(w, "| ID | Name | Default severity | Phase | Summary |")
		fmt.Fprintln(w, "|---|---|---|---|---|")
		for _, r := range all {
			fmt.Fprintf(w, "| `%s` | %s | %s | %s | %s |\n", r.ID, r.Name, r.Severity, r.Phase, mdEscape(r.Summary))
		}
		return
	}
	for _, r := range all {
		fmt.Fprintf(w, "%-16s %-9s %-7s %s\n", r.ID, r.Severity, r.Phase, r.Summary)
	}
}

// ---- SARIF ----

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string         `json:"id"`
	Name             string         `json:"name"`
	ShortDescription sarifText      `json:"shortDescription"`
	FullDescription  sarifText      `json:"fullDescription"`
	Help             sarifText      `json:"help"`
	DefaultConfig    map[string]any `json:"defaultConfiguration"`
	Properties       map[string]any `json:"properties"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	Level               string            `json:"level"`
	Message             sarifText         `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           *sarifRegion  `json:"region,omitempty"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// SARIF writes capabilities as a SARIF 2.1.0 log suitable for GitHub code
// scanning. modules maps module key → directory (relative to the repo root
// prefix uriBase).
func SARIF(w io.Writer, caps []model.Capability, modules []model.Module, uriBase, version string) error {
	dirs := map[string]string{}
	mods := map[string]model.Module{}
	for _, m := range modules {
		dirs[m.Key] = m.Dir
		mods[m.Key] = m
	}
	used := map[string]bool{}
	results := []sarifResult{}
	for _, c := range caps {
		used[c.RuleID] = true
		uri := path.Clean(path.Join(uriBase, dirs[c.Module], c.File))
		line := c.Line
		msg := c.Message
		props := map[string]any{"phase": c.Phase, "module": displayKey(c.Module), "severity": c.Severity.String()}
		// Downloaded third-party module files are not in the repository,
		// so code scanning cannot show alerts on them. Point at the
		// `module` block that pins the module instead (the line a version
		// bump changes), and keep the real location in the message.
		if m, ok := mods[c.Module]; ok && m.ThirdParty && m.Anchor != nil {
			inner := c.File
			if c.Line > 0 {
				inner = fmt.Sprintf("%s:%d", c.File, c.Line)
			}
			msg = fmt.Sprintf("%s [%s, %s]", c.Message, displayKey(c.Module), joinNonEmpty(" ", c.Address, inner))
			props["module_file"] = inner
			uri = path.Clean(path.Join(uriBase, m.Anchor.File))
			line = m.Anchor.Line
		}
		loc := sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}}
		if line > 0 {
			loc.Region = &sarifRegion{StartLine: line}
		}
		if len(c.Tags) > 0 {
			props["tags"] = c.Tags
		}
		results = append(results, sarifResult{
			RuleID: c.RuleID, Level: sarifLevel(c.Severity), Message: sarifText{msg},
			Locations:           []sarifLocation{{loc}},
			PartialFingerprints: map[string]string{"tfcap/v1": c.Fingerprint()},
			Properties:          props,
		})
	}
	ids := make([]string, 0, len(used))
	for id := range used {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var srules []sarifRule
	for _, id := range ids {
		r := rules.Get(id)
		srules = append(srules, sarifRule{
			ID: r.ID, Name: r.Name, ShortDescription: sarifText{r.Summary}, FullDescription: sarifText{r.Help},
			Help:          sarifText{r.Help},
			DefaultConfig: map[string]any{"level": sarifLevel(r.Severity)},
			Properties: map[string]any{
				"security-severity": securitySeverity(r.Severity),
				"tags":              []string{"security", "supply-chain", "terraform"},
			},
		})
	}
	if srules == nil {
		srules = []sarifRule{}
	}
	return JSON(w, sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool:    sarifTool{sarifDriver{Name: "tfcap", Version: version, InformationURI: "https://github.com/r-morato/tfcap", Rules: srules}},
			Results: results,
		}},
	})
}

func sarifLevel(s model.Severity) string {
	switch s {
	case model.Critical, model.High:
		return "error"
	case model.Medium:
		return "warning"
	}
	return "note"
}

// securitySeverity maps to GitHub's numeric scale (critical ≥ 9.0, high ≥ 7.0,
// medium ≥ 4.0, low > 0).
func securitySeverity(s model.Severity) string {
	switch s {
	case model.Critical:
		return "9.5"
	case model.High:
		return "8.0"
	case model.Medium:
		return "5.5"
	case model.Low:
		return "3.0"
	}
	return "0.0"
}
