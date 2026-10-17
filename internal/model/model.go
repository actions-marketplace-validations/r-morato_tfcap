// Package model holds the data types shared across tfcap: capabilities
// (findings), modules, and reports.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
)

// Severity orders findings from purely informational to critical.
type Severity int

const (
	Info Severity = iota
	Low
	Medium
	High
	Critical
)

var severityNames = []string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if int(s) < 0 || int(s) >= len(severityNames) {
		return "unknown"
	}
	return severityNames[s]
}

// ParseSeverity converts a name ("high") into a Severity. ok is false for
// unknown names.
func ParseSeverity(name string) (Severity, bool) {
	for i, n := range severityNames {
		if strings.EqualFold(n, name) {
			return Severity(i), true
		}
	}
	return Info, false
}

func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

func (s *Severity) UnmarshalText(b []byte) error {
	v, ok := ParseSeverity(string(b))
	if !ok {
		v = Info
	}
	*s = v
	return nil
}

// Phase is the Terraform lifecycle phase in which a capability can fire.
// "plan" matters most: it runs before any human approves anything.
type Phase string

const (
	PhaseInit   Phase = "init"
	PhasePlan   Phase = "plan"
	PhaseApply  Phase = "apply"
	PhaseStatic Phase = "static" // property of the code/metadata, not a runtime action
)

// Capability is one thing a module can do (or one risky property it has).
type Capability struct {
	RuleID   string   `json:"rule_id"`
	Severity Severity `json:"severity"`
	Phase    Phase    `json:"phase"`
	Module   string   `json:"module"`  // module key, "" for root
	Address  string   `json:"address"` // e.g. data.http.beacon, module.vpc
	File     string   `json:"file"`    // path relative to module dir
	Line     int      `json:"line"`
	Message  string   `json:"message"`
	// Detail is the stable, line-number-free description used for diffing,
	// e.g. a hostname or the normalized command.
	Detail   string   `json:"detail,omitempty"`
	Evidence string   `json:"evidence,omitempty"`
	Tags     []string `json:"tags,omitempty"`
}

// Fingerprint identifies a capability independent of line numbers and the
// module version, so the same capability in v1.2 and v1.3 compares equal.
func (c Capability) Fingerprint() string {
	h := sha256.New()
	for _, p := range []string{c.RuleID, c.Module, c.Address, baseFile(c.File), c.Detail} {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func baseFile(p string) string {
	p = strings.ReplaceAll(p, "\\", "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

// SourceKind classifies where a module came from.
type SourceKind string

const (
	SourceRoot     SourceKind = "root"
	SourceLocal    SourceKind = "local"
	SourceRegistry SourceKind = "registry"
	SourceGit      SourceKind = "git"
	SourceHTTP     SourceKind = "http"
	SourceBucket   SourceKind = "bucket"
	SourceUnknown  SourceKind = "unknown"
)

// Module is one Terraform module directory that was analyzed.
type Module struct {
	Key        string     `json:"key"`
	Source     string     `json:"source"`
	Version    string     `json:"version,omitempty"`
	Kind       SourceKind `json:"kind"`
	Dir        string     `json:"dir"`
	ThirdParty bool       `json:"third_party"`
	Hash       string     `json:"hash,omitempty"`
	Providers  []Provider `json:"providers,omitempty"`
	Files      int        `json:"files"`
	// Anchor is where this third-party module enters your own code: the
	// line of the `module` block (in a first-party file) that pins it.
	// Downloaded module files are not part of your repository, so reports
	// such as SARIF point here instead.
	Anchor *Location `json:"anchor,omitempty"`
	// Commit is the git commit the module was downloaded at, when init kept
	// the git metadata (git sources, and registry modules served from git).
	Commit string `json:"commit,omitempty"`
	// Call is the module block in first-party code that brings this module
	// in (the same block as Anchor), with byte ranges for rewriting.
	Call *CallSite `json:"-"`
}

// CallSite locates a module block's source and version in a file.
type CallSite struct {
	File                     string // relative to the scanned root
	Source, Version          string // as written
	SourceStart, SourceEnd   int
	VersionStart, VersionEnd int
}

// Location is a file and line relative to the scanned root.
type Location struct {
	File string `json:"file"`
	Line int    `json:"line"`
}

// Provider is an entry from a required_providers block.
type Provider struct {
	Name    string `json:"name"`
	Source  string `json:"source"`
	Version string `json:"version,omitempty"`
}

// Report is the full output of a scan.
type Report struct {
	Schema       string       `json:"schema"`
	Tool         string       `json:"tool"`
	Version      string       `json:"version"`
	Root         string       `json:"root"`
	Modules      []Module     `json:"modules"`
	Capabilities []Capability `json:"capabilities"`
	Errors       []string     `json:"errors,omitempty"`
}

const ReportSchema = "tfcap/report/v1"

// Sort orders capabilities deterministically: module, severity desc, file, line.
func (r *Report) Sort() {
	sort.SliceStable(r.Modules, func(i, j int) bool { return r.Modules[i].Key < r.Modules[j].Key })
	sort.SliceStable(r.Capabilities, func(i, j int) bool {
		a, b := r.Capabilities[i], r.Capabilities[j]
		if a.Module != b.Module {
			return a.Module < b.Module
		}
		if a.Severity != b.Severity {
			return a.Severity > b.Severity
		}
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.RuleID < b.RuleID
	})
}

// Max returns the highest severity in caps, and false if caps is empty.
func Max(caps []Capability) (Severity, bool) {
	if len(caps) == 0 {
		return Info, false
	}
	m := Info
	for _, c := range caps {
		if c.Severity > m {
			m = c.Severity
		}
	}
	return m, true
}
