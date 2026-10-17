// Package policy reads tfcap.hcl, a reviewed list of accepted findings.
// Every exception names who approved it, why, and when it expires, so an
// accepted risk is re-reviewed instead of silently living forever.
package policy

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/r-morato/tfcap/internal/model"
	"github.com/r-morato/tfcap/internal/rules"
)

// FileName is the default policy file name, looked up in the scanned dir.
const FileName = "tfcap.hcl"

// MaxLifetime caps how far ahead an exception may expire.
const MaxLifetime = 366 * 24 * time.Hour

// Exception accepts findings that match all of its selectors.
type Exception struct {
	Module, Detail              string
	Rules                       []string
	Reason, ApprovedBy, Expires string

	Line    int
	expires time.Time // end of the Expires day, UTC
	rules   []*regexp.Regexp
	module  *regexp.Regexp
	detail  *regexp.Regexp
}

// Policy is a parsed tfcap.hcl.
type Policy struct {
	Path       string
	Exceptions []*Exception
}

// Load reads a policy file. A missing file returns (nil, nil).
func Load(path string, now time.Time) (*Policy, error) {
	src, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	f, diags := hclsyntax.ParseConfig(src, path, hcl.InitialPos)
	if diags.HasErrors() {
		return nil, diags
	}
	body := f.Body.(*hclsyntax.Body)
	if len(body.Attributes) > 0 {
		for k, at := range body.Attributes {
			return nil, fmt.Errorf("%s:%d: unexpected top-level attribute %q", path, at.SrcRange.Start.Line, k)
		}
	}
	p := &Policy{Path: path}
	for _, b := range body.Blocks {
		line := b.TypeRange.Start.Line
		if b.Type != "allow" || len(b.Labels) > 0 {
			return nil, fmt.Errorf("%s:%d: unexpected block %q (only unlabeled allow blocks are supported)", path, line, b.Type)
		}
		e := &Exception{Line: line}
		for k, at := range b.Body.Attributes {
			v, d := at.Expr.Value(nil)
			if d.HasErrors() {
				return nil, fmt.Errorf("%s:%d: %s must be a literal", path, at.SrcRange.Start.Line, k)
			}
			str := func() (string, error) {
				if v.Type() != cty.String || v.IsNull() {
					return "", fmt.Errorf("%s:%d: %s must be a string", path, at.SrcRange.Start.Line, k)
				}
				return v.AsString(), nil
			}
			var err error
			switch k {
			case "module":
				e.Module, err = str()
			case "detail":
				e.Detail, err = str()
			case "reason":
				e.Reason, err = str()
			case "approved_by":
				e.ApprovedBy, err = str()
			case "expires":
				e.Expires, err = str()
			case "rules":
				if !v.Type().IsTupleType() && !v.Type().IsListType() {
					return nil, fmt.Errorf("%s:%d: rules must be a list of rule IDs", path, at.SrcRange.Start.Line)
				}
				for it := v.ElementIterator(); it.Next(); {
					_, ev := it.Element()
					if ev.Type() != cty.String || ev.IsNull() {
						return nil, fmt.Errorf("%s:%d: rules must be a list of rule IDs", path, at.SrcRange.Start.Line)
					}
					e.Rules = append(e.Rules, ev.AsString())
				}
			default:
				err = fmt.Errorf("%s:%d: unknown attribute %q in allow block", path, at.SrcRange.Start.Line, k)
			}
			if err != nil {
				return nil, err
			}
		}
		if len(b.Body.Blocks) > 0 {
			return nil, fmt.Errorf("%s:%d: allow blocks cannot contain blocks", path, line)
		}
		e.Reason, e.ApprovedBy = strings.TrimSpace(e.Reason), strings.TrimSpace(e.ApprovedBy)
		if err := e.compile(now); err != nil {
			return nil, fmt.Errorf("%s:%d: %w", path, e.Line, err)
		}
		p.Exceptions = append(p.Exceptions, e)
	}
	return p, nil
}

func (e *Exception) compile(now time.Time) error {
	if len(e.Rules) == 0 {
		return fmt.Errorf("allow block needs at least one rule")
	}
	if e.Reason == "" || e.ApprovedBy == "" {
		return fmt.Errorf("allow block needs a reason and approved_by")
	}
	t, err := time.Parse("2006-01-02", e.Expires)
	if err != nil {
		return fmt.Errorf("expires must be a date like 2026-12-31, got %q", e.Expires)
	}
	e.expires = t.Add(24*time.Hour - time.Nanosecond)
	if e.expires.Sub(now) > MaxLifetime {
		return fmt.Errorf("expires %s is more than a year away; exceptions must be re-reviewed at least yearly", e.Expires)
	}
	for _, r := range e.Rules {
		e.rules = append(e.rules, glob(strings.ToUpper(r)))
	}
	mod := strings.TrimPrefix(e.Module, "module.")
	mod = strings.ReplaceAll(mod, ".module.", ".")
	if mod == "" {
		mod = "*"
	}
	e.module = glob(mod)
	if e.Detail != "" {
		e.detail = glob(e.Detail)
	}
	return nil
}

// glob turns a pattern where * matches anything into an anchored regexp.
func glob(p string) *regexp.Regexp {
	parts := strings.Split(p, "*")
	for i := range parts {
		parts[i] = regexp.QuoteMeta(parts[i])
	}
	return regexp.MustCompile("^" + strings.Join(parts, ".*") + "$")
}

// Expired reports whether the exception no longer applies at now.
func (e *Exception) Expired(now time.Time) bool { return now.After(e.expires) }

// ExpiresSoon reports whether the exception expires within two weeks.
func (e *Exception) ExpiresSoon(now time.Time) bool {
	return !e.Expired(now) && e.expires.Sub(now) < 14*24*time.Hour
}

// integrity findings mean the code is not what was reviewed. No exception
// can accept them; re-locking after review is the only way through.
var integrity = map[string]bool{rules.SrcContentChanged: true, rules.ProvMutated: true}

func (e *Exception) matches(c model.Capability) bool {
	if integrity[c.RuleID] {
		return false
	}
	ok := false
	for _, r := range e.rules {
		if r.MatchString(c.RuleID) {
			ok = true
			break
		}
	}
	if !ok || !e.module.MatchString(c.Module) && !(c.Module == "" && e.Module == "(root)") {
		return false
	}
	return e.detail == nil || e.detail.MatchString(c.Detail)
}

// Outcome is the result of applying a policy.
type Outcome struct {
	Kept     []model.Capability
	Accepted []model.Accepted
	Warnings []string
}

// Apply removes findings accepted by an active exception. Expired
// exceptions are ignored and reported, so the findings come back.
func (p *Policy) Apply(caps []model.Capability, now time.Time) Outcome {
	var o Outcome
	if p == nil {
		o.Kept = caps
		return o
	}
	used := map[*Exception]bool{}
	for _, c := range caps {
		var hit *Exception
		for _, e := range p.Exceptions {
			if !e.Expired(now) && e.matches(c) {
				hit = e
				break
			}
		}
		if hit == nil {
			o.Kept = append(o.Kept, c)
			continue
		}
		used[hit] = true
		o.Accepted = append(o.Accepted, model.Accepted{Capability: c, Reason: hit.Reason, ApprovedBy: hit.ApprovedBy, Expires: hit.Expires})
	}
	if o.Kept == nil {
		o.Kept = []model.Capability{}
	}
	for _, e := range p.Exceptions {
		switch {
		case e.Expired(now):
			o.Warnings = append(o.Warnings, fmt.Sprintf("%s:%d: exception for %s expired on %s (approved by %s); its findings are reported again",
				p.Path, e.Line, strings.Join(e.Rules, ", "), e.Expires, e.ApprovedBy))
		case e.ExpiresSoon(now) && used[e]:
			o.Warnings = append(o.Warnings, fmt.Sprintf("%s:%d: exception for %s expires on %s; re-review it", p.Path, e.Line, strings.Join(e.Rules, ", "), e.Expires))
		}
	}
	return o
}
