package analyze

import (
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"

	"github.com/r-morato/tfcap/internal/model"
	"github.com/r-morato/tfcap/internal/rules"
)

// revealed runs the text indicators on what an expression evaluates to,
// keeping only what is NOT visible in the module's source: hosts, paths,
// credential variables and shell patterns that were assembled with
// join(), format(), base64decode() and friends.
func (a *analyzer) revealed(addr string, rng hcl.Range, evaluated string) {
	if evaluated == "" {
		return
	}
	hidden := func(s string) bool { return !strings.Contains(a.allSrc, s) }
	note := " (assembled from expressions; not visible in the source)"
	if p, ok := sensitivePath(evaluated); ok && hidden(p) {
		a.add(rules.FSSensitiveRead, addr, rng, "References credential material: "+p+note, "path:"+p, evaluated, "evaluated")
	}
	for _, v := range credEnvRefs(evaluated) {
		if hidden(v) {
			a.add(rules.CredEnvReference, addr, rng, "References credential variable "+v+note, "env:"+v, evaluated, "evaluated")
		}
	}
	for _, h := range urlHosts(evaluated) {
		if hidden(h) {
			a.add(rules.NetEndpoint, addr, rng, "References host "+h+note, "host:"+h, evaluated, "evaluated")
			a.bump(model.High)
		}
	}
	for _, ip := range publicIPs(evaluated) {
		if hidden(ip) {
			a.add(rules.NetIPLiteral, addr, rng, "References public IP "+ip+note, "ip:"+ip, evaluated, "evaluated")
			a.bump(model.High)
		}
	}
	srcTags := map[string]bool{}
	for _, t := range matchShell(a.allSrc) {
		srcTags[t] = true
	}
	var newTags []string
	for _, t := range matchShell(evaluated) {
		if !srcTags[t] {
			newTags = append(newTags, t)
		}
	}
	if len(newTags) > 0 {
		a.add(rules.ExecShellPattern, addr, rng, "Command assembled from expressions shows suspicious patterns: "+strings.Join(newTags, ", "),
			"eval:"+strings.Join(newTags, ","), evaluated, append([]string{"evaluated"}, newTags...)...)
		a.bump(model.Critical)
	}
}

// evalAttrs evaluates the named attributes of a block and returns the
// concatenated text of those that could be evaluated.
func (a *analyzer) evalAttrs(b *hclsyntax.Block, names ...string) string {
	var out []string
	for _, n := range names {
		if at, ok := attr(b, n); ok {
			if t, ok := a.scope.evalText(at.Expr); ok {
				out = append(out, t)
			}
		}
	}
	return strings.Join(out, "\n")
}

// sink describes where a secret ends up.
type sink struct {
	attr     string
	severity model.Severity
}

// flows reports secrets that reach the given attributes of b.
func (a *analyzer) flows(ruleID, addr string, b *hclsyntax.Block, what string, sinks []sink) {
	type hit struct {
		origin string
		attrs  []string
		sev    model.Severity
	}
	hits := map[string]*hit{}
	for _, s := range sinks {
		at, ok := attr(b, s.attr)
		if !ok {
			continue
		}
		origin, ok := a.scope.taintOf(at.Expr)
		if !ok {
			continue
		}
		h := hits[origin]
		if h == nil {
			h = &hit{origin: origin}
			hits[origin] = h
		}
		h.attrs = append(h.attrs, s.attr)
		if s.severity > h.sev {
			h.sev = s.severity
		}
	}
	origins := make([]string, 0, len(hits))
	for o := range hits {
		origins = append(origins, o)
	}
	sort.Strings(origins)
	for _, o := range origins {
		h := hits[o]
		a.add(ruleID, addr, b.TypeRange, fmt.Sprintf("Secret %s flows into %s (%s)", o, what, strings.Join(h.attrs, ", ")),
			"flow:"+o+">"+strings.Join(h.attrs, ","), "")
		c := &a.res.Capabilities[len(a.res.Capabilities)-1]
		if c.Detail == "flow:"+o+">"+strings.Join(h.attrs, ",") {
			c.Severity = h.sev
			if b.Type == "provisioner" {
				c.Phase = model.PhaseApply
			}
		}
	}
}

// httpSinks grades where a secret goes in a data "http" request: in the
// URL or body it leaves in the clear to whoever the URL names; a header to
// a fixed host is how API tokens are normally sent.
func httpSinks(b *hclsyntax.Block) []sink {
	headerSev := model.Medium
	if at, ok := attr(b, "url"); ok {
		if _, static := staticString(at.Expr); !static {
			headerSev = model.High
		}
	}
	return []sink{{"url", model.Critical}, {"request_body", model.Critical}, {"request_headers", headerSev}}
}
