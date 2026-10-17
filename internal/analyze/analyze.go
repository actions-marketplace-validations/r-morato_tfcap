// Package analyze inspects Terraform/OpenTofu module source code and
// produces an inventory of capabilities: what the module can do to the
// machine running Terraform, to the network, and to your cloud account.
package analyze

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/r-morato/tfcap/internal/model"
	"github.com/r-morato/tfcap/internal/rules"
)

// ModuleCall is a `module` block found in analyzed source.
type ModuleCall struct {
	Name    string
	Source  string
	Version string
	File    string
	Line    int
	// PinLine is the line a version bump changes: `version` if present,
	// otherwise `source` (git refs live there), otherwise the block header.
	PinLine int
	// Byte ranges of the source and version expressions in File (End 0 when
	// absent), used by `tfcap pin` to rewrite them in place.
	SourceStart, SourceEnd   int
	VersionStart, VersionEnd int
}

// Result is the outcome of analyzing one module directory.
type Result struct {
	Capabilities []model.Capability
	Providers    []model.Provider
	Calls        []ModuleCall
	Files        int
	Errors       []string
}

// Options tune analysis.
type Options struct {
	// ThirdParty marks the module as not authored by the user. Some
	// inventory-only rules are reported only for third-party code.
	ThirdParty bool
}

// analyzer carries per-module state.
type analyzer struct {
	dir     string
	module  string
	opts    Options
	res     *Result
	seen    map[string]bool
	file    string
	src     []byte
	scanned map[string]bool // helper scripts already scanned
}

// Dir analyzes the Terraform files directly inside dir (not subdirectories;
// nested modules are separate modules).
func Dir(dir, moduleKey string, opts Options) (*Result, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	a := &analyzer{dir: dir, module: moduleKey, opts: opts, res: &Result{}, seen: map[string]bool{}, scanned: map[string]bool{}}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		n := e.Name()
		if strings.HasSuffix(n, ".tf") || strings.HasSuffix(n, ".tofu") ||
			strings.HasSuffix(n, ".tf.json") || strings.HasSuffix(n, ".tofu.json") {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	for _, n := range names {
		src, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			a.res.Errors = append(a.res.Errors, err.Error())
			continue
		}
		a.res.Files++
		a.file, a.src = n, src
		if strings.HasSuffix(n, ".json") {
			a.analyzeJSON(src)
		} else {
			a.analyzeHCL(src)
		}
	}
	a.scanBinaries()
	return a.res, nil
}

// add records a capability, de-duplicating by fingerprint+line.
func (a *analyzer) add(ruleID string, addr string, rng hcl.Range, msg, detail, evidence string, tags ...string) {
	r := rules.Get(ruleID)
	c := model.Capability{
		RuleID: ruleID, Severity: r.Severity, Phase: r.Phase, Module: a.module, Address: addr,
		File: a.file, Line: rng.Start.Line, Message: msg, Detail: detail,
		Evidence: truncate(evidence, 240), Tags: tags,
	}
	k := c.Fingerprint() + fmt.Sprint(c.Line)
	if a.seen[k] {
		return
	}
	a.seen[k] = true
	a.res.Capabilities = append(a.res.Capabilities, c)
}

func (a *analyzer) bump(sev model.Severity) {
	c := &a.res.Capabilities[len(a.res.Capabilities)-1]
	if sev > c.Severity {
		c.Severity = sev
	}
}

func (a *analyzer) text(r hcl.Range) string {
	if r.End.Byte > len(a.src) || r.Start.Byte > r.End.Byte {
		return ""
	}
	return string(a.src[r.Start.Byte:r.End.Byte])
}

// ---- HCL native syntax ----

func (a *analyzer) analyzeHCL(src []byte) {
	f, diags := hclsyntax.ParseConfig(src, a.file, hcl.InitialPos)
	if diags.HasErrors() {
		a.add(rules.ObfUnparsed, "", hcl.Range{Start: hcl.InitialPos}, "File could not be parsed and was not analyzed: "+diags.Errs()[0].Error(), a.file, "")
		// fall back to raw text indicators so a parse error is not a free pass
		a.rawText(string(src), "", hcl.Range{Start: hcl.InitialPos})
		return
	}
	body, ok := f.Body.(*hclsyntax.Body)
	if !ok {
		return
	}
	for _, b := range body.Blocks {
		addr := blockAddr(b)
		switch b.Type {
		case "resource":
			if len(b.Labels) == 2 {
				a.resource(b.Labels[0], addr, b)
			}
		case "data":
			if len(b.Labels) == 2 {
				a.dataSource(b.Labels[0], addr, b)
			}
		case "module":
			a.moduleCall(b, addr)
		case "terraform":
			a.terraformBlock(b)
		case "check":
			// `check` blocks may contain scoped data sources that run at plan.
			for _, nb := range b.Body.Blocks {
				if nb.Type == "data" && len(nb.Labels) == 2 {
					a.dataSource(nb.Labels[0], addr+"."+blockAddr(nb), nb)
				}
			}
		}
		a.walkBody(b.Body, addr)
	}
	for name, attr := range body.Attributes {
		a.walkExpr(attr.Expr, name)
	}
}

func blockAddr(b *hclsyntax.Block) string {
	switch b.Type {
	case "resource":
		return strings.Join(b.Labels, ".")
	case "data", "module", "variable", "output", "provider", "check":
		return b.Type + "." + strings.Join(b.Labels, ".")
	}
	if len(b.Labels) > 0 {
		return b.Type + "." + strings.Join(b.Labels, ".")
	}
	return b.Type
}

// walkBody visits every attribute expression in body (recursively).
func (a *analyzer) walkBody(body *hclsyntax.Body, addr string) {
	isModule := strings.HasPrefix(addr, "module.")
	for name, attr := range body.Attributes {
		if name == "description" || name == "validation" {
			continue
		}
		if isModule && (name == "source" || name == "version") {
			continue // analyzed by checkSource, not an endpoint the module calls
		}
		a.walkExpr(attr.Expr, addr)
	}
	for _, b := range body.Blocks {
		if b.Type == "validation" {
			continue
		}
		a.walkBody(b.Body, addr)
	}
}

var fileFuncs = map[string]bool{
	"file": true, "filebase64": true, "filesha256": true, "filesha1": true, "filesha512": true,
	"filemd5": true, "filebase64sha256": true, "filebase64sha512": true, "templatefile": true,
	"fileexists": true, "fileset": true,
}

var decodeFuncs = map[string]bool{"base64decode": true, "textdecodebase64": true, "base64gunzip": true}

func (a *analyzer) walkExpr(expr hclsyntax.Expression, addr string) {
	var templates []hcl.Range
	inTemplate := func(r hcl.Range) bool {
		for _, t := range templates {
			if r.Start.Byte >= t.Start.Byte && r.End.Byte <= t.End.Byte {
				return true
			}
		}
		return false
	}
	hclsyntax.VisitAll(expr, func(n hclsyntax.Node) hcl.Diagnostics {
		switch e := n.(type) {
		case *hclsyntax.FunctionCallExpr:
			a.funcCall(e, addr)
		case *hclsyntax.TemplateExpr:
			// Whole template text, so URLs split across interpolation are
			// seen. Its literal parts are then skipped.
			if !inTemplate(e.SrcRange) {
				templates = append(templates, e.SrcRange)
				a.stringValue(a.text(e.SrcRange), addr, e.SrcRange)
			}
		case *hclsyntax.LiteralValueExpr:
			if e.Val.Type() == cty.String && e.Val.IsKnown() && !e.Val.IsNull() && !inTemplate(e.SrcRange) {
				a.stringValue(e.Val.AsString(), addr, e.SrcRange)
			}
		case *hclsyntax.ObjectConsExpr:
			a.iamObject(e, addr)
		}
		return nil
	})
}

func (a *analyzer) funcCall(e *hclsyntax.FunctionCallExpr, addr string) {
	name := strings.TrimPrefix(e.Name, "core::")
	switch {
	case fileFuncs[name] && len(e.Args) > 0:
		arg := a.text(e.Args[0].Range())
		if p, ok := sensitivePath(arg); ok {
			a.add(rules.FSSensitiveRead, addr, e.Range(), fmt.Sprintf("%s() reads credential material: %s", name, p), "path:"+p, a.text(e.Range()))
			return
		}
		if escapesModule(arg) {
			a.add(rules.FSLocalRead, addr, e.Range(), fmt.Sprintf("%s() reads a path outside the module", name), "path:"+normPathExpr(arg), a.text(e.Range()))
		}
	case name == "pathexpand" && len(e.Args) > 0:
		if p, ok := sensitivePath(a.text(e.Args[0].Range())); ok {
			a.add(rules.FSSensitiveRead, addr, e.Range(), "pathexpand() resolves a credential path: "+p, "path:"+p, a.text(e.Range()))
		}
	case decodeFuncs[name] && len(e.Args) > 0:
		if v, ok := staticString(e.Args[0]); ok && len(v) >= 24 {
			a.add(rules.ObfDecodeInline, addr, e.Range(), name+"() decodes a constant", "len:"+bucket(len(v)), a.text(e.Range()))
		}
	}
}

var escapeRe = regexp.MustCompile(`^\s*"?(/|~|[A-Za-z]:\\|\.\./)|\$\{\s*pathexpand\(|path\.(root|cwd)\}?/\.\.`)

func escapesModule(argText string) bool { return escapeRe.MatchString(argText) }

func normPathExpr(s string) string { return truncate(strings.Trim(s, `"`), 80) }

func bucket(n int) string {
	switch {
	case n < 256:
		return "small"
	case n < 4096:
		return "medium"
	}
	return "large"
}

// stringValue applies text indicators to a string literal or template.
func (a *analyzer) stringValue(s, addr string, rng hcl.Range) {
	if p, ok := sensitivePath(s); ok {
		a.add(rules.FSSensitiveRead, addr, rng, "References credential material: "+p, "path:"+p, s)
	}
	for _, v := range credEnvRefs(s) {
		a.add(rules.CredEnvReference, addr, rng, "References credential variable "+v, "env:"+v, s)
	}
	for _, h := range urlHosts(s) {
		a.add(rules.NetEndpoint, addr, rng, "References host "+h, "host:"+h, s)
	}
	for _, ip := range publicIPs(s) {
		a.add(rules.NetIPLiteral, addr, rng, "References public IP "+ip, "ip:"+ip, s)
	}
	if kind, n := encodedBlob(s); n > 0 {
		a.add(rules.ObfBase64Blob, addr, rng, fmt.Sprintf("Contains a %d-char %s blob", n, kind), kind+":"+bucket(n), s)
	}
	if strings.Contains(s, "Statement") && strings.Contains(s, "{") {
		a.iamJSON(s, addr, rng)
	}
}

// rawText is the parse-failure fallback: run the string indicators on the
// whole file and look for exec-ish block headers.
func (a *analyzer) rawText(s, addr string, rng hcl.Range) {
	a.stringValue(s, addr, rng)
	if regexp.MustCompile(`data\s+"external"`).MatchString(s) {
		a.add(rules.ExecExternalData, addr, rng, "Unparseable file contains an external data source", "unparsed", "")
	}
	if regexp.MustCompile(`provisioner\s+"local-exec"`).MatchString(s) {
		a.add(rules.ExecLocal, addr, rng, "Unparseable file contains a local-exec provisioner", "unparsed", "")
	}
	if tags := matchShell(s); len(tags) > 0 {
		a.add(rules.ExecShellPattern, addr, rng, "Suspicious shell patterns: "+strings.Join(tags, ", "), "unparsed:"+strings.Join(tags, ","), "", tags...)
	}
}

// ---- block handlers ----

func attr(b *hclsyntax.Block, name string) (*hclsyntax.Attribute, bool) {
	at, ok := b.Body.Attributes[name]
	return at, ok
}

func staticString(e hclsyntax.Expression) (string, bool) {
	v, diags := e.Value(nil)
	if diags.HasErrors() || !v.IsWhollyKnown() || v.IsNull() || v.Type() != cty.String {
		return "", false
	}
	return v.AsString(), true
}

func staticStrings(e hclsyntax.Expression) ([]string, bool) {
	if s, ok := staticString(e); ok {
		return []string{s}, true
	}
	v, diags := e.Value(nil)
	if diags.HasErrors() || !v.IsWhollyKnown() || v.IsNull() {
		return nil, false
	}
	if !(v.Type().IsTupleType() || v.Type().IsListType() || v.Type().IsSetType()) {
		return nil, false
	}
	var out []string
	for it := v.ElementIterator(); it.Next(); {
		_, ev := it.Element()
		if ev.Type() != cty.String {
			return nil, false
		}
		out = append(out, ev.AsString())
	}
	return out, true
}

func (a *analyzer) resource(typ, addr string, b *hclsyntax.Block) {
	switch typ {
	case "local_file", "local_sensitive_file":
		a.add(rules.FSLocalWrite, addr, b.TypeRange, "Writes a file on the Terraform host", "write:"+typ, "")
	case "shell_script":
		a.execCommand(rules.ExecLocal, addr, b.TypeRange, a.text(b.Body.SrcRange), "shell_script resource runs commands")
	}
	for _, p := range b.Body.Blocks {
		if p.Type != "provisioner" || len(p.Labels) != 1 {
			continue
		}
		switch p.Labels[0] {
		case "local-exec":
			cmd := ""
			if at, ok := attr(p, "command"); ok {
				cmd = a.text(at.Expr.Range())
			}
			if at, ok := attr(p, "interpreter"); ok {
				cmd = a.text(at.Expr.Range()) + " " + cmd
			}
			a.execCommand(rules.ExecLocal, addr, p.TypeRange, cmd, "local-exec provisioner runs a command on the Terraform host")
		case "remote-exec":
			cmd := ""
			for _, n := range []string{"inline", "script", "scripts"} {
				if at, ok := attr(p, n); ok {
					cmd += a.text(at.Expr.Range()) + " "
				}
			}
			a.execCommand(rules.ExecRemote, addr, p.TypeRange, cmd, "remote-exec provisioner runs commands on a remote host")
		case "file":
			src := ""
			if at, ok := attr(p, "source"); ok {
				src = a.text(at.Expr.Range())
			}
			a.add(rules.FSUpload, addr, p.TypeRange, "file provisioner uploads "+truncate(src, 60), "src:"+normCmd(src), src)
			if path, ok := sensitivePath(src); ok {
				a.add(rules.FSSensitiveRead, addr, p.TypeRange, "file provisioner uploads credential material: "+path, "path:"+path, src)
			}
		}
	}
}

func (a *analyzer) dataSource(typ, addr string, b *hclsyntax.Block) {
	switch {
	case typ == "external":
		prog := ""
		if at, ok := attr(b, "program"); ok {
			prog = a.text(at.Expr.Range())
		}
		a.execCommand(rules.ExecExternalData, addr, b.TypeRange, prog, "external data source runs a program during plan")
	case typ == "shell_script":
		a.execCommand(rules.ExecExternalData, addr, b.TypeRange, a.text(b.Body.SrcRange), "shell_script data source runs commands during plan")
	case typ == "http":
		urlText := ""
		if at, ok := attr(b, "url"); ok {
			urlText = a.text(at.Expr.Range())
		}
		host := "dynamic"
		if hs := urlHosts(urlText); len(hs) > 0 {
			host = hs[0]
		}
		var tags []string
		if strings.Contains(urlText, "${") || !strings.HasPrefix(strings.TrimSpace(urlText), `"`) {
			tags = append(tags, "interpolated-url")
		}
		for _, n := range []string{"request_body", "request_headers", "method"} {
			if at, ok := attr(b, n); ok {
				if n == "method" {
					if m, ok := staticString(at.Expr); ok && strings.EqualFold(m, "GET") {
						continue
					}
				}
				tags = append(tags, "sends-"+strings.TrimPrefix(n, "request_"))
			}
		}
		a.add(rules.NetHTTPData, addr, b.TypeRange, "http data source contacts "+host+" during plan", "host:"+host, urlText, tags...)
		if len(tags) >= 2 || (contains(tags, "interpolated-url") && contains(tags, "sends-body")) {
			a.bump(model.Critical)
		}
	case typ == "aws_iam_policy_document":
		a.iamDocument(addr, b)
	case strings.HasPrefix(typ, "dns_"):
		a.add(rules.NetDNSData, addr, b.TypeRange, typ+" performs DNS lookups during plan", "dns:"+typ, "")
	case typ == "local_file" || typ == "local_sensitive_file":
		fn := ""
		if at, ok := attr(b, "filename"); ok {
			fn = a.text(at.Expr.Range())
		}
		if p, ok := sensitivePath(fn); ok {
			a.add(rules.FSSensitiveRead, addr, b.TypeRange, typ+" reads credential material: "+p, "path:"+p, fn)
		} else if escapesModule(fn) {
			a.add(rules.FSLocalRead, addr, b.TypeRange, typ+" reads a path outside the module", "path:"+normPathExpr(fn), fn)
		}
	}
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

var scriptRefRe = regexp.MustCompile(`\$\{path\.module\}[/\\]([^\s"'$\]\),]+)`)

// execCommand records an exec capability and inspects its command text and
// any helper scripts it references inside the module.
func (a *analyzer) execCommand(ruleID, addr string, rng hcl.Range, cmd, msg string) {
	// Everything found in the command or its helper scripts fires in the
	// same phase as the exec itself (plan for external data sources).
	start := len(a.res.Capabilities)
	defer func() {
		phase := rules.Get(ruleID).Phase
		for i := start; i < len(a.res.Capabilities); i++ {
			a.res.Capabilities[i].Phase = phase
		}
	}()
	a.add(ruleID, addr, rng, msg+": "+truncate(cmd, 80), "cmd:"+normCmd(cmd), cmd)
	full := cmd
	for _, m := range scriptRefRe.FindAllStringSubmatch(cmd, -1) {
		if body, rel, ok := a.readHelper(m[1]); ok {
			full += "\n" + body
			a.scanHelper(rel, body, addr)
		}
	}
	if tags := matchShell(full); len(tags) > 0 {
		a.add(rules.ExecShellPattern, addr, rng, "Command shows suspicious patterns: "+strings.Join(tags, ", "), "cmd:"+normCmd(cmd)+"|"+strings.Join(tags, ","), cmd, tags...)
		if len(tags) >= 2 {
			a.bump(model.Critical)
		}
	}
}

// normCmd makes a command comparable across versions: whitespace-collapsed
// and truncated.
func normCmd(s string) string { return truncate(s, 120) }

// readHelper reads a script referenced via ${path.module}, refusing paths
// that escape the module directory.
func (a *analyzer) readHelper(rel string) (string, string, bool) {
	clean := filepath.Clean(filepath.FromSlash(rel))
	if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return "", "", false
	}
	p := filepath.Join(a.dir, clean)
	st, err := os.Stat(p)
	if err != nil || st.IsDir() || st.Size() > 2<<20 {
		return "", "", false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", "", false
	}
	return string(b), filepath.ToSlash(clean), true
}

// scanHelper applies the string indicators to a helper script, attributing
// findings to that file.
func (a *analyzer) scanHelper(rel, body, addr string) {
	if a.scanned[rel] {
		return
	}
	a.scanned[rel] = true
	saveFile, saveSrc := a.file, a.src
	a.file, a.src = rel, []byte(body)
	defer func() { a.file, a.src = saveFile, saveSrc }()
	for i, line := range strings.Split(body, "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "#") && !strings.HasPrefix(t, "#!") || strings.HasPrefix(t, "//") || strings.HasPrefix(t, "REM ") {
			continue // comments do not execute
		}
		rng := hcl.Range{Start: hcl.Pos{Line: i + 1}}
		a.stringValue(line, addr, rng)
	}
}

func (a *analyzer) moduleCall(b *hclsyntax.Block, addr string) {
	call := ModuleCall{File: a.file, Line: b.TypeRange.Start.Line}
	if len(b.Labels) > 0 {
		call.Name = b.Labels[0]
	}
	call.PinLine = call.Line
	if at, ok := attr(b, "source"); ok {
		call.Source, _ = staticString(at.Expr)
		call.PinLine = at.SrcRange.Start.Line
		call.SourceStart, call.SourceEnd = at.Expr.Range().Start.Byte, at.Expr.Range().End.Byte
	}
	if at, ok := attr(b, "version"); ok {
		call.Version, _ = staticString(at.Expr)
		call.PinLine = at.SrcRange.Start.Line
		call.VersionStart, call.VersionEnd = at.Expr.Range().Start.Byte, at.Expr.Range().End.Byte
	}
	a.res.Calls = append(a.res.Calls, call)
	a.checkSource(call, addr, b.TypeRange)
}

func (a *analyzer) checkSource(call ModuleCall, addr string, rng hcl.Range) {
	info := ClassifySource(call.Source)
	src := call.Source
	if info.Insecure {
		a.add(rules.SrcInsecureTransport, addr, rng, "Module fetched over an unauthenticated transport: "+src, "src:"+src, src)
	}
	switch info.Kind {
	case model.SourceGit:
		switch {
		case info.Ref == "":
			a.add(rules.SrcGitUnpinned, addr, rng, "Git module tracks the default branch: "+src, "src:"+stripRef(src), src)
		case !IsSHA(info.Ref):
			a.add(rules.SrcGitMutableRef, addr, rng, "Git module pinned to mutable ref "+info.Ref, "src:"+stripRef(src), src)
		}
	case model.SourceRegistry:
		if !IsExactVersion(call.Version) {
			v := call.Version
			if v == "" {
				v = "(none)"
			}
			a.add(rules.SrcRegistryUnpinned, addr, rng, "Registry module version not pinned exactly: "+v, "src:"+src, src)
		}
	case model.SourceHTTP:
		a.add(rules.SrcHTTPArchive, addr, rng, "Module downloaded from an archive URL: "+src, "src:"+src, src)
	}
}

func stripRef(src string) string {
	if i := strings.Index(src, "?"); i >= 0 {
		return src[:i]
	}
	return src
}

func (a *analyzer) terraformBlock(b *hclsyntax.Block) {
	for _, rp := range b.Body.Blocks {
		if rp.Type != "required_providers" {
			continue
		}
		names := make([]string, 0, len(rp.Body.Attributes))
		for n := range rp.Body.Attributes {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, name := range names {
			at := rp.Body.Attributes[name]
			p := model.Provider{Name: name}
			v, diags := at.Expr.Value(nil)
			if !diags.HasErrors() && v.IsWhollyKnown() && !v.IsNull() {
				switch {
				case v.Type() == cty.String:
					p.Version = v.AsString()
				case v.Type().IsObjectType():
					if v.Type().HasAttribute("source") {
						if s := v.GetAttr("source"); s.Type() == cty.String {
							p.Source = s.AsString()
						}
					}
					if v.Type().HasAttribute("version") {
						if s := v.GetAttr("version"); s.Type() == cty.String {
							p.Version = s.AsString()
						}
					}
				}
			}
			a.provider(p, at.SrcRange)
		}
	}
}

func (a *analyzer) provider(p model.Provider, rng hcl.Range) {
	addr := ParseProviderSource(p.Source, p.Name)
	if p.Source == "" {
		p.Source = addr.Short()
	}
	a.res.Providers = append(a.res.Providers, p)
	label := "provider." + p.Name
	if ref, ok := knownMalicious[addr.Short()]; ok {
		a.add(rules.RepKnownMalicious, label, rng, fmt.Sprintf("Provider %s is a confirmed malicious package (%s)", addr.Short(), ref), "provider:"+addr.Short(), p.Source)
	}
	if target, ok := Typosquat(addr); ok {
		a.add(rules.ProvTyposquat, label, rng, fmt.Sprintf("Provider %s looks like a typosquat of %s", addr.Short(), target), "provider:"+addr.Short(), p.Source)
	}
	if addr.Host != defaultRegistry && addr.Host != "registry.opentofu.org" {
		a.add(rules.ProvCustomHost, label, rng, "Provider installed from custom host "+addr.Host, "provider:"+addr.Host+"/"+addr.Short(), p.Source)
	}
	if execCapableProviders[addr.Short()] {
		a.add(rules.ProvExecCapable, label, rng, "Requires exec/network provider "+addr.Short(), "provider:"+addr.Short(), p.Source)
	}
	if a.opts.ThirdParty && !officialNamespaces[addr.Namespace] {
		a.add(rules.ProvUnofficialNS, label, rng, "Requires community provider "+addr.Short(), "provider:"+addr.Short(), p.Source)
	}
}

// ---- binaries ----

var binaryMagic = [][]byte{
	{0x7f, 'E', 'L', 'F'},
	{'M', 'Z'},
	{0xfe, 0xed, 0xfa, 0xce}, {0xfe, 0xed, 0xfa, 0xcf},
	{0xce, 0xfa, 0xed, 0xfe}, {0xcf, 0xfa, 0xed, 0xfe},
	{0xca, 0xfe, 0xba, 0xbe},
}

// scanBinaries walks the module directory (not nested module dirs that
// contain their own .tf files... those are reported by their own module
// entry) looking for compiled executables.
func (a *analyzer) scanBinaries() {
	_ = filepath.WalkDir(a.dir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			n := d.Name()
			if p != a.dir && (n == ".git" || n == ".terraform" || n == "node_modules" || hasTF(p)) {
				return filepath.SkipDir // nested modules are scanned as their own module
			}
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Size() < 64 || !info.Mode().IsRegular() {
			return nil
		}
		f, err := os.Open(p)
		if err != nil {
			return nil
		}
		head := make([]byte, 4)
		_, _ = f.Read(head)
		f.Close()
		for _, m := range binaryMagic {
			if bytes.HasPrefix(head, m) {
				rel, _ := filepath.Rel(a.dir, p)
				rel = filepath.ToSlash(rel)
				if m[0] == 'M' && !strings.HasSuffix(strings.ToLower(rel), ".exe") && !strings.HasSuffix(strings.ToLower(rel), ".dll") && info.Size() < 1024 {
					break // "MZ" prefix on a tiny non-exe file is likely text
				}
				save := a.file
				a.file = rel
				a.add(rules.ObfBinaryFile, "", hcl.Range{Start: hcl.Pos{Line: 1}}, "Module ships an executable: "+rel, "bin:"+rel, "")
				a.file = save
				break
			}
		}
		return nil
	})
}

func hasTF(dir string) bool {
	m, _ := filepath.Glob(filepath.Join(dir, "*.tf"))
	return len(m) > 0
}
