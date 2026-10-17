package analyze

import (
	"encoding/base64"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// moduleScope holds what a module declares across all of its files, so
// expressions can be evaluated and references followed.
type moduleScope struct {
	locals    map[string]hclsyntax.Expression
	vars      map[string]variable
	ctx       *hcl.EvalContext
	taint     map[string]string // "local.x" / "var.x" -> where the secret came from
	evaluated map[string]cty.Value
}

type variable struct {
	def       hclsyntax.Expression
	sensitive bool
}

// prepass parses every .tf/.tofu file of the module and collects locals,
// variables and secret sources. JSON-syntax files are not evaluated.
func (a *analyzer) prepass(names []string) {
	s := &moduleScope{locals: map[string]hclsyntax.Expression{}, vars: map[string]variable{},
		taint: map[string]string{}, evaluated: map[string]cty.Value{}}
	for _, n := range names {
		if strings.HasSuffix(n, ".json") {
			continue
		}
		src, err := os.ReadFile(filepath.Join(a.dir, n))
		if err != nil {
			continue
		}
		f, diags := hclsyntax.ParseConfig(src, n, hcl.InitialPos)
		if diags.HasErrors() {
			continue
		}
		for _, b := range f.Body.(*hclsyntax.Body).Blocks {
			switch {
			case b.Type == "locals":
				for k, at := range b.Body.Attributes {
					s.locals[k] = at.Expr
				}
			case b.Type == "variable" && len(b.Labels) == 1:
				v := variable{}
				if at, ok := b.Body.Attributes["default"]; ok {
					v.def = at.Expr
				}
				if at, ok := b.Body.Attributes["sensitive"]; ok {
					if val, d := at.Expr.Value(nil); !d.HasErrors() && val.Type() == cty.Bool && val.True() {
						v.sensitive = true
					}
				}
				s.vars[b.Labels[0]] = v
			}
		}
	}
	a.scope = s
	s.build()
}

var secretNameRe = regexp.MustCompile(`(?i)(password|passwd|secret|token|api_?key|private_?key|credential|access_?key|client_?secret|auth)`)

// secretData lists data sources whose purpose is reading a secret.
var secretData = map[string]bool{
	"aws_secretsmanager_secret_version": true, "aws_ssm_parameter": true, "aws_kms_secrets": true,
	"vault_generic_secret": true, "vault_kv_secret_v2": true, "vault_kv_secret": true, "vault_aws_access_credentials": true,
	"azurerm_key_vault_secret": true, "google_secret_manager_secret_version": true, "google_secret_manager_secret_version_access": true,
	"onepassword_item": true, "doppler_secrets": true, "kubernetes_secret": true, "kubernetes_secret_v1": true,
	"github_actions_secrets": true, "tfe_outputs": true, "terraform_remote_state": true,
}

// secretResourceAttrs are resource attributes that hold generated secrets.
var secretResourceAttrs = map[string]map[string]bool{
	"random_password":                    {"result": true, "bcrypt_hash": true},
	"tls_private_key":                    {"private_key_pem": true, "private_key_openssh": true, "private_key_pem_pkcs8": true},
	"aws_iam_access_key":                 {"secret": true, "ses_smtp_password_v4": true},
	"google_service_account_key":         {"private_key": true},
	"azuread_service_principal_password": {"value": true},
	"azuread_application_password":       {"value": true},
}

// secretOrigin reports whether a traversal reads a secret directly.
func (s *moduleScope) secretOrigin(t hcl.Traversal) (string, bool) {
	name := func(i int) string {
		if i < len(t) {
			if a, ok := t[i].(hcl.TraverseAttr); ok {
				return a.Name
			}
		}
		return ""
	}
	root := t.RootName()
	switch root {
	case "var":
		v := name(1)
		if s.vars[v].sensitive {
			return "sensitive variable var." + v, true
		}
		if secretNameRe.MatchString(v) {
			return "variable var." + v, true
		}
	case "local":
		if o, ok := s.taint["local."+name(1)]; ok {
			return o, true
		}
	case "data":
		if secretData[name(1)] {
			return "data." + name(1) + "." + name(2), true
		}
	default:
		if attrs, ok := secretResourceAttrs[root]; ok {
			for i := 2; i < len(t); i++ {
				if a, ok := t[i].(hcl.TraverseAttr); ok && attrs[a.Name] {
					return root + "." + name(1) + "." + a.Name, true
				}
			}
		}
	}
	return "", false
}

// taintOf returns the secret an expression is derived from, if any.
func (s *moduleScope) taintOf(e hcl.Expression) (string, bool) {
	if s == nil || e == nil {
		return "", false
	}
	for _, t := range e.Variables() {
		if o, ok := s.secretOrigin(t); ok {
			return o, true
		}
	}
	return "", false
}

// build propagates taint through locals and evaluates what it can.
func (s *moduleScope) build() {
	for changed, i := true, 0; changed && i < 20; i++ {
		changed = false
		for k, e := range s.locals {
			if _, done := s.taint["local."+k]; done {
				continue
			}
			if o, ok := s.taintOf(e); ok {
				s.taint["local."+k] = o
				changed = true
			}
		}
	}
	vars := map[string]cty.Value{}
	for k, v := range s.vars {
		val := cty.DynamicVal
		if v.def != nil {
			if dv, d := v.def.Value(nil); !d.HasErrors() {
				val = dv
			}
		}
		vars[k] = val
	}
	s.ctx = &hcl.EvalContext{
		Variables: map[string]cty.Value{
			"var":   cty.ObjectVal(vars),
			"path":  cty.ObjectVal(map[string]cty.Value{"module": cty.StringVal("${path.module}"), "root": cty.StringVal("${path.root}"), "cwd": cty.StringVal("${path.cwd}")}),
			"local": cty.EmptyObjectVal,
		},
		Functions: safeFunctions,
	}
	// Evaluate locals in passes so locals can use other locals.
	for i := 0; i < 8; i++ {
		progress := false
		for k, e := range s.locals {
			if _, ok := s.evaluated[k]; ok {
				continue
			}
			v, d := e.Value(s.ctx)
			if d.HasErrors() || !v.IsWhollyKnown() {
				continue
			}
			s.evaluated[k] = v
			progress = true
		}
		if !progress {
			break
		}
		s.ctx.Variables["local"] = cty.ObjectVal(s.evaluated)
	}
}

// evalText evaluates e and returns its string content (lists and maps are
// flattened, space-separated). ok is false when e is a plain literal (the
// static analysis already saw it) or cannot be fully evaluated.
func (s *moduleScope) evalText(e hcl.Expression) (string, bool) {
	if s == nil || e == nil || len(e.Variables()) == 0 && !hasCall(e) {
		return "", false
	}
	v, d := e.Value(s.ctx)
	if d.HasErrors() || !v.IsWhollyKnown() || v.IsNull() {
		return "", false
	}
	var parts []string
	flatten(v, &parts)
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, " "), true
}

// withSelf returns a scope whose evaluation context also has `self`, built
// from a resource's triggers/input, so provisioner commands written as
// self.triggers.cmd can be evaluated.
func (s *moduleScope) withSelf(b *hclsyntax.Block) *moduleScope {
	if s == nil {
		return nil
	}
	self := map[string]cty.Value{}
	for _, n := range []string{"triggers", "triggers_replace", "input"} {
		at, ok := b.Body.Attributes[n]
		if !ok {
			continue
		}
		v, d := at.Expr.Value(s.ctx)
		if d.HasErrors() {
			continue
		}
		self[n] = v
		if n == "input" {
			self["output"] = v
		}
	}
	if len(self) == 0 {
		return s
	}
	c := *s
	ctx := *s.ctx
	ctx.Variables = map[string]cty.Value{}
	for k, v := range s.ctx.Variables {
		ctx.Variables[k] = v
	}
	ctx.Variables["self"] = cty.ObjectVal(self)
	c.ctx = &ctx
	return &c
}

func hasCall(e hcl.Expression) bool {
	found := false
	if se, ok := e.(hclsyntax.Expression); ok {
		hclsyntax.VisitAll(se, func(n hclsyntax.Node) hcl.Diagnostics {
			if _, ok := n.(*hclsyntax.FunctionCallExpr); ok {
				found = true
			}
			return nil
		})
	}
	return found
}

func flatten(v cty.Value, out *[]string) {
	if v.IsNull() || !v.IsKnown() {
		return
	}
	t := v.Type()
	switch {
	case t == cty.String:
		*out = append(*out, v.AsString())
	case t == cty.Number || t == cty.Bool:
		return
	case t.IsListType() || t.IsTupleType() || t.IsSetType() || t.IsMapType() || t.IsObjectType():
		for it := v.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			flatten(ev, out)
		}
	}
}

// safeFunctions are pure functions only. File, network and time functions
// are deliberately absent: evaluation must never touch the host.
var safeFunctions = map[string]function.Function{
	"upper": stdlib.UpperFunc, "lower": stdlib.LowerFunc, "reverse": stdlib.ReverseListFunc, "strrev": stdlib.ReverseFunc,
	"join": stdlib.JoinFunc, "split": stdlib.SplitFunc, "replace": stdlib.ReplaceFunc, "regex_replace": stdlib.RegexReplaceFunc,
	"format": stdlib.FormatFunc, "formatlist": stdlib.FormatListFunc, "concat": stdlib.ConcatFunc,
	"trimspace": stdlib.TrimSpaceFunc, "trim": stdlib.TrimFunc, "trimprefix": stdlib.TrimPrefixFunc, "trimsuffix": stdlib.TrimSuffixFunc,
	"chomp": stdlib.ChompFunc, "substr": stdlib.SubstrFunc, "element": stdlib.ElementFunc, "lookup": stdlib.LookupFunc,
	"coalesce": stdlib.CoalesceFunc, "flatten": stdlib.FlattenFunc, "distinct": stdlib.DistinctFunc, "merge": stdlib.MergeFunc,
	"jsonencode": stdlib.JSONEncodeFunc, "jsondecode": stdlib.JSONDecodeFunc, "length": stdlib.LengthFunc,
	"tostring": stdlib.MakeToFunc(cty.String), "tolist": stdlib.MakeToFunc(cty.List(cty.DynamicPseudoType)),
	"compact": stdlib.CompactFunc, "slice": stdlib.SliceFunc, "keys": stdlib.KeysFunc, "values": stdlib.ValuesFunc,
	"base64decode": base64DecodeFunc, "base64encode": base64EncodeFunc, "urlencode": urlEncodeFunc,
	"textdecodebase64": base64DecodeFunc2,
}

var base64DecodeFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "str", Type: cty.String}},
	Type:   function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		b, err := base64.StdEncoding.DecodeString(args[0].AsString())
		if err != nil || !utf8.Valid(b) {
			return cty.UnknownVal(cty.String), nil
		}
		return cty.StringVal(string(b)), nil
	},
})

var base64DecodeFunc2 = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "str", Type: cty.String}, {Name: "enc", Type: cty.String}},
	Type:   function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, t cty.Type) (cty.Value, error) {
		return base64DecodeFunc.Call(args[:1])
	},
})

var base64EncodeFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "str", Type: cty.String}},
	Type:   function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		return cty.StringVal(base64.StdEncoding.EncodeToString([]byte(args[0].AsString()))), nil
	},
})

var urlEncodeFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "str", Type: cty.String}},
	Type:   function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, _ cty.Type) (cty.Value, error) {
		return cty.StringVal(url.QueryEscape(args[0].AsString())), nil
	},
})
