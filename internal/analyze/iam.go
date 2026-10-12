package analyze

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"github.com/r-morato/tfcap/internal/model"
	"github.com/r-morato/tfcap/internal/rules"
)

// statement is a normalized IAM policy statement. Only static values are
// captured; anything dynamic is left empty and treated as "unknown".
type statement struct {
	effect       string
	actions      []string
	notActions   []string
	resources    []string
	anyPrincipal bool
	hasCondition bool
}

var privescActions = map[string]bool{
	"iam:passrole": true, "iam:createaccesskey": true, "iam:createloginprofile": true,
	"iam:updateloginprofile": true, "iam:attachuserpolicy": true, "iam:attachrolepolicy": true,
	"iam:attachgrouppolicy": true, "iam:putuserpolicy": true, "iam:putrolepolicy": true,
	"iam:putgrouppolicy": true, "iam:createpolicyversion": true, "iam:setdefaultpolicyversion": true,
	"iam:updateassumerolepolicy": true, "iam:addusertogroup": true, "sts:assumerole": true,
	"lambda:updatefunctioncode": true, "iam:*": true, "sts:*": true,
}

func (a *analyzer) evalStatement(st statement, addr string, rng hcl.Range, evidence string) {
	if strings.EqualFold(st.effect, "deny") {
		return
	}
	anyResource := contains(st.resources, "*")
	if contains(st.actions, "*") && anyResource {
		a.add(rules.IAMWildcardBoth, addr, rng, "Allows Action \"*\" on Resource \"*\" (administrator equivalent)", "iam:*:*", evidence)
	} else {
		var wild []string
		for _, ac := range st.actions {
			if ac == "*" || strings.HasSuffix(ac, ":*") {
				wild = append(wild, ac)
			}
		}
		if len(st.notActions) > 0 {
			a.add(rules.IAMWildcardAction, addr, rng, "Allow with NotAction grants everything except "+strings.Join(st.notActions, ", "), "iam:notaction:"+strings.Join(sortedCopy(st.notActions), ","), evidence, "not-action")
		}
		if len(wild) > 0 {
			a.add(rules.IAMWildcardAction, addr, rng, "Grants wildcard actions: "+strings.Join(wild, ", "), "iam:"+strings.Join(sortedCopy(wild), ","), evidence)
		}
		if anyResource {
			var esc []string
			for _, ac := range st.actions {
				if privescActions[strings.ToLower(ac)] {
					esc = append(esc, ac)
				}
			}
			if len(esc) > 0 {
				a.add(rules.IAMPrivilegeEscal, addr, rng, "Grants privilege-escalation actions on \"*\": "+strings.Join(esc, ", "), "iam:esc:"+strings.Join(sortedCopy(esc), ","), evidence)
			}
		}
	}
	if st.anyPrincipal {
		a.add(rules.IAMTrustAnyPrincipal, addr, rng, "Allows any principal (\"*\")", "iam:principal:*", evidence)
		if st.hasCondition {
			a.res.Capabilities[len(a.res.Capabilities)-1].Severity = model.Low
		}
	}
}

func sortedCopy(ss []string) []string {
	c := append([]string(nil), ss...)
	sort.Strings(c)
	return c
}

// iamDocument handles data "aws_iam_policy_document".
func (a *analyzer) iamDocument(addr string, b *hclsyntax.Block) {
	for _, sb := range b.Body.Blocks {
		if sb.Type != "statement" {
			continue
		}
		st := statement{effect: "Allow"}
		if at, ok := attr(sb, "effect"); ok {
			if s, ok := staticString(at.Expr); ok {
				st.effect = s
			}
		}
		if at, ok := attr(sb, "actions"); ok {
			st.actions, _ = staticStrings(at.Expr)
		}
		if at, ok := attr(sb, "not_actions"); ok {
			st.notActions, _ = staticStrings(at.Expr)
		}
		if at, ok := attr(sb, "resources"); ok {
			st.resources, _ = staticStrings(at.Expr)
		}
		for _, nb := range sb.Body.Blocks {
			switch nb.Type {
			case "principals":
				if at, ok := attr(nb, "identifiers"); ok {
					ids, _ := staticStrings(at.Expr)
					if contains(ids, "*") {
						st.anyPrincipal = true
					}
				}
			case "condition":
				st.hasCondition = true
			}
		}
		a.evalStatement(st, addr, sb.TypeRange, a.text(sb.Range()))
	}
}

// iamObject handles policy-shaped HCL objects such as those passed to
// jsonencode({ Statement = [{ Effect = "Allow", Action = "*", ... }] }).
func (a *analyzer) iamObject(e *hclsyntax.ObjectConsExpr, addr string) {
	items := map[string]hclsyntax.Expression{}
	for _, it := range e.Items {
		k := objectKey(it.KeyExpr)
		if k != "" {
			items[k] = it.ValueExpr
		}
	}
	_, hasAction := items["Action"]
	_, hasNotAction := items["NotAction"]
	_, hasPrincipal := items["Principal"]
	if !hasAction && !hasNotAction && !hasPrincipal {
		return
	}
	if _, ok := items["Effect"]; !ok && !hasAction {
		return
	}
	st := statement{effect: "Allow"}
	if x, ok := items["Effect"]; ok {
		if s, ok := staticString(x); ok {
			st.effect = s
		}
	}
	if x, ok := items["Action"]; ok {
		st.actions, _ = staticStrings(x)
	}
	if x, ok := items["NotAction"]; ok {
		st.notActions, _ = staticStrings(x)
	}
	if x, ok := items["Resource"]; ok {
		st.resources, _ = staticStrings(x)
	}
	if x, ok := items["Principal"]; ok {
		if v, diags := x.Value(nil); !diags.HasErrors() {
			st.anyPrincipal = ctyHasStar(v)
		}
	}
	_, st.hasCondition = items["Condition"]
	a.evalStatement(st, addr, e.SrcRange, a.text(e.SrcRange))
}

func objectKey(k hclsyntax.Expression) string {
	if ok, isKey := k.(*hclsyntax.ObjectConsKeyExpr); isKey {
		if kw := hcl.ExprAsKeyword(ok.Wrapped); kw != "" {
			return kw
		}
		k = ok.Wrapped
	}
	if s, ok := staticString(k); ok {
		return s
	}
	return ""
}

func ctyHasStar(v cty.Value) bool {
	if !v.IsWhollyKnown() || v.IsNull() {
		return false
	}
	switch {
	case v.Type() == cty.String:
		return v.AsString() == "*"
	case v.CanIterateElements():
		for it := v.ElementIterator(); it.Next(); {
			_, ev := it.Element()
			if ctyHasStar(ev) {
				return true
			}
		}
	}
	return false
}

// iamJSON handles literal JSON policy documents (heredocs, strings).
func (a *analyzer) iamJSON(s, addr string, rng hcl.Range) {
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start < 0 || end <= start {
		return
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(s[start:end+1]), &doc); err != nil {
		return
	}
	var stmts []any
	switch v := doc["Statement"].(type) {
	case []any:
		stmts = v
	case map[string]any:
		stmts = []any{v}
	}
	for _, raw := range stmts {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		st := statement{effect: "Allow"}
		if e, ok := m["Effect"].(string); ok {
			st.effect = e
		}
		st.actions = jsonStrings(m["Action"])
		st.notActions = jsonStrings(m["NotAction"])
		st.resources = jsonStrings(m["Resource"])
		st.anyPrincipal = jsonHasStar(m["Principal"])
		_, st.hasCondition = m["Condition"]
		a.evalStatement(st, addr, rng, s)
	}
}

func jsonStrings(v any) []string {
	switch x := v.(type) {
	case string:
		return []string{x}
	case []any:
		var out []string
		for _, e := range x {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func jsonHasStar(v any) bool {
	switch x := v.(type) {
	case string:
		return x == "*"
	case []any:
		for _, e := range x {
			if jsonHasStar(e) {
				return true
			}
		}
	case map[string]any:
		for _, e := range x {
			if jsonHasStar(e) {
				return true
			}
		}
	}
	return false
}
