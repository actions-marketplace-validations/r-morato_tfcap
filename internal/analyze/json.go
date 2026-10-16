package analyze

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/hcl/v2"

	"github.com/r-morato/tfcap/internal/model"
	"github.com/r-morato/tfcap/internal/rules"
)

// analyzeJSON handles .tf.json files. Terraform's JSON syntax is a common
// blind spot for scanners, which makes it an obvious place to hide things,
// so tfcap applies the same rules to it.
func (a *analyzer) analyzeJSON(src []byte) {
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(src))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		a.add(rules.ObfUnparsed, "", hcl.Range{Start: hcl.InitialPos}, "JSON file could not be parsed and was not analyzed: "+err.Error(), a.file, "")
		a.rawText(string(src), "", hcl.Range{Start: hcl.InitialPos})
		return
	}
	for _, section := range sortedMapKeys(root) {
		v := root[section]
		switch section {
		case "resource", "data":
			eachLabeled2(v, func(typ, name string, body map[string]any) {
				addr := typ + "." + name
				if section == "data" {
					addr = "data." + addr
					a.jsonData(typ, addr, body)
				} else {
					a.jsonResource(typ, addr, body)
				}
				a.jsonStrings(body, addr)
			})
		case "module":
			eachLabeled1(v, func(name string, body map[string]any) {
				addr := "module." + name
				src, _ := body["source"].(string)
				ver, _ := body["version"].(string)
				call := ModuleCall{Name: name, Source: src, Version: ver, File: a.file, Line: a.lineOf(`"` + name + `"`)}
				call.PinLine = call.Line
				a.res.Calls = append(a.res.Calls, call)
				a.checkSource(call, addr, a.rangeOf(`"`+name+`"`))
				rest := map[string]any{}
				for k, v := range body {
					if k != "source" && k != "version" {
						rest[k] = v
					}
				}
				a.jsonStrings(rest, addr)
			})
		case "terraform":
			for _, tb := range asObjects(v) {
				for _, rp := range asObjects(tb["required_providers"]) {
					for _, name := range sortedMapKeys(rp) {
						p := model.Provider{Name: name}
						switch x := rp[name].(type) {
						case string:
							p.Version = x
						case map[string]any:
							p.Source, _ = x["source"].(string)
							p.Version, _ = x["version"].(string)
						}
						a.provider(p, a.rangeOf(`"`+name+`"`))
					}
				}
			}
		default:
			a.jsonStrings(v, section)
		}
	}
}

func (a *analyzer) jsonResource(typ, addr string, body map[string]any) {
	rng := a.rangeOf(`"` + typ + `"`)
	switch typ {
	case "local_file", "local_sensitive_file":
		a.add(rules.FSLocalWrite, addr, rng, "Writes a file on the Terraform host", "write:"+typ, "")
	case "shell_script":
		a.execCommand(rules.ExecLocal, addr, rng, compactJSON(body), "shell_script resource runs commands")
	}
	// "provisioner": [{"local-exec": {...}}] or {"local-exec": {...}}
	for _, pm := range asObjects(body["provisioner"]) {
		for _, kind := range sortedMapKeys(pm) {
			for _, pb := range asObjects(pm[kind]) {
				prng := a.rangeOf(`"` + kind + `"`)
				switch kind {
				case "local-exec":
					cmd := fmt.Sprint(pb["command"])
					if it, ok := pb["interpreter"]; ok {
						cmd = compactJSON(it) + " " + cmd
					}
					a.execCommand(rules.ExecLocal, addr, prng, cmd, "local-exec provisioner runs a command on the Terraform host")
				case "remote-exec":
					a.execCommand(rules.ExecRemote, addr, prng, compactJSON(pb), "remote-exec provisioner runs commands on a remote host")
				case "file":
					src := fmt.Sprint(pb["source"])
					a.add(rules.FSUpload, addr, prng, "file provisioner uploads "+truncate(src, 60), "src:"+normCmd(src), src)
				}
			}
		}
	}
}

func (a *analyzer) jsonData(typ, addr string, body map[string]any) {
	rng := a.rangeOf(`"` + typ + `"`)
	switch {
	case typ == "external":
		a.execCommand(rules.ExecExternalData, addr, rng, compactJSON(body["program"]), "external data source runs a program during plan")
	case typ == "http":
		u := fmt.Sprint(body["url"])
		host := "dynamic"
		if hs := urlHosts(u); len(hs) > 0 {
			host = hs[0]
		}
		var tags []string
		if strings.Contains(u, "${") {
			tags = append(tags, "interpolated-url")
		}
		if _, ok := body["request_body"]; ok {
			tags = append(tags, "sends-body")
		}
		a.add(rules.NetHTTPData, addr, rng, "http data source contacts "+host+" during plan", "host:"+host, u, tags...)
		if len(tags) >= 2 {
			a.bump(model.Critical)
		}
	case strings.HasPrefix(typ, "dns_"):
		a.add(rules.NetDNSData, addr, rng, typ+" performs DNS lookups during plan", "dns:"+typ, "")
	case typ == "aws_iam_policy_document":
		for _, st := range asObjects(body["statement"]) {
			s := statement{effect: "Allow"}
			if e, ok := st["effect"].(string); ok {
				s.effect = e
			}
			s.actions = jsonStrings(st["actions"])
			s.notActions = jsonStrings(st["not_actions"])
			s.resources = jsonStrings(st["resources"])
			for _, p := range asObjects(st["principals"]) {
				if contains(jsonStrings(p["identifiers"]), "*") {
					s.anyPrincipal = true
				}
			}
			_, s.hasCondition = st["condition"]
			a.evalStatement(s, addr, rng, compactJSON(st))
		}
	}
}

// jsonStrings runs string indicators over every string value, and IAM
// checks over policy-shaped objects.
func (a *analyzer) jsonStrings(v any, addr string) {
	switch x := v.(type) {
	case string:
		a.stringValue(x, addr, a.rangeOf(firstLine(x)))
		if strings.Contains(x, "file(") || strings.Contains(x, "pathexpand(") {
			if p, ok := sensitivePath(x); ok {
				a.add(rules.FSSensitiveRead, addr, a.rangeOf(firstLine(x)), "Reads credential material: "+p, "path:"+p, x)
			}
		}
	case []any:
		for _, e := range x {
			a.jsonStrings(e, addr)
		}
	case map[string]any:
		if _, ok := x["Action"]; ok {
			s := statement{effect: "Allow"}
			if e, ok := x["Effect"].(string); ok {
				s.effect = e
			}
			s.actions = jsonStrings(x["Action"])
			s.resources = jsonStrings(x["Resource"])
			s.anyPrincipal = jsonHasStar(x["Principal"])
			_, s.hasCondition = x["Condition"]
			a.evalStatement(s, addr, a.rangeOf(`"Action"`), compactJSON(x))
		}
		for _, k := range sortedMapKeys(x) {
			if k == "description" {
				continue
			}
			a.jsonStrings(x[k], addr)
		}
	}
}

func (a *analyzer) lineOf(needle string) int {
	i := bytes.Index(a.src, []byte(needle))
	if i < 0 {
		return 1
	}
	return bytes.Count(a.src[:i], []byte("\n")) + 1
}

func (a *analyzer) rangeOf(needle string) hcl.Range {
	return hcl.Range{Filename: a.file, Start: hcl.Pos{Line: a.lineOf(needle)}}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 40 {
		s = s[:40]
	}
	// JSON-escape so we can find it in the raw source.
	b, _ := json.Marshal(s)
	return strings.Trim(string(b), `"`)
}

func compactJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

func asObjects(v any) []map[string]any {
	switch x := v.(type) {
	case map[string]any:
		return []map[string]any{x}
	case []any:
		var out []map[string]any
		for _, e := range x {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

func eachLabeled1(v any, fn func(string, map[string]any)) {
	for _, m := range asObjects(v) {
		for _, name := range sortedMapKeys(m) {
			for _, body := range asObjects(m[name]) {
				fn(name, body)
			}
		}
	}
}

func eachLabeled2(v any, fn func(string, string, map[string]any)) {
	eachLabeled1(v, func(typ string, inner map[string]any) {
		for _, name := range sortedMapKeys(inner) {
			for _, body := range asObjects(inner[name]) {
				fn(typ, name, body)
			}
		}
	})
}

func sortedMapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
