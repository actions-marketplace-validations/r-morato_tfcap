package sandbox

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/r-morato/tfcap/internal/model"
	"github.com/r-morato/tfcap/internal/rules"
)

func TestHoneyLeaks(t *testing.T) {
	h := NewHoney()
	creds := h.Files[".aws/credentials"]
	for name, s := range map[string]string{
		"plain":          "GET /?k=" + h.Env["AWS_SECRET_ACCESS_KEY"],
		"key id":         "AKIA" + strings.ToUpper(h.Canary[:16]),
		"dns label":      h.Canary + ".x.example.invalid",
		"base64 file":    base64.StdEncoding.EncodeToString([]byte(creds)),
		"base64 shifted": base64.StdEncoding.EncodeToString([]byte("x" + creds)),
		"base64 shift2":  base64.StdEncoding.EncodeToString([]byte("xy" + creds)),
		"truncated b64":  base64.StdEncoding.EncodeToString([]byte(creds))[:120],
	} {
		if !h.Leaks(s) {
			t.Errorf("%s: canary not detected in %q", name, s)
		}
	}
	if h.Leaks("GET /healthz HTTP/1.1 host: api.example.com") {
		t.Error("false positive")
	}
}

func TestParseQuestion(t *testing.T) {
	q := []byte{0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'a', 'b', 'c', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0, 0, 1, 0, 1}
	name, typ, end, ok := parseQuestion(q)
	if !ok || name != "abc.example" || typ != 1 || end != len(q) {
		t.Errorf("got %q %d %d %v", name, typ, end, ok)
	}
}

func TestFindings(t *testing.T) {
	res := &Result{Events: []Event{
		{Kind: "dns", Host: "sts.amazonaws.com"},
		{Kind: "http", Host: "c.example.invalid", Port: 80, Detail: "POST /", Leak: true},
		{Kind: "exec", Host: "/bin/sh", Proc: "sh", Detail: "sh .terraform/modules/net/x.sh; then ran: curl"},
		{Kind: "exec", Host: "/x/terraform-provider-aws_v6", Proc: "terraform-provider-aws_v6"},
		{Kind: "open", Host: "~/.aws/credentials", Proc: "terraform-provider-aws"},
		{Kind: "open", Host: "~/.aws/credentials", Proc: "sh", Detail: "sh .terraform/modules/net/x.sh"},
	}}
	caps := Findings(res, map[string]string{"net": ".terraform/modules/net"})
	got := map[string]model.Capability{}
	for _, c := range caps {
		got[c.RuleID+" "+c.Detail] = c
	}
	check := func(k string, sev model.Severity, module string) {
		t.Helper()
		c, ok := got[k]
		if !ok {
			t.Errorf("missing %s in %v", k, got)
			return
		}
		if c.Severity != sev || c.Module != module {
			t.Errorf("%s: %s %q", k, c.Severity, c.Module)
		}
	}
	check(rules.DynNetwork+" net:sts.amazonaws.com", model.Info, "")
	check(rules.DynCanaryLeak+" leak:http:c.example.invalid", model.Critical, "")
	check(rules.DynExec+" exec:sh", model.High, "net")
	check(rules.DynCredRead+" open:~/.aws/credentials:terraform-provider-aws", model.Info, "")
	check(rules.DynCredRead+" open:~/.aws/credentials:sh", model.High, "net")
	if len(caps) != 5 {
		t.Errorf("provider exec should be ignored: %d findings", len(caps))
	}
}
