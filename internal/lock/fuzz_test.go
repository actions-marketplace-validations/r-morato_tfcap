package lock

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzValidate: a lock file arrives in pull requests, so Validate must
// reject anything malformed without panicking.
func FuzzValidate(f *testing.F) {
	f.Add(`{"schema":"tfcap/lock/v1","modules":[]}`)
	f.Add(`{"schema":"tfcap/lock/v1","modules":[{"key":"a","source":"x","hash":"tfcap1:` +
		`0000000000000000000000000000000000000000000000000000000000000000","capabilities":[]}]}`)
	f.Add(`{"schema":"tfcap/lock/v1","modules":[],"providers_locked":true,"providers":[{"address":"registry.terraform.io/hashicorp/aws","version":"6.0.0","hashes":["h1:a="]}]}`)
	f.Add(`{}`)
	f.Fuzz(func(t *testing.T, body string) {
		p := filepath.Join(t.TempDir(), "tfcap.lock.json")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		_ = Validate(p)
		_, _ = Read(p)
	})
}
