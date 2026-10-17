// Package sandbox runs a command (normally `terraform plan`) with no real
// network, no real credentials and a decoy home directory full of
// honeytokens, and records what the command and anything it starts tried
// to do: DNS lookups, connections, HTTP requests, programs executed and
// decoy credential files opened. It is a detector, not a security
// boundary: run it on a disposable CI runner or VM.
package sandbox

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Honey holds the canary value planted in every decoy credential.
type Honey struct {
	Canary string            // 24 lowercase hex chars
	Files  map[string]string // path relative to HOME -> content
	Env    map[string]string
}

// NewHoney creates a fresh canary and the decoy files and variables.
func NewHoney() *Honey {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	c := hex.EncodeToString(b)
	up := strings.ToUpper(c)
	akid := "AKIA" + up[:16]
	secret := "tfcap" + c + "TfcapHoneytokenDoNotUse0"
	h := &Honey{Canary: c, Files: map[string]string{
		".aws/credentials": fmt.Sprintf("[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n", akid, secret),
		".aws/config":      "[default]\nregion = us-east-1\n",
		".ssh/id_ed25519":  "-----BEGIN OPENSSH PRIVATE KEY-----\ntfcap-honeytoken-" + c + "\n-----END OPENSSH PRIVATE KEY-----\n",
		".kube/config":     "apiVersion: v1\nkind: Config\nusers:\n- name: u\n  user:\n    token: tfcap" + c + "\n",
		".docker/config.json": `{"auths":{"https://index.docker.io/v1/":{"auth":"` +
			base64.StdEncoding.EncodeToString([]byte("tfcap:"+c)) + `"}}}`,
		".config/gcloud/application_default_credentials.json": `{"type":"authorized_user","client_id":"tfcap","client_secret":"tfcap` + c + `","refresh_token":"tfcap` + c + `"}`,
		".git-credentials": "https://tfcap:tfcap" + c + "@github.com\n",
		".netrc":           "machine github.com login tfcap password tfcap" + c + "\n",
	}, Env: map[string]string{
		"AWS_ACCESS_KEY_ID":              akid,
		"AWS_SECRET_ACCESS_KEY":          secret,
		"AWS_SESSION_TOKEN":              "tfcap" + c,
		"GITHUB_TOKEN":                   "ghp_tfcap" + c,
		"GH_TOKEN":                       "ghp_tfcap" + c,
		"ARM_CLIENT_SECRET":              "tfcap" + c,
		"GOOGLE_OAUTH_ACCESS_TOKEN":      "ya29.tfcap" + c,
		"VAULT_TOKEN":                    "hvs.tfcap" + c,
		"TFE_TOKEN":                      "tfcap" + c,
		"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "tfcap" + c,
		"ACTIONS_ID_TOKEN_REQUEST_URL":   "http://oidc.tfcap.invalid/token",
	}}
	return h
}

// Write creates the decoy files under home.
func (h *Honey) Write(home string) error {
	for rel, body := range h.Files {
		p := filepath.Join(home, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return err
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			return err
		}
	}
	return nil
}

// Patterns returns encodings of the canary to look for in traffic: plain,
// upper-case hex (AWS key id) and base64 at each of the three alignments.
func (h *Honey) Patterns() []string {
	raw := []string{h.Canary, strings.ToUpper(h.Canary[:16])}
	out := append([]string(nil), raw...)
	for _, r := range raw {
		for pad := 0; pad < 3; pad++ {
			buf := append(make([]byte, pad), r...)
			enc := base64.StdEncoding.EncodeToString(buf)
			// Drop characters that depend on the unknown neighbouring bytes.
			start := (pad*8 + 5) / 6
			end := len(enc) - 4
			if end-start >= 12 {
				out = append(out, enc[start:end])
			}
		}
	}
	return out
}

// Leaks reports whether s contains the canary in any known encoding.
func (h *Honey) Leaks(s string) bool {
	low := strings.ToLower(s)
	for i, p := range h.Patterns() {
		if i < 2 && strings.Contains(low, strings.ToLower(p)) || i >= 2 && strings.Contains(s, p) {
			return true
		}
	}
	return false
}
