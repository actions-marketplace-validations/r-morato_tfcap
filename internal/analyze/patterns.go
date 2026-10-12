package analyze

import (
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

// shellPattern is a named indicator found in command text.
type shellPattern struct {
	tag string
	re  *regexp.Regexp
}

var shellPatterns = []shellPattern{
	{"download-and-execute", regexp.MustCompile(`(?i)\b(curl|wget|fetch)\b[^|;&\n]*\|\s*(sudo\s+)?(ba|z|da|k)?sh\b`)},
	{"download-and-execute", regexp.MustCompile(`(?i)(iex|invoke-expression)\b.*(downloadstring|invoke-webrequest|iwr|irm)`)},
	{"base64-decode", regexp.MustCompile(`(?i)\bbase64\s+(-d|--decode|-D)\b|frombase64string|\bopenssl\s+(enc\s+)?-d|\bxxd\s+-r`)},
	{"encoded-powershell", regexp.MustCompile(`(?i)powershell(\.exe)?\b.*\s-(e|enc|encodedcommand)\s`)},
	{"raw-socket", regexp.MustCompile(`(?i)/dev/(tcp|udp)/|\b(nc|ncat|netcat|socat)\b\s`)},
	{"eval", regexp.MustCompile(`\beval\b\s*[\("'$]`)},
	{"inline-interpreter", regexp.MustCompile(`(?i)\b(python[0-9.]*|perl|ruby|node)\s+-(c|e)\b`)},
	{"env-dump", regexp.MustCompile(`(?i)\bprintenv\b|\benv\b\s*($|[|>;&])|/proc/(self|\d+)/environ|\bset\b\s*\|\s*`)},
	{"upload", regexp.MustCompile(`(?i)\bcurl\b[^\n;]*\s(-d|--data[a-z-]*|-F|--form|-T|--upload-file)\b`)},
	{"make-executable", regexp.MustCompile(`(?i)\bchmod\s+(\+x|[0-7]?[75][0-7][0-7])\b`)},
	{"detach", regexp.MustCompile(`(?i)\bnohup\b|\bdisown\b|\bsetsid\b|&\s*$|start-process\b.*-windowstyle\s+hidden`)},
	{"build-and-run", regexp.MustCompile(`(?i)\bgo\s+run\b|\bgo\s+build\b|\bgcc\b|\bcargo\s+run\b`)},
	{"temp-dir", regexp.MustCompile(`(?i)/tmp/\.|/dev/shm/|%temp%|\$env:temp`)},
	{"history-tamper", regexp.MustCompile(`(?i)history\s+-c|unset\s+histfile|\.bash_history`)},
}

// matchShell returns the sorted unique set of indicator tags present in s.
func matchShell(s string) []string {
	set := map[string]bool{}
	for _, p := range shellPatterns {
		if p.re.MatchString(s) {
			set[p.tag] = true
		}
	}
	return sortedKeys(set)
}

var sensitivePathRes = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(^|[/\\~"'\s:=])\.(aws|ssh|kube|docker|azure|gnupg|netrc|git-credentials|npmrc|pypirc|terraformrc|oci)([/\\"'\s]|$)`),
	regexp.MustCompile(`(?i)\.config[/\\](gcloud|gh)\b`),
	regexp.MustCompile(`(?i)\.terraform\.d[/\\]credentials`),
	regexp.MustCompile(`(?i)credentials\.tfrc\.json`),
	regexp.MustCompile(`(?i)/etc/(shadow|sudoers|ssh/)`),
	regexp.MustCompile(`(?i)/var/run/secrets/`),
	regexp.MustCompile(`(?i)\bid_(rsa|ed25519|ecdsa|dsa)\b`),
	regexp.MustCompile(`(?i)application_default_credentials\.json`),
	regexp.MustCompile(`(?i)169\.254\.169\.254/latest/(meta-data/iam|api/token)|metadata\.google\.internal/computeMetadata/v1/instance/service-accounts`),
}

// sensitivePath returns the first credential-ish path reference in s.
func sensitivePath(s string) (string, bool) {
	for _, re := range sensitivePathRes {
		for _, loc := range re.FindAllStringIndex(s, -1) {
			// ~/.ssh/known_hosts is public data that build tooling mounts
			// routinely; it is not credential material.
			if strings.HasPrefix(strings.ToLower(s[loc[1]:]), "known_hosts") ||
				strings.HasPrefix(strings.ToLower(s[loc[0]:]), "/.ssh/known_hosts") {
				continue
			}
			for _, home := range []string{"~", "$HOME", "${HOME}", "%USERPROFILE%", "$env:USERPROFILE"} {
				if strings.HasSuffix(s[:loc[0]], home) {
					loc[0] -= len(home)
					break
				}
			}
			return strings.Trim(s[loc[0]:loc[1]], " \"'=:"), true
		}
	}
	return "", false
}

var credEnvRe = regexp.MustCompile(`\b(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|AWS_ACCESS_KEY_ID|AWS_CONTAINER_CREDENTIALS_FULL_URI|GITHUB_TOKEN|GH_TOKEN|ACTIONS_ID_TOKEN_REQUEST_TOKEN|ACTIONS_ID_TOKEN_REQUEST_URL|ACTIONS_RUNTIME_TOKEN|ARM_CLIENT_SECRET|ARM_ACCESS_KEY|ARM_OIDC_TOKEN|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS|GOOGLE_CREDENTIALS|GOOGLE_OAUTH_ACCESS_TOKEN|TF_TOKEN_[A-Za-z0-9_]+|TFE_TOKEN|ATLAS_TOKEN|VAULT_TOKEN|CI_JOB_TOKEN|CI_JOB_JWT[A-Z0-9_]*|NPM_TOKEN|DIGITALOCEAN_TOKEN|CLOUDFLARE_API_TOKEN|HCLOUD_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|SPACELIFT_API_[A-Z_]+|BUILDKITE_AGENT_ACCESS_TOKEN|CIRCLE_TOKEN)\b`)

// credEnvRefs returns the unique credential variable names mentioned in s.
func credEnvRefs(s string) []string {
	set := map[string]bool{}
	for _, m := range credEnvRe.FindAllString(s, -1) {
		set[m] = true
	}
	return sortedKeys(set)
}

var urlRe = regexp.MustCompile(`(?i)\b(https?|wss?|ftp)://[^\s"'<>\\` + "`" + `]+`)

// urlHosts returns hosts of absolute URLs whose host part is static.
func urlHosts(s string) []string {
	set := map[string]bool{}
	for _, raw := range urlRe.FindAllString(s, -1) {
		if h := hostOf(raw); h != "" {
			set[h] = true
		}
	}
	return sortedKeys(set)
}

func hostOf(raw string) string {
	// Cut at interpolation; a partially dynamic host is not a static host.
	if i := strings.Index(raw, "${"); i >= 0 {
		raw = raw[:i]
		if !strings.Contains(strings.SplitN(raw, "://", 2)[1], "/") {
			return ""
		}
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return ""
	}
	h := strings.ToLower(u.Hostname())
	if !strings.Contains(h, ".") && net.ParseIP(h) == nil {
		return ""
	}
	return h
}

var ipRe = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b(/\d{1,2})?`)

// publicIPs returns public IPv4 literals in s that are not CIDR blocks.
func publicIPs(s string) []string {
	set := map[string]bool{}
	for _, m := range ipRe.FindAllStringSubmatchIndex(s, -1) {
		if m[10] != -1 { // has /prefix → CIDR, which is normal in IaC
			continue
		}
		// Skip things that look like version numbers: preceded by "v" or ".".
		if m[0] > 0 && (s[m[0]-1] == '.' || s[m[0]-1] == 'v' || s[m[0]-1] == 'V') {
			continue
		}
		lit := s[m[0]:m[1]]
		ip := net.ParseIP(lit)
		if ip == nil || ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() ||
			ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
			continue
		}
		if isDocumentationIP(ip) || isWellKnownResolver(lit) {
			continue
		}
		set[lit] = true
	}
	return sortedKeys(set)
}

func isDocumentationIP(ip net.IP) bool {
	for _, c := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "100.64.0.0/10"} {
		_, n, _ := net.ParseCIDR(c)
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func isWellKnownResolver(s string) bool {
	switch s {
	case "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "208.67.222.222":
		return true
	}
	return false
}

var (
	base64BlobRe = regexp.MustCompile(`[A-Za-z0-9+/]{160,}={0,2}`)
	hexBlobRe    = regexp.MustCompile(`(?i)\b[0-9a-f]{256,}\b`)
)

// encodedBlob reports the length of the largest encoded blob in s, ignoring
// PEM certificates and public keys, which are routine in IaC.
func encodedBlob(s string) (kind string, n int) {
	if strings.Contains(s, "-----BEGIN CERTIFICATE") || strings.Contains(s, "-----BEGIN PUBLIC KEY") ||
		strings.HasPrefix(strings.TrimSpace(s), "ssh-") {
		return "", 0
	}
	for _, m := range base64BlobRe.FindAllString(s, -1) {
		if len(m) > n && looksEncoded(m) {
			kind, n = "base64", len(m)
		}
	}
	for _, m := range hexBlobRe.FindAllString(s, -1) {
		if len(m) > n {
			kind, n = "hex", len(m)
		}
	}
	return kind, n
}

// looksEncoded filters out long runs that are clearly not base64, like a
// repeated character or a long path.
func looksEncoded(s string) bool {
	var upper, lower, digit int
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z':
			upper++
		case r >= 'a' && r <= 'z':
			lower++
		case r >= '0' && r <= '9':
			digit++
		}
	}
	return upper > len(s)/10 && lower > len(s)/10 && digit > 0
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func truncate(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
