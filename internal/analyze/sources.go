package analyze

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2"

	"github.com/r-morato/tfcap/internal/model"
)

var (
	registrySourceRe = regexp.MustCompile(`^(?:([a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?)/)?([A-Za-z0-9][A-Za-z0-9_-]*)/([A-Za-z0-9][A-Za-z0-9_-]*)/([A-Za-z0-9][A-Za-z0-9_-]*)(//.*)?$`)
	shaRe            = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	exactVersionRe   = regexp.MustCompile(`^=?\s*v?\d+\.\d+\.\d+([-+][0-9A-Za-z.-]+)?$`)
)

// SourceInfo is the parsed form of a module `source` string.
type SourceInfo struct {
	Kind     model.SourceKind
	Ref      string // git ref, if any
	Insecure bool   // http:// or git:// transport
}

// ClassifySource parses a Terraform module source address the way the
// installer would, without fetching anything.
func ClassifySource(src string) SourceInfo {
	s := strings.TrimSpace(src)
	switch {
	case s == "":
		return SourceInfo{Kind: model.SourceUnknown}
	case strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") || s == "." || s == "..",
		strings.HasPrefix(s, ".\\") || strings.HasPrefix(s, "..\\"):
		return SourceInfo{Kind: model.SourceLocal}
	case strings.HasPrefix(s, "s3::") || strings.HasPrefix(s, "gcs::") ||
		strings.Contains(s, ".amazonaws.com/") || strings.HasPrefix(s, "www.googleapis.com/storage"):
		return SourceInfo{Kind: model.SourceBucket}
	case strings.HasPrefix(s, "hg::"):
		return SourceInfo{Kind: model.SourceUnknown, Insecure: strings.Contains(s, "http://")}
	}

	forcedGit := strings.HasPrefix(s, "git::")
	body := strings.TrimPrefix(s, "git::")
	if forcedGit || strings.HasPrefix(body, "git@") || strings.HasPrefix(body, "git://") ||
		strings.HasPrefix(body, "ssh://") || strings.HasPrefix(body, "github.com/") ||
		strings.HasPrefix(body, "bitbucket.org/") || strings.HasSuffix(strings.SplitN(body, "?", 2)[0], ".git") {
		info := SourceInfo{Kind: model.SourceGit}
		info.Insecure = strings.HasPrefix(body, "git://") || strings.HasPrefix(body, "http://")
		if i := strings.Index(body, "?"); i >= 0 {
			if q, err := url.ParseQuery(body[i+1:]); err == nil {
				info.Ref = q.Get("ref")
			}
		}
		return info
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return SourceInfo{Kind: model.SourceHTTP, Insecure: strings.HasPrefix(s, "http://")}
	}
	if registrySourceRe.MatchString(s) {
		return SourceInfo{Kind: model.SourceRegistry}
	}
	return SourceInfo{Kind: model.SourceUnknown}
}

// IsSHA reports whether ref is a full git commit hash.
func IsSHA(ref string) bool { return shaRe.MatchString(strings.ToLower(ref)) }

// IsExactVersion reports whether a version constraint pins one release.
func IsExactVersion(v string) bool { return exactVersionRe.MatchString(strings.TrimSpace(v)) }

// ---- providers ----

// ProviderAddr is a parsed provider source address.
type ProviderAddr struct {
	Host, Namespace, Type string
}

const defaultRegistry = "registry.terraform.io"

// ParseProviderSource parses "ns/type" or "host/ns/type". Legacy
// unqualified names get the hashicorp namespace, as Terraform does.
func ParseProviderSource(src, localName string) ProviderAddr {
	src = strings.ToLower(strings.TrimSpace(src))
	if src == "" {
		return ProviderAddr{defaultRegistry, "hashicorp", strings.ToLower(localName)}
	}
	parts := strings.Split(src, "/")
	switch len(parts) {
	case 1:
		return ProviderAddr{defaultRegistry, "hashicorp", parts[0]}
	case 2:
		return ProviderAddr{defaultRegistry, parts[0], parts[1]}
	default:
		return ProviderAddr{parts[0], parts[len(parts)-2], parts[len(parts)-1]}
	}
}

func (p ProviderAddr) Short() string { return p.Namespace + "/" + p.Type }

// Popular providers that are attractive typosquatting targets. Lowercase.
var popularProviders = []string{
	"hashicorp/aws", "hashicorp/awscc", "hashicorp/azurerm", "hashicorp/azuread", "hashicorp/google",
	"hashicorp/google-beta", "hashicorp/kubernetes", "hashicorp/helm", "hashicorp/random", "hashicorp/null",
	"hashicorp/local", "hashicorp/tls", "hashicorp/http", "hashicorp/external", "hashicorp/archive",
	"hashicorp/time", "hashicorp/vault", "hashicorp/consul", "hashicorp/nomad", "hashicorp/tfe",
	"hashicorp/hcp", "hashicorp/cloudinit", "hashicorp/dns", "hashicorp/template",
	"kreuzwerker/docker", "integrations/github", "cloudflare/cloudflare", "datadog/datadog",
	"mongodb/mongodbatlas", "grafana/grafana", "pagerduty/pagerduty", "newrelic/newrelic",
	"oracle/oci", "digitalocean/digitalocean", "linode/linode", "hetznercloud/hcloud", "auth0/auth0",
	"okta/okta", "snowflake-labs/snowflake", "snowflakedb/snowflake", "databricks/databricks",
	"aliyun/alicloud", "ibm-cloud/ibm", "cyrilgdn/postgresql", "petoju/mysql", "gavinbunney/kubectl",
	"alekc/kubectl", "fluxcd/flux", "carlpett/sops", "coder/coder", "spacelift-io/spacelift",
	"elastic/ec", "elastic/elasticstack", "confluentinc/confluent", "vancluever/acme", "gitlabhq/gitlab",
	"microsoft/azuredevops", "azure/azapi", "vmware/vsphere", "fastly/fastly", "heroku/heroku",
	"opsgenie/opsgenie", "sumologic/sumologic", "splunk-terraform/signalfx", "jfrog/artifactory",
	"bpg/proxmox", "telmate/proxmox", "terraform-aws-modules/http", "scottwinkler/shell",
	"mastercard/restapi", "ns1-terraform/ns1", "cloudamqp/cloudamqp", "launchdarkly/launchdarkly",
	"rancher/rancher2", "ovh/ovh", "exoscale/exoscale", "scaleway/scaleway", "upcloudltd/upcloud",
	"vultr/vultr", "akamai/akamai", "infobloxopen/infoblox", "f5networks/bigip", "paloaltonetworks/panos",
	"fortinetdev/fortios", "ciscodevnet/aci", "junos-vsrx/junos-vsrx", "tailscale/tailscale",
	"opentofu/aws", "opentofu/google", "opentofu/azurerm",
}

var popularSet = func() map[string]bool {
	m := map[string]bool{}
	for _, p := range popularProviders {
		m[p] = true
	}
	return m
}()

// providers whose entire purpose is executing code or making requests.
var execCapableProviders = map[string]bool{
	"hashicorp/external": true, "scottwinkler/shell": true, "mastercard/restapi": true,
	"magodo/restful": true, "jgroeneveld/script": true,
}

// Typosquat returns the popular provider that p imitates, if any.
func Typosquat(p ProviderAddr) (string, bool) {
	short := p.Short()
	if popularSet[short] {
		return "", false
	}
	for _, known := range popularProviders {
		kns, ktype, _ := strings.Cut(known, "/")
		if p.Type == ktype && p.Namespace != kns {
			if norm(p.Namespace) == norm(kns) {
				return known, true
			}
			d := levenshtein(p.Namespace, kns)
			limit := 2
			if len(kns) <= 6 {
				limit = 1
			}
			if d <= limit {
				return known, true
			}
		}
		// Same trusted namespace, near-identical type name.
		if p.Namespace == kns && kns != "hashicorp" && p.Type != ktype && levenshtein(p.Type, ktype) == 1 {
			return known, true
		}
		// A namespace that imitates hashicorp itself.
		if kns == "hashicorp" && p.Namespace != "hashicorp" && levenshtein(p.Namespace, "hashicorp") <= 2 {
			return "hashicorp/" + p.Type, true
		}
	}
	return "", false
}

func norm(s string) string {
	return strings.NewReplacer("-", "", "_", "", ".", "").Replace(strings.ToLower(s))
}

func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}

// officialNamespaces are namespaces we do not bother reporting as community.
var officialNamespaces = map[string]bool{"hashicorp": true, "opentofu": true}

// SourceFindings checks a module source the same way a module block's
// source is checked. It is used for sources that live outside .tf files,
// such as the terraform.source of a terragrunt.hcl.
func SourceFindings(module, file, addr string, line int, source, version string) []model.Capability {
	a := &analyzer{module: module, res: &Result{}, seen: map[string]bool{}, file: file}
	a.checkSource(ModuleCall{Source: source, Version: version}, addr, hcl.Range{Start: hcl.Pos{Line: line}})
	return a.res.Capabilities
}
