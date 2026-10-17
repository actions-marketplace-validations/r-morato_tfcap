package sandbox

import (
	"fmt"
	"strings"

	"github.com/r-morato/tfcap/internal/model"
	"github.com/r-morato/tfcap/internal/rules"
)

// providerHosts are API domains that providers call while planning. A
// connection to them is expected, as long as no canary goes with it.
var providerHosts = []string{
	"amazonaws.com", "amazonaws.com.cn", "aws", "googleapis.com", "google.com", "azure.com", "azure.net",
	"microsoft.com", "microsoftonline.com", "windows.net", "api.github.com", "cloudflare.com", "hashicorp.com",
	"terraform.io", "opentofu.org", "digitalocean.com", "datadoghq.com", "datadoghq.eu", "oraclecloud.com",
	"hetzner.cloud", "linode.com", "vultr.com", "scaleway.com", "ibm.com", "cloud.ibm.com", "kubernetes.default.svc",
}

func expectedHost(h string) bool {
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	for _, d := range providerHosts {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// expectedProc reports whether a program is Terraform itself or a provider.
func expectedProc(p string) bool {
	return p == "terraform" || p == "tofu" || strings.HasPrefix(p, "terraform-provider-") || p == "strace"
}

// credentialOwner maps decoy paths to the provider that legitimately
// reads them while configuring itself.
var credentialOwner = map[string]string{
	".aws/": "terraform-provider-aws", ".config/gcloud/": "terraform-provider-google", ".azure/": "terraform-provider-azurerm",
	".kube/": "terraform-provider-kubernetes", ".docker/": "terraform-provider-docker",
}

// Findings turns observed events into capabilities. moduleDirs maps module
// keys to their directories (relative to the scanned root, or absolute),
// so programs can be attributed to the module that ships them.
func Findings(res *Result, moduleDirs map[string]string) []model.Capability {
	var out []model.Capability
	add := func(id string, sev model.Severity, module, addr, msg, detail, evidence string, tags ...string) {
		r := rules.Get(id)
		out = append(out, model.Capability{RuleID: r.ID, Severity: sev, Phase: model.PhasePlan, Module: module,
			Address: addr, Message: msg, Detail: detail, Evidence: evidence, Tags: tags})
	}
	for _, e := range res.Events {
		module := ""
		best := 0
		for k, d := range moduleDirs {
			if d != "" && d != "." && len(d) > best && strings.Contains(e.Detail+" "+e.Host, d+"/") {
				module, best = k, len(d)
			}
		}
		if e.Leak && e.Kind == "exec" {
			add(rules.DynExec, model.Critical, module, "sandbox", fmt.Sprintf("Ran %s during plan with a decoy credential in its arguments: %s", e.Proc, truncate(e.Detail, 120)),
				"exec:"+e.Proc, e.Detail, "honeytoken")
			continue
		}
		if e.Leak {
			add(rules.DynCanaryLeak, model.Critical, module, "sandbox", fmt.Sprintf("Honeytoken sent over the network (%s %s)", e.Kind, e.Host),
				"leak:"+e.Kind+":"+e.Host, e.Detail, "honeytoken")
			continue
		}
		switch e.Kind {
		case "dns", "connect", "http", "tls":
			host := e.Host
			if host == "" {
				host = "(unknown)"
			}
			if expectedHost(host) {
				add(rules.DynNetwork, model.Info, module, "sandbox", fmt.Sprintf("Provider API call to %s (expected)", host), "net:"+host, e.Detail, e.Kind)
				continue
			}
			sev := model.High
			if e.Kind == "dns" {
				sev = model.Medium // a lookup alone; the connection, if any, is its own event
			}
			where := host
			if e.Port != 0 {
				where = fmt.Sprintf("%s:%d", host, e.Port)
			}
			add(rules.DynNetwork, sev, module, "sandbox", fmt.Sprintf("Network %s to %s during plan", e.Kind, where), "net:"+host, e.Detail, e.Kind)
		case "exec":
			if expectedProc(e.Proc) {
				continue
			}
			add(rules.DynExec, model.High, module, "sandbox", "Ran "+e.Proc+" during plan: "+truncate(e.Detail, 120), "exec:"+e.Proc, e.Detail)
		case "open":
			sev := model.High
			for prefix, owner := range credentialOwner {
				if strings.HasPrefix(strings.TrimPrefix(e.Host, "~/"), prefix) && e.Proc == owner {
					sev = model.Info
				}
			}
			proc := e.Proc
			if proc == "" {
				proc = "a process"
			}
			add(rules.DynCredRead, sev, module, "sandbox", fmt.Sprintf("%s opened decoy credential %s", proc, e.Host), "open:"+e.Host+":"+proc, "")
		}
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}
