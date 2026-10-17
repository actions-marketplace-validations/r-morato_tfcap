// Package rules is the catalog of capability rules tfcap knows about. It is
// used for SARIF rule metadata, `tfcap rules`, and documentation.
package rules

import (
	"sort"

	"github.com/r-morato/tfcap/internal/model"
)

// Rule describes one capability class.
type Rule struct {
	ID       string
	Name     string
	Severity model.Severity
	Phase    model.Phase
	Summary  string
	Help     string
}

// All rule IDs. Prefixes group them: EXEC, NET, FS, CRED, OBF, IAM, SRC, PROV.
const (
	ExecExternalData = "TFCAP-EXEC-001"
	ExecLocal        = "TFCAP-EXEC-002"
	ExecRemote       = "TFCAP-EXEC-003"
	ExecShellPattern = "TFCAP-EXEC-004"

	NetHTTPData  = "TFCAP-NET-001"
	NetEndpoint  = "TFCAP-NET-002"
	NetIPLiteral = "TFCAP-NET-003"
	NetDNSData   = "TFCAP-NET-004"

	FSSensitiveRead = "TFCAP-FS-001"
	FSLocalRead     = "TFCAP-FS-002"
	FSLocalWrite    = "TFCAP-FS-003"
	FSUpload        = "TFCAP-FS-004"

	CredEnvReference = "TFCAP-CRED-001"

	ObfBase64Blob   = "TFCAP-OBF-001"
	ObfDecodeInline = "TFCAP-OBF-002"
	ObfBinaryFile   = "TFCAP-OBF-003"
	ObfUnparsed     = "TFCAP-OBF-004"

	IAMWildcardAction    = "TFCAP-IAM-001"
	IAMWildcardBoth      = "TFCAP-IAM-002"
	IAMPrivilegeEscal    = "TFCAP-IAM-003"
	IAMTrustAnyPrincipal = "TFCAP-IAM-004"

	SrcGitUnpinned       = "TFCAP-SRC-001"
	SrcGitMutableRef     = "TFCAP-SRC-002"
	SrcRegistryUnpinned  = "TFCAP-SRC-003"
	SrcHTTPArchive       = "TFCAP-SRC-004"
	SrcContentChanged    = "TFCAP-SRC-005"
	SrcNotDownloaded     = "TFCAP-SRC-006"
	SrcInsecureTransport = "TFCAP-SRC-007"

	ProvTyposquat    = "TFCAP-PROV-001"
	ProvUnofficialNS = "TFCAP-PROV-002"
	ProvCustomHost   = "TFCAP-PROV-003"
	ProvExecCapable  = "TFCAP-PROV-004"
	ProvNew          = "TFCAP-PROV-005"
	ProvUpgraded     = "TFCAP-PROV-006"
	ProvMutated      = "TFCAP-PROV-007"

	FlowSecretNet  = "TFCAP-FLOW-001"
	FlowSecretExec = "TFCAP-FLOW-002"

	RepKnownMalicious = "TFCAP-REP-001"
	RepRepoMissing    = "TFCAP-REP-002"
	RepRepoMoved      = "TFCAP-REP-003"
	RepRepoArchived   = "TFCAP-REP-004"
	RepRepoYoung      = "TFCAP-REP-005"
	RepLowScorecard   = "TFCAP-REP-006"
	RepFreshRelease   = "TFCAP-REP-007"
	RepUnknownModule  = "TFCAP-REP-008"
)

var catalog = map[string]Rule{
	ExecExternalData: {ExecExternalData, "external-data-source", model.Critical, model.PhasePlan,
		"Runs an arbitrary local program during `terraform plan`.",
		"`data \"external\"` executes its `program` on the machine running Terraform as soon as the data source is read, which happens during plan, before anyone reviews or approves anything. In a third-party module this is equivalent to running unreviewed code in CI with all of its credentials."},
	ExecLocal: {ExecLocal, "local-exec-provisioner", model.High, model.PhaseApply,
		"Runs a shell command on the Terraform host during apply.",
		"`local-exec` provisioners run arbitrary commands with the environment of the Terraform process (cloud credentials, CI tokens). Review the command, and prefer native resources."},
	ExecRemote: {ExecRemote, "remote-exec-provisioner", model.Medium, model.PhaseApply,
		"Runs commands on a remote host over SSH/WinRM during apply.",
		"`remote-exec` runs commands on created infrastructure. It can be legitimate bootstrap logic but is a common place to hide backdoors."},
	ExecShellPattern: {ExecShellPattern, "suspicious-shell-pattern", model.High, model.PhaseApply,
		"A command contains download-and-execute, encoding or network-tool patterns.",
		"Patterns such as `curl | sh`, `base64 -d`, `nc`, `/dev/tcp` or `eval` inside a provisioner or external program are strong indicators of a dropper or exfiltration step."},

	NetHTTPData: {NetHTTPData, "http-data-source", model.High, model.PhasePlan,
		"Makes an HTTP request during `terraform plan`.",
		"`data \"http\"` is fetched during plan. Combined with interpolated values in the URL, headers or body it can exfiltrate secrets before any approval gate."},
	NetEndpoint: {NetEndpoint, "hardcoded-endpoint", model.Info, model.PhaseStatic,
		"Contains a hard-coded URL.",
		"Inventory of hosts this module references. Mostly informational; it becomes interesting when a new host appears in an upgrade."},
	NetIPLiteral: {NetIPLiteral, "hardcoded-ip", model.Low, model.PhaseStatic,
		"Contains a hard-coded public IP address.",
		"Public IP literals (not CIDR ranges) in a reusable module are unusual and worth a look."},
	NetDNSData: {NetDNSData, "dns-data-source", model.Medium, model.PhasePlan,
		"Performs DNS lookups during plan.",
		"`data \"dns_*\"` lookups happen during plan and can be used as a low-bandwidth exfiltration channel by encoding data into queried names."},

	FSSensitiveRead: {FSSensitiveRead, "sensitive-file-read", model.Critical, model.PhasePlan,
		"Reads credential or key material from the Terraform host.",
		"References to paths such as `~/.aws/credentials`, `~/.ssh`, `~/.kube/config`, `~/.docker/config.json` or `/etc/` from a module have almost no legitimate use and are a classic credential-stealer signature."},
	FSLocalRead: {FSLocalRead, "local-file-read", model.Low, model.PhasePlan,
		"Reads a file outside the module directory.",
		"Reading files via absolute paths, `~`, or `..` escapes reaches outside the module. Usually benign (e.g. a user-supplied path), occasionally not."},
	FSLocalWrite: {FSLocalWrite, "local-file-write", model.Low, model.PhaseApply,
		"Writes files on the Terraform host.",
		"`local_file`/`local_sensitive_file` resources write to the machine running Terraform."},
	FSUpload: {FSUpload, "file-provisioner", model.Medium, model.PhaseApply,
		"Copies files from the Terraform host to a remote machine.",
		"`file` provisioners can ship local files (including secrets) to remote hosts."},

	CredEnvReference: {CredEnvReference, "credential-env-reference", model.High, model.PhaseApply,
		"References well-known credential environment variables.",
		"Commands or strings that mention variables such as `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN` or `ARM_CLIENT_SECRET` suggest the module wants the credentials Terraform is running with."},

	ObfBase64Blob: {ObfBase64Blob, "encoded-blob", model.High, model.PhaseStatic,
		"Contains a large base64/hex encoded blob.",
		"Large encoded literals hide what code actually does. Legitimate uses exist (certificates, user-data), so check what it decodes to."},
	ObfDecodeInline: {ObfDecodeInline, "inline-decode", model.Medium, model.PhaseStatic,
		"Decodes an inline literal at runtime (base64decode/textdecodebase64 on a constant).",
		"Decoding a constant hides the effective value from reviewers and scanners."},
	ObfBinaryFile: {ObfBinaryFile, "binary-in-module", model.High, model.PhaseStatic,
		"Module ships a compiled executable.",
		"ELF, PE or Mach-O binaries inside a module package are rarely needed and cannot be reviewed. They are a common payload carrier for `external`/`local-exec` droppers."},
	ObfUnparsed: {ObfUnparsed, "unparseable-config", model.Medium, model.PhaseStatic,
		"A Terraform file could not be parsed, so it was not analyzed.",
		"Terraform may still accept files that a scanner fails on. Unparseable files are a scanner-evasion vector; look at them by hand."},

	IAMWildcardAction: {IAMWildcardAction, "iam-wildcard-action", model.Medium, model.PhaseStatic,
		"Grants a wildcard IAM action (e.g. `*` or `s3:*`).",
		"Wildcard actions grant every current and future permission for that service."},
	IAMWildcardBoth: {IAMWildcardBoth, "iam-admin-equivalent", model.High, model.PhaseStatic,
		"Grants `*` actions on `*` resources (administrator equivalent).",
		"An Allow statement with Action `*` and Resource `*` is full administrator access."},
	IAMPrivilegeEscal: {IAMPrivilegeEscal, "iam-privilege-escalation", model.High, model.PhaseStatic,
		"Grants IAM actions that allow privilege escalation.",
		"Actions such as `iam:PassRole`, `iam:CreateAccessKey`, `iam:AttachRolePolicy` or `sts:AssumeRole` on `*` let the grantee become someone more powerful."},
	IAMTrustAnyPrincipal: {IAMTrustAnyPrincipal, "iam-trust-any-principal", model.High, model.PhaseStatic,
		"A trust or resource policy allows any principal (`*`).",
		"Principal `*` lets any AWS account assume the role or access the resource unless constrained by conditions."},

	SrcGitUnpinned: {SrcGitUnpinned, "git-module-unpinned", model.Medium, model.PhaseInit,
		"Git module source has no `ref`, so it tracks the default branch.",
		"Every `terraform init` may fetch different code. Pin to a full commit SHA."},
	SrcGitMutableRef: {SrcGitMutableRef, "git-module-mutable-ref", model.Low, model.PhaseInit,
		"Git module source is pinned to a tag/branch, not a commit SHA.",
		"Tags and branches can be moved. Terraform's lock file does not record module hashes, so a moved tag silently changes the code you run. Pin `?ref=<40-char sha>` or use `tfcap lock`."},
	SrcRegistryUnpinned: {SrcRegistryUnpinned, "registry-module-unpinned", model.Low, model.PhaseInit,
		"Registry module has no exact version.",
		"Without an exact `version = \"x.y.z\"` constraint, new releases are picked up automatically on the next init."},
	SrcHTTPArchive: {SrcHTTPArchive, "http-archive-module", model.Medium, model.PhaseInit,
		"Module is downloaded from an HTTP(S) archive URL.",
		"Archive sources have no integrity check; anyone controlling the URL controls the code."},
	SrcContentChanged: {SrcContentChanged, "module-content-changed", model.Critical, model.PhaseInit,
		"Module content changed while its source and version stayed the same.",
		"The same source+version now hashes differently than when it was locked. This is what a re-pointed git tag or a compromised registry looks like."},
	SrcNotDownloaded: {SrcNotDownloaded, "module-not-downloaded", model.Info, model.PhaseInit,
		"Remote module was not analyzed because it is not downloaded.",
		"Run `terraform init` (or `tofu init`) first so tfcap can read `.terraform/modules`."},
	SrcInsecureTransport: {SrcInsecureTransport, "insecure-module-transport", model.High, model.PhaseInit,
		"Module is fetched over plain HTTP or unauthenticated git://.",
		"Plain-text transports allow anyone on the network path to substitute module code."},

	ProvTyposquat: {ProvTyposquat, "provider-typosquat", model.Critical, model.PhaseInit,
		"Provider source looks like a typo of a popular provider.",
		"Provider binaries run with full access during init/plan/apply. A source that is one edit away from a well-known provider (e.g. `kreuzwenker/docker` vs `kreuzwerker/docker`) is a strong typosquatting signal."},
	ProvUnofficialNS: {ProvUnofficialNS, "provider-community", model.Info, model.PhaseInit,
		"Provider is published by a community namespace.",
		"Inventory of non-HashiCorp, non-partner providers. Worth knowing who you trust."},
	ProvCustomHost: {ProvCustomHost, "provider-custom-host", model.Medium, model.PhaseInit,
		"Provider is installed from a non-default registry host.",
		"Providers from custom hosts bypass the public registry's publisher verification."},
	ProvNew: {ProvNew, "provider-new", model.Medium, model.PhaseInit,
		"A provider was added since the lock was reviewed.",
		"Provider binaries run with the full permissions of Terraform. Check the publisher before accepting a new one."},
	ProvUpgraded: {ProvUpgraded, "provider-upgraded", model.Low, model.PhaseInit,
		"A provider version changed since the lock was reviewed.",
		"Routine, but worth a glance at the provider's changelog."},
	FlowSecretNet: {FlowSecretNet, "secret-to-network", model.High, model.PhasePlan,
		"A secret (sensitive variable, secret store read, generated password) flows into a request made during plan.",
		"tfcap follows references through locals from secret sources to data \"http\" and DNS lookups. In the URL or body the secret leaves to whoever the URL names; a header to a fixed API host is the normal way to send a token and is graded medium."},
	FlowSecretExec: {FlowSecretExec, "secret-to-exec", model.High, model.PhasePlan,
		"A secret flows into a program or command (external data source or local-exec).",
		"Secrets in a command line show up in process lists and CI logs, and the program receiving them can send them anywhere. Passing them in a local-exec environment block is safer and graded medium."},
	RepKnownMalicious: {RepKnownMalicious, "known-malicious", model.Critical, model.PhaseInit,
		"Module or provider is on tfcap's list of confirmed malicious packages.",
		"The list only contains packages with a public, verified incident report. Remove it and rotate any credentials that were present where it ran."},
	RepRepoMissing: {RepRepoMissing, "source-repo-missing", model.High, model.PhaseInit,
		"The module's GitHub repository no longer exists (--online).",
		"A deleted or renamed repository name can be registered by someone else (repo-jacking), and the next init then fetches their code."},
	RepRepoMoved: {RepRepoMoved, "source-repo-moved", model.Medium, model.PhaseInit,
		"The module's GitHub repository was renamed or transferred (--online).",
		"GitHub redirects the old name until someone claims it. Point the source at the new location."},
	RepRepoArchived: {RepRepoArchived, "source-repo-archived", model.Low, model.PhaseInit,
		"The module's GitHub repository is archived (--online).",
		"Archived repositories get no security fixes."},
	RepRepoYoung: {RepRepoYoung, "source-repo-young", model.Medium, model.PhaseInit,
		"The module's GitHub repository or registry namespace is less than 90 days old (--online).",
		"New publishers have no track record; most malicious packages are young."},
	RepLowScorecard: {RepLowScorecard, "low-openssf-scorecard", model.Low, model.PhaseInit,
		"The source repository scores below 4/10 on the OpenSSF Scorecard (--online).",
		"Weak repository security practices (no branch protection, unpinned CI, no code review) make a takeover easier."},
	RepFreshRelease: {RepFreshRelease, "fresh-release", model.Low, model.PhaseInit,
		"The registry version in use was published in the last 7 days (--online).",
		"Compromised releases are usually caught within days. A short cool-off before adopting new versions avoids most of them."},
	RepUnknownModule: {RepUnknownModule, "registry-module-not-found", model.Medium, model.PhaseInit,
		"The public registry does not know this module or version (--online).",
		"The module may have been removed, often because it was malicious, or the source is misspelled."},
	ProvMutated: {ProvMutated, "provider-content-changed", model.Critical, model.PhaseInit,
		"A provider's checksums changed while its version stayed the same.",
		"The registry's checksums for a given provider version never change. Different hashes for the same version mean a different binary: a compromised release or registry."},
	ProvExecCapable: {ProvExecCapable, "exec-capable-provider", model.Medium, model.PhasePlan,
		"Requires a provider whose purpose is running programs or making requests.",
		"Providers like `hashicorp/external`, `hashicorp/http` or `scottwinkler/shell` exist to execute code or talk to the network."},
}

// Get returns the rule for id; unknown IDs get a generic rule.
func Get(id string) Rule {
	if r, ok := catalog[id]; ok {
		return r
	}
	return Rule{ID: id, Name: id, Severity: model.Info, Summary: id}
}

// All returns every rule sorted by ID.
func All() []Rule {
	out := make([]Rule, 0, len(catalog))
	for _, r := range catalog {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
