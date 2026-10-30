# Why tfcap exists


Terraform's supply chain has three structural gaps that the misconfiguration scanners weren't built to cover.

**1. Modules have no lock file.** `.terraform.lock.hcl` pins provider *hashes*. It records nothing at all about modules, and OpenTofu inherited the same design. A git module pinned to `?ref=v1.2.0` runs whatever that tag points at today. Tags can be moved, and research from [BoostSecurity Labs](https://labs.boostsecurity.io/articles/erosion-of-trust-unmasking-supply-chain-vulnerabilities-in-the-terraform-registry/) found hundreds of public registry modules whose release tags could be hijacked.

**2. Code runs during `plan`.** `data "external"` executes a program, and `data "http"` makes a request, while Terraform *reads* data sources. That happens during plan, before any human approves anything, in a CI job that usually holds cloud credentials. "We review the plan before apply" doesn't protect you here.

**3. Scanners judge resources, not behavior.** Misconfiguration scanners are excellent at "this S3 bucket is public." They aren't designed to answer "this module started executing a shell script in its latest patch release."

This isn't hypothetical. In 2026 alone:
- **Coder registry compromise (Aug 31).** For about 14 hours, a compromised module registry served Terraform modules that stole cloud, CI/CD and AI API credentials ([CSA research note](https://labs.cloudsecurityalliance.org/research/csa-research-note-coder-registry-terraform-supply-chain-2026/)).
- **Typosquatted Docker provider (September).** `kreuzwenker/docker` unpacked a payload hidden in a `.sqlite3` file and ran it as a detached Go program ([Corgea](https://corgea.com/research/graphalgo-terraform-go-modules-september-2026/)).

## What existing tools see

On the demo module in the README ([`examples/upgrade-attack`](../examples/upgrade-attack)), **Checkov 3.3.28** (default Terraform checks) reports 13 findings. They cover the wildcard IAM policy and the open trust policy (it does that well) plus VPC hygiene. **None** of them cover the `external` program that runs during plan, the plan-time HTTP POST, the script that reads `~/.aws/credentials`, or the typosquatted provider. That's not a bug in Checkov; it's a different question. Run both.

| | Misconfig scanners (Checkov, Trivy, KICS) | `tfcap` |
|---|---|---|
| Insecure resource settings | ✅ deep coverage | IAM wildcards only |
| Programs/requests run during plan | No | ✅ |
| Credential paths & env vars read by modules | No | ✅ incl. helper scripts |
| Capability *changes* across module versions | No | ✅ `diff` / `verify` |
| Module content integrity (tag mutation) | No | ✅ `lock` / `verify` |
| Provider typosquatting | No | ✅ |
| `.tf.json` and unparseable-file handling | varies | ✅ |

## Who it's for

tfcap protects you from code **you didn't write**: modules pulled from the Terraform/OpenTofu registry or from git, and the providers they bring in. It's most useful if:

- your configurations use **third-party modules** (`terraform-aws-modules/*`, a vendor's modules, your company's shared module repos);
- **Dependabot or Renovate** bumps module versions for you, and someone has to approve those PRs;
- **CI runs `terraform plan`** with cloud credentials, where code that runs during plan can reach them.

If your configuration only uses your own resources and local modules, tfcap still checks provider sources and module pins, but there's little for it to lock. That's expected, not a problem.
