# Benchmark: popular public modules

How noisy is tfcap on code people actually use, and how fast is it? This
scans 27 widely used module repositories (AWS, Google, Azure, IBM, Cloud
Posse, Gruntwork, HashiCorp) with tfcap v0.4.0, treating every module
directory as third-party, exactly as it would be when you call it from
your own configuration. Reproduce with:

```sh
while read -r r; do git clone --depth 1 "https://github.com/$r.git" "repos/${r#*/}"; done < bench/repos.txt
go build -o tfcap ./cmd/tfcap
bench/run.py ./tfcap repos results.json
```

## Summary

| | |
|---|---|
| Repositories | 27 |
| Modules scanned | 197 (873 files; `examples/` and tests excluded) |
| Total time | 4.6 s, median 0.06 s per repository |
| Repositories with no findings at all | 14 |
| Findings | 117: 10 critical, 32 high, 6 medium, 17 low, 52 info |
| Repositories with any critical or high finding | 4 |

**Every critical and high finding was reviewed by hand, and every one is
real.** They come from four repositories that genuinely run programs
during `plan` or `apply`:

- `terraform-aws-lambda` runs `package.py` from a `data "external"` during
  plan to build deployment packages, and again from `local-exec`.
- `terraform-aws-utilities` (Gruntwork) is a toolbox of exactly this:
  Python run as data sources, PEX execution, executable checks.
- `terraform-google-gcloud` downloads and runs the gcloud SDK with
  `local-exec`, and reads `GOOGLE_CREDENTIALS`.
- `terraform-ibm-base-ocp-vpc` runs a shell script during plan and a
  dozen scripts at apply, several decoding base64 and posting to APIs.

None of this is malicious. It's the point of a capability inventory: these
are the modules whose next release you'd want to review before running it,
because they already hold the ability to run code in your CI. With
`tfcap lock`, this is reviewed once; after that only *changes* are
reported.

The rest is low-severity context: hosts the modules reference (`NET-002`),
community providers (`PROV-002`), registry submodules without exact
versions (`SRC-003`).

## Expression evaluation and taint tracking

v0.4 evaluates locals, variable defaults and a pure subset of Terraform's
functions, and follows secrets into network and exec sinks. On this corpus
that added **one** finding, and it's accurate: `terraform-ibm-base-ocp-vpc`
passes the sensitive `ibmcloud_api_key` to a `local-exec` script through its
environment (graded medium, the safe way to do it). Evaluation produced no
new findings elsewhere, because it only reports what is *hidden* in the
source: a host, path or shell pattern that appears only after evaluating
`join()`, `format()`, `base64decode()` and similar.

## Detection

Detection is covered by the inert fixtures in this repository rather than
by the corpus above:

- [`examples/upgrade-attack`](../examples/upgrade-attack): a patch release
  that adds plan-time credential theft, a typosquatted provider and an
  admin role. `tfcap diff` reports 14 new capabilities, 6 of them critical.
- [`examples/sandbox-canary`](../examples/sandbox-canary): verified end to
  end with `tofu plan` inside `tfcap sandbox`, which records the program,
  the decoy credential read and the honeytoken leaving in an HTTP request.
- The unit tests under `internal/analyze` cover each rule, including
  expressions that only reveal a host or command after evaluation.

## Per repository

| Repository | Commit | Modules | Findings | Critical/high | Time |
|---|---|---|---|---|---|
| [Azure/terraform-azurerm-aks](https://github.com/Azure/terraform-azurerm-aks) | `58ffc7c` | 2 | 2 | 0 | 0.15s |
| [Azure/terraform-azurerm-avm-res-network-virtualnetwork](https://github.com/Azure/terraform-azurerm-avm-res-network-virtualnetwork) | `22ce4ea` | 3 | 4 | 0 | 0.06s |
| [cloudposse/terraform-aws-ecs-container-definition](https://github.com/cloudposse/terraform-aws-ecs-container-definition) | `b7bd87e` | 1 | 0 | 0 | 0.02s |
| [cloudposse/terraform-aws-eks-cluster](https://github.com/cloudposse/terraform-aws-eks-cluster) | `4fa8d25` | 1 | 0 | 0 | 0.04s |
| [cloudposse/terraform-null-label](https://github.com/cloudposse/terraform-null-label) | `38364d7` | 2 | 0 | 0 | 0.03s |
| [gruntwork-io/terraform-aws-utilities](https://github.com/gruntwork-io/terraform-aws-utilities) | `962e543` | 12 | 9 | 8 | 1.45s |
| [hashicorp/terraform-aws-consul](https://github.com/hashicorp/terraform-aws-consul) | `9fc09ae` | 5 | 0 | 0 | 0.03s |
| [terraform-aws-modules/terraform-aws-alb](https://github.com/terraform-aws-modules/terraform-aws-alb) | `6c6e48c` | 2 | 0 | 0 | 0.03s |
| [terraform-aws-modules/terraform-aws-atlantis](https://github.com/terraform-aws-modules/terraform-aws-atlantis) | `7b7073e` | 3 | 2 | 0 | 0.02s |
| [terraform-aws-modules/terraform-aws-autoscaling](https://github.com/terraform-aws-modules/terraform-aws-autoscaling) | `2a249e9` | 1 | 0 | 0 | 0.05s |
| [terraform-aws-modules/terraform-aws-cloudfront](https://github.com/terraform-aws-modules/terraform-aws-cloudfront) | `5b9a0a4` | 2 | 0 | 0 | 0.03s |
| [terraform-aws-modules/terraform-aws-ec2-instance](https://github.com/terraform-aws-modules/terraform-aws-ec2-instance) | `4dfedcd` | 1 | 0 | 0 | 0.03s |
| [terraform-aws-modules/terraform-aws-ecs](https://github.com/terraform-aws-modules/terraform-aws-ecs) | `135c225` | 5 | 0 | 0 | 0.14s |
| [terraform-aws-modules/terraform-aws-eks](https://github.com/terraform-aws-modules/terraform-aws-eks) | `91b8a8d` | 8 | 1 | 0 | 0.16s |
| [terraform-aws-modules/terraform-aws-iam](https://github.com/terraform-aws-modules/terraform-aws-iam) | `da8e6a8` | 8 | 3 | 0 | 0.06s |
| [terraform-aws-modules/terraform-aws-kms](https://github.com/terraform-aws-modules/terraform-aws-kms) | `d25e459` | 1 | 0 | 0 | 0.02s |
| [terraform-aws-modules/terraform-aws-lambda](https://github.com/terraform-aws-modules/terraform-aws-lambda) | `851d209` | 4 | 7 | 3 | 0.19s |
| [terraform-aws-modules/terraform-aws-rds](https://github.com/terraform-aws-modules/terraform-aws-rds) | `175da04` | 7 | 0 | 0 | 0.05s |
| [terraform-aws-modules/terraform-aws-rds-aurora](https://github.com/terraform-aws-modules/terraform-aws-rds-aurora) | `d72cba2` | 2 | 0 | 0 | 0.04s |
| [terraform-aws-modules/terraform-aws-s3-bucket](https://github.com/terraform-aws-modules/terraform-aws-s3-bucket) | `9afa4fc` | 7 | 0 | 0 | 0.08s |
| [terraform-aws-modules/terraform-aws-security-group](https://github.com/terraform-aws-modules/terraform-aws-security-group) | `b3c1b2e` | 55 | 5 | 0 | 0.25s |
| [terraform-aws-modules/terraform-aws-vpc](https://github.com/terraform-aws-modules/terraform-aws-vpc) | `b3abd6d` | 3 | 0 | 0 | 0.09s |
| [terraform-google-modules/terraform-google-gcloud](https://github.com/terraform-google-modules/terraform-google-gcloud) | `7e70361` | 3 | 20 | 17 | 0.05s |
| [terraform-google-modules/terraform-google-kubernetes-engine](https://github.com/terraform-google-modules/terraform-google-kubernetes-engine) | `c44138e` | 21 | 22 | 0 | 0.88s |
| [terraform-google-modules/terraform-google-network](https://github.com/terraform-google-modules/terraform-google-network) | `91352be` | 20 | 6 | 0 | 0.11s |
| [terraform-google-modules/terraform-google-project-factory](https://github.com/terraform-google-modules/terraform-google-project-factory) | `eeda8a6` | 12 | 1 | 0 | 0.07s |
| [terraform-ibm-modules/terraform-ibm-base-ocp-vpc](https://github.com/terraform-ibm-modules/terraform-ibm-base-ocp-vpc) | `f9372a8` | 6 | 35 | 14 | 0.46s |

Measured on a 4-vCPU Linux container, October 2026.
