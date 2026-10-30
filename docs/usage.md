# Using tfcap

The full reference for the command line. For the GitHub Action, see [github-action.md](github-action.md).

## Install

Requires Go 1.25 or newer.

```sh
go install github.com/r-morato/tfcap/cmd/tfcap@latest
```

`go install` puts the binary in `~/go/bin` (on Windows, `%USERPROFILE%\go\bin`). If your shell says `tfcap: command not found`, add that folder to your PATH:

```sh
# macOS / Linux with zsh (use ~/.bashrc for bash)
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.zshrc && source ~/.zshrc
```

The Windows Go installer usually adds its folder to PATH for you. Check it works with `tfcap version`.

Prebuilt binaries for Linux, macOS and Windows (Intel and ARM) are attached to each [release](https://github.com/r-morato/tfcap/releases) if you'd rather not install Go. Each release also has a `checksums.txt`.

## Try it in two minutes

- **[`examples/testkit`](../examples/testkit)**: ten small, defused Terraform configurations, one per kind of risk, and a `run-all.sh` that checks tfcap catches each one.
- **[`examples/realworld-lab`](../examples/realworld-lab)**: a hands-on lab with a real `terraform init`. A module maintainer gets compromised, the tag you pinned is quietly moved to malicious code, Terraform downloads it without a warning, and `tfcap verify` stops it before `plan`. Needs git and Terraform or OpenTofu; no cloud account.

## Scan

`tfcap` reads source code only. It never runs Terraform and never talks to the network unless you pass `--online`.

```sh
terraform init -backend=false   # or tofu init; downloads modules into .terraform/modules
tfcap scan                      # inventory everything
tfcap scan --third-party-only --min-severity medium
```

Without `init`, `tfcap` still scans the root and its local modules, and lists the remote ones it couldn't see.

## Lock and verify (recommended for CI)

```sh
tfcap lock          # writes tfcap.lock.json: per-module content hash + reviewed capabilities
git add tfcap.lock.json
```

Then, on every pull request:

```sh
terraform init -backend=false
tfcap verify        # exit 1 if anything is unreviewed at or above --fail-on (default: high)
```

`verify` reports each third-party module as one of:

| Status | Meaning |
|---|---|
| `ok` | Same source, version and content as locked. |
| `upgraded` | Version or source changed. Only capabilities **not** in the lock are reported. |
| `MUTATED` | **Same version, different content.** The tag was moved or the release was swapped. Always critical. For git modules the message names the commit the tag used to point at. |
| `new` | Module not in the lock; all of its capabilities are reported. |
| `removed` | In the lock, no longer used. |

After reviewing an upgrade, run `tfcap lock` again and commit (or let the GitHub Action do it, see [Approving from the pull request](github-action.md#approving-from-the-pull-request)). The lock diff in the PR then shows exactly which capabilities you accepted.

`tfcap lock` is safe to re-run:

- It **refuses** to accept a `MUTATED` module (same version, different code) and exits 1, so a hurried `lock` can't quietly approve a tampered module. If you've investigated and it's legitimate, pass `--accept-mutated`.
- `--module <key>` updates only that module's entry (repeatable), leaving the rest of the lock untouched.
- It prints what changed: `+` added, `~` updated (with the number of new capabilities), `-` removed.

## Providers

`tfcap lock` also records every provider's version and checksums from `.terraform.lock.hcl`, so `verify` covers providers too:

| Status | Meaning |
|---|---|
| `new` | Provider not in the lock (medium). |
| `upgraded` | Version changed (low). |
| `MUTATED` | Same version, but none of the locked checksums match any more (critical). `lock` refuses it, like a mutated module. |

`init` adding `h1:` hashes for another platform is normal and stays `ok`. Lock files written before v0.3 skip provider checks until you re-run `tfcap lock`.

## Pin git modules to commits

```sh
tfcap pin            # rewrites ?ref=v1.2.0 to ?ref=<the commit it resolved to>
tfcap pin --check    # CI: exit 1 if anything is still on a tag or branch
```

`pin` uses the commit `init` actually downloaded, and leaves a `# tfcap pin: was ref=v1.2.0` comment so reviewers can see the tag. `--exact-registry` also pins registry modules to the exact version installed. Only literal sources are rewritten.

## Accept a finding on purpose: `tfcap.hcl`

Some findings are fine for your setup. Write them down instead of turning the rule off:

```hcl
# tfcap.hcl, next to tfcap.lock.json
allow {
  module      = "module.network"          # optional, * globs allowed; default: any module
  rules       = ["TFCAP-NET-003"]          # required, * globs allowed
  detail      = "host:*.amazonaws.com"     # optional, matches the finding's detail
  reason      = "Talks to AWS APIs only, reviewed in SEC-123"
  approved_by = "@alice"
  expires     = "2027-03-31"               # required, at most a year out
}
```

`scan` and `verify` drop matching findings and say how many they dropped; the PR comment lists them with who approved them and why. An exception stops applying the day after it expires, and `tfcap` warns two weeks before. Integrity findings (mutated modules or providers) can't be accepted. `--no-policy` shows everything. Protect `tfcap.hcl` with CODEOWNERS like the lock file.

## SBOM

```sh
tfcap sbom -o tfcap.cdx.json
```

Writes a CycloneDX 1.6 SBOM of third-party modules (source, version, resolved commit as a `pkg:github` purl, content hash, capability counts) and providers (version, SHA-256 checksums). Output is reproducible: the serial number comes from the content, and `SOURCE_DATE_EPOCH` sets the timestamp.

## Reputation checks (`--online`)

```sh
GITHUB_TOKEN=... tfcap verify --online
```

Opt-in. Asks the Terraform registry, the GitHub API and the OpenSSF Scorecard API about each third-party module: the version doesn't exist on the registry, it was published in the last 7 days, the source repository is gone (repo-jacking risk), renamed, archived or under 90 days old, or scores below 4 on Scorecard. The token is only sent to GitHub. Network errors are warnings, never failures. Confirmed malicious packages (`TFCAP-REP-001`) are flagged offline, from a short list with a public incident report for every entry.

## Terragrunt

Run `tfcap` in a unit directory (the one with `terragrunt.hcl`) after `terragrunt init`. The `terraform.source` is checked like any module source (including `tfr://`), and the copy in `.terragrunt-cache` is scanned, locked and verified as `module.terragrunt`. Files Terragrunt copies or generates from your unit are treated as your code. For many units: `find live -name terragrunt.hcl -execdir tfcap verify \;`.

## pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/r-morato/tfcap
    rev: v0.4.0
    hooks:
      - id: tfcap-verify          # needs `terraform init` to have run
      - id: tfcap-validate-lock
      - id: tfcap-pin-check
```

## GitLab CI

```yaml
tfcap:
  image: golang:1.25
  variables:
    TFCAP_VERSION: v0.4.0
  before_script:
    - go install github.com/r-morato/tfcap/cmd/tfcap@${TFCAP_VERSION}
    # install terraform or tofu here, then:
    - tofu init -backend=false -input=false
  script:
    - tfcap verify --format sarif -o gl-tfcap.sarif --fail-on none
    - tfcap verify
  artifacts:
    when: always
    paths: [gl-tfcap.sarif]
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
```

For approvals on GitLab, run `tfcap lock` locally and commit the lock file; it is a normal reviewed change like any other.

## Sandbox: watch `plan` actually run (Linux)

Static analysis can be outwitted. `tfcap sandbox` runs the real thing and watches:

```sh
terraform init -backend=false     # outside the sandbox: it needs the network
tfcap sandbox                     # runs terraform/tofu plan inside it
tfcap sandbox -- tofu plan -var-file=ci.tfvars
```

The plan runs in new Linux namespaces (no root needed where unprivileged user namespaces are allowed):

- **No network.** Only loopback exists. Every DNS name resolves to the sandbox, and every IPv4 address routes to it, so lookups, HTTP requests, TLS server names, proxy `CONNECT`s and raw-IP connections are all recorded instead of leaving.
- **Decoy credentials.** Your real `~/.aws`, `~/.ssh`, `~/.kube` and friends are hidden. The environment and home directory carry fake AWS, GitHub, Azure, GCP and Vault credentials containing a unique canary. If the canary shows up in a DNS name, URL or request body, in plain text, upper case or base64 at any alignment, that's `TFCAP-DYN-002`: theft caught in the act.
- **Programs and file opens** are recorded with `strace` when it's installed: what Terraform started, what that ran in turn, and who opened a decoy credential file. Findings are attributed to the module whose files were involved.

Calls to well-known provider API domains, and a provider reading its own credentials (the AWS provider reading `~/.aws`), are reported as info. A plan that fails without real credentials is normal and doesn't matter: data sources and their programs have already run by then.

It's a detector, not a security boundary: run it on a disposable CI runner or VM. On Ubuntu 23.10+, AppArmor blocks unprivileged user namespaces; use `sudo -E tfcap sandbox` there, or set `kernel.apparmor_restrict_unprivileged_userns=0`. HTTPS bodies are encrypted, so a canary inside one is only seen if it also appears in the URL host, DNS or a program's arguments. Try it on [`examples/sandbox-canary`](../examples/sandbox-canary).

## Diff two trees or reports

```sh
tfcap diff main-checkout/ pr-checkout/
tfcap scan --format json -o base.json    # on the base branch
tfcap scan --format json -o head.json    # on the PR branch
tfcap diff base.json head.json --format markdown > comment.md
```

## Commands

| Command | What it does |
|---|---|
| `tfcap scan [dir]` | Inventory capabilities. Formats: `text`, `json`, `sarif`. |
| `tfcap diff <base> <head>` | Capabilities added/removed. Each side is a directory or a JSON report. Formats: `text`, `json`, `markdown`, `sarif`. |
| `tfcap lock [dir]` | Write `tfcap.lock.json`. |
| `tfcap verify [dir]` | Check against the lock. Formats: `text`, `json`, `markdown`, `sarif`. |
| `tfcap pin [dir]` | Rewrite git module refs to the commit they resolved to. `--check` for CI, `--exact-registry` for registry versions. |
| `tfcap sbom [dir]` | CycloneDX 1.6 SBOM of modules and providers. |
| `tfcap sandbox [dir] [-- cmd]` | Run `plan` with no network and decoy credentials, and report what it tried (Linux). |
| `tfcap validate-lock <file>...` | Strict schema check of a lock file (unknown fields, malformed hashes). |
| `tfcap rules` | List every rule (`--format markdown` for docs). |

Common flags: `--fail-on <severity|none>`, `--min-severity`, `--third-party-only`, `--format`, `--output`, `--data-dir`, `--no-color`, `--policy <file>` / `--no-policy`, `--online`, and for SARIF `--sarif-base <dir>` (the scanned folder relative to the repository root).
Exit codes: `0` ok, `1` findings at or above `--fail-on`, `2` usage or runtime error.

## What it detects

The full catalog, with rationale, is in [docs/rules.md](rules.md). The highlights:

| Area | Examples |
|---|---|
| **Execution** | `data "external"` (plan-time), `local-exec`, `remote-exec`, `shell_script`; download-and-execute, env dumps, `/dev/tcp`, `base64 -d`, detached processes. Helper scripts referenced via `${path.module}` are opened and scanned too. |
| **Network** | `data "http"` (critical when the URL is interpolated and data is sent), DNS data sources, hard-coded hosts and public IPs |
| **Credentials** | `~/.aws`, `~/.ssh`, `~/.kube`, `~/.docker`, gcloud ADC, `credentials.tfrc.json`, cloud metadata endpoints; `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `ACTIONS_ID_TOKEN_REQUEST_TOKEN`, `TF_TOKEN_*`… |
| **Obfuscation** | Large base64/hex blobs, `base64decode("<constant>")`, compiled binaries shipped inside modules, unparseable files |
| **IAM** | `*:*` admin grants, `service:*`, `NotAction`, privilege-escalation actions, `Principal: "*"`. Covers `aws_iam_policy_document`, `jsonencode({...})` and heredoc JSON. |
| **Module sources** | Unpinned git, tag/branch refs instead of SHAs, inexact registry versions, archive URLs, plain-HTTP transports, content changed under the same version |
| **Providers** | Typosquats of ~90 popular providers, confirmed malicious packages, custom registry hosts, exec-capable providers, community namespaces in third-party code; with a lock, new, upgraded and mutated providers |
| **Expressions and secrets** | Locals, variable defaults and pure functions are evaluated, so a host or command assembled with `join()`, `format()` or `base64decode()` is found. Secrets (sensitive or secret-named variables, secret-store reads, generated passwords) are followed through locals into HTTP, DNS, `external` and `local-exec`. |
| **Observed behavior** (`sandbox`) | Network attempts, honeytokens leaving, programs run and credential files opened during a real `plan` |
| **Reputation** (`--online`) | Unknown registry versions, fresh releases, missing/renamed/archived/young repositories, low OpenSSF Scorecard |

Every finding records the **phase** it fires in (`init`, `plan`, `apply`, `static`). Anything in `plan` runs before your approval gate.

## How it works

- Parses `.tf`, `.tofu`, `.tf.json` and `.tofu.json` with HashiCorp's own `hcl/v2` parser. The JSON syntax gets the same rules, because it's a classic place to hide things.
- Discovers modules the way Terraform does, from `.terraform/modules/modules.json` (written by both `terraform init` and `tofu init`). A local submodule of a registry module counts as third-party.
- Gives each capability a **fingerprint** (rule, module, address, file, normalized detail) that ignores line numbers and versions. Moving code around doesn't create noise; new behavior does.
- Hashes each module with a portable content hash: sorted paths plus contents, CRLF-normalized so Windows and Linux agree, ignoring `.git` and `.terraform`.
- Reads `.terraform.lock.hcl` for provider checksums, and `.git` metadata that `init` leaves in `.terraform/modules` for the commit a git module resolved to.
- Runs nothing: no Terraform execution, no telemetry, and no network access unless you pass `--online`.

