# GitHub Action: tfcap Plan Guard


[![GitHub Marketplace](https://img.shields.io/badge/Marketplace-tfcap%20Plan%20Guard-6f42c1?logo=github)](https://github.com/marketplace/actions/tfcap-plan-guard)

On every pull request, tfcap Plan Guard checks your modules against `tfcap.lock.json` before anything runs `terraform plan`. When something changes, it comments on the PR, adds code-scanning alerts on the `module` block that pulled the change in, and fails the check.

**See it live:** [this demo pull request](https://github.com/r-morato/tfcap-action-demo/pull/1) bumps a module to a version that steals credentials during plan.

## Setup

1. **Lock your modules** (locally, once):
   ```sh
   cd infra                       # your Terraform root module
   terraform init -backend=false
   tfcap lock                     # writes tfcap.lock.json
   git add tfcap.lock.json && git commit -m "Lock Terraform module capabilities"
   ```
2. **Add the workflow** as `.github/workflows/tfcap.yml`:
   ```yaml
   name: tfcap
   on:
     pull_request:
       types: [opened, synchronize, reopened, labeled]
     push:
       branches: [main]
     schedule:
       - cron: "0 6 * * *"     # daily: catches moved tags even when nobody opens a PR
   permissions:
     contents: read
   jobs:
     tfcap:                    # checks every PR, push and the daily run
       if: github.event.action != 'labeled'
       runs-on: ubuntu-latest
       permissions:
         contents: read
         pull-requests: write  # PR comment
         security-events: write # code-scanning alerts
       steps:
         - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
           with:
             persist-credentials: false
         - uses: hashicorp/setup-terraform@dfe3c3f87815947d99a8997f908cb6525fc44e9e # v4.0.1
         - run: terraform init -backend=false -input=false
           working-directory: infra
         - uses: r-morato/tfcap@v0  # pin to a commit SHA in production
           with:
             working-directory: infra

     approve-prepare:          # runs the PR's code, with a read-only token
       if: github.event.action == 'labeled' && github.event.label.name == 'tfcap-approved'
       runs-on: ubuntu-latest
       permissions:
         contents: read
         pull-requests: write
       outputs:
         approved: ${{ steps.tfcap.outputs.approved }}
       steps:
         - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
           with:
             ref: ${{ github.event.pull_request.head.sha }}
             persist-credentials: false
         - uses: hashicorp/setup-terraform@dfe3c3f87815947d99a8997f908cb6525fc44e9e # v4.0.1
         - run: terraform init -backend=false -input=false
           working-directory: infra
         - id: tfcap
           uses: r-morato/tfcap@v0
           with:
             working-directory: infra
             mode: approve-prepare

     approve-commit:           # has write access, never runs the PR's code
       needs: approve-prepare
       if: needs.approve-prepare.outputs.approved == 'true'
       runs-on: ubuntu-latest
       permissions:
         contents: write       # commit the lock file to the PR branch
         pull-requests: write
         statuses: write       # mark the check as passed on that commit
       steps:
         - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
           with:
             ref: ${{ github.head_ref }}
         - uses: r-morato/tfcap@v0
           with:
             working-directory: infra
             mode: approve-commit
   ```
3. **When a PR changes a module**, tfcap comments with what's new and, if it's risky, fails the check. Review it, then either add the **`tfcap-approved`** label (see below) or run `tfcap lock` yourself and push the updated lock file.

If the daily run fails, a module changed behind a version you had locked. GitHub emails the person who last edited the workflow's schedule.

## Approving from the pull request

Reviewing a Dependabot or Renovate bump shouldn't mean checking out the branch and running commands. Instead, read tfcap's comment and, if you're happy, add the `tfcap-approved` label. Two jobs then take over:

1. **`approve-prepare`** (read-only token) checks that whoever added the label has **write access** (others are ignored, with a comment saying why), runs `terraform init` and `tfcap lock` on the PR's code, and hands the new lock file to the next job. `tfcap lock` still **refuses MUTATED modules**: a label can never approve code that changed behind an unchanged version.
2. **`approve-commit`** (write token) never runs the PR's code. It re-checks the approver, checks the lock file was made for the PR's current commit and passes `tfcap validate-lock`, commits **only that file** as `github-actions[bot]` with `Approved-by: @you`, sets a passing `tfcap` status and updates the PR comment.

The split matters because `terraform init` on someone's pull request is untrusted work, and it shouldn't happen while holding a token that can push. If you prefer a single job anyway, `mode: approve` does both halves in one (with `contents: write`).

Works for branches in the same repository, including Dependabot and Renovate PRs. Pull requests from forks can't be approved this way (GitHub gives fork PRs a read-only token); run `tfcap lock` locally instead.

## Protect the lock file

Anyone who can push can edit `tfcap.lock.json` by hand. Make changes to it, and to the workflow, need a security reviewer with a [`CODEOWNERS`](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners) entry plus branch protection:

```
# .github/CODEOWNERS
**/tfcap.lock.json      @your-org/security
**/tfcap.hcl            @your-org/security
.github/workflows/      @your-org/security
```

## Inputs

| Input | Default | Description |
|---|---|---|
| `working-directory` | `.` | Terraform root module, relative to the repository root. Run `terraform init` or `tofu init` there first. |
| `mode` | `verify` | `verify`: compare against `tfcap.lock.json` and report only unreviewed changes. `scan`: report everything (no lock file needed). `approve-prepare` / `approve-commit`: the two halves of approving from a PR label (see above). `approve`: both halves in one job. |
| `approve-label` | `tfcap-approved` | `approve` mode: the label that approves module changes. |
| `status-context` | `tfcap` | `approve` mode: name of the commit status to set. Match your verify job's name if it's a required check. |
| `fail-on` | `high` | Fail the check at or above this severity: `none`, `info`, `low`, `medium`, `high`, `critical`. |
| `min-severity` | `low` | Hide findings below this severity in the comment and alerts. |
| `third-party-only` | `true` | `scan` mode only: ignore capabilities in your own modules. |
| `online` | `false` | Also run the `--online` reputation checks, using `github-token` for GitHub API calls. |
| `comment` | `true` | Post a PR comment, and update the same comment on later pushes. |
| `sarif` | `true` | Upload results to GitHub code scanning (needs `security-events: write`). |
| `version` | *(empty)* | Empty builds tfcap from the Action's own source, so the scanner is pinned with the Action. Or set a release such as `v0.1.2`. |
| `github-token` | `github.token` | Token used for the PR comment, the approve flow and `online` checks. |

Outputs: `exit-code` (`0` ok, `1` policy failure, `2` error) and, for `approve-prepare`, `approved` (`true` when a lock file was handed to `approve-commit`).

Pin this Action, and every other Action, to a commit SHA: the Trivy and KICS Actions were both hit by supply-chain incidents earlier this year. Because tfcap builds from the Action's own source by default, pinning the Action also pins the scanner binary.

