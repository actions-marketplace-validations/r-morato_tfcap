# tfcap test kit

Ten small Terraform configurations for trying out tfcap. Each folder is one scenario.

**Everything is defused.** Nothing here can do harm, even if someone runs `terraform plan` or `apply` on it by mistake:
- every shell command starts with `true ||` or exits on its first line, so the risky part never runs;
- every URL uses the reserved `.invalid` domain (RFC 2606), which can never resolve.

tfcap only reads the files; it never runs them.

## Run everything

```sh
./run-all.sh
```

It scans each scenario, checks the findings against that folder's `expect.txt`, and prints PASS/FAIL. Scenario 10 is copied to a temp folder first, so the kit itself is never modified.

## Or try them one by one

| Folder | What it shows | Try |
|---|---|---|
| `01-clean` | Normal code: local module, pinned git module, scoped IAM. Should be quiet. | `tfcap scan 01-clean --min-severity low` |
| `02-plan-time-exec` | `data "external"` runs a script during **plan**; the script reads `~/.aws` and env vars | `tfcap scan 02-plan-time-exec` |
| `03-plan-time-http` | `data "http"` POSTs a secret variable during **plan** (critical) vs a plain GET (high) | `tfcap scan 03-plan-time-http` |
| `04-provisioners` | `curl \| bash`, env dump, uploading `~/.ssh/id_rsa`, remote-exec | `tfcap scan 04-provisioners` |
| `05-iam` | Admin `*:*`, `s3:*`, PassRole, trust-anyone role, NotAction; a Deny that must be ignored | `tfcap scan 05-iam` |
| `06-module-sources` | Unpinned git, moving tag, loose registry version, zip URL, plain HTTP; pinned ones stay quiet | `tfcap scan 06-module-sources` |
| `07-providers` | Typosquats `kreuzwenker/docker` and `hashlcorp/aws`, custom registry host, exec-capable provider | `tfcap scan 07-providers` |
| `08-obfuscation` | Base64 blob, `base64decode("…")`, and an exec hidden in a `.tf.json` file | `tfcap scan 08-obfuscation` |
| `09-upgrade` | A module "upgrade" that adds credential theft | `tfcap diff 09-upgrade/before 09-upgrade/after` |
| `10-tag-mutation` | Same version, different code: what a moved git tag looks like | see below |

### Tag mutation walkthrough

```sh
cp -R 10-tag-mutation /tmp/tagtest && cd /tmp/tagtest
tfcap lock                 # record the module's hash and capabilities
tfcap verify               # ok
./simulate-tag-move.sh     # "attacker" moves the v2.1.0 tag
tfcap verify               # MUTATED, exit 1
```

### Other formats to try

```sh
tfcap scan 04-provisioners --format json
tfcap diff 09-upgrade/before 09-upgrade/after --format markdown   # what the PR comment looks like
tfcap scan 05-iam --format sarif                                  # for GitHub code scanning
```
