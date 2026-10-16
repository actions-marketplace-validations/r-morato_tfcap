# tfcap real-world lab: a compromised module

You're about to run Terraform. Your project uses a third-party module, pinned to a version tag, the way most teams do. Overnight, the module maintainer's account is compromised and the attacker swaps the code behind that tag.

This lab recreates that on your machine with a real `terraform init`, then shows what tfcap catches before `terraform plan` runs.

**Safe by design.** Everything stays inside `./lab`, no cloud credentials are used, and the "malicious" code is defused: during plan it only writes a text file, `PWNED-during-plan.txt`, to prove it ran. The credential-stealing lines come after `exit 0` and never execute. Read `attack.sh` first if you like; it's short.

Needs: `git`, `tfcap`, and `terraform` or `tofu` (use `tofu` wherever this says `terraform`).

## 1. A normal day

```sh
./setup.sh                  # run from examples/realworld-lab
cd lab/infra
cat main.tf                 # module "network" pinned to ?ref=v1.0.0
terraform init              # downloads the module
tfcap lock                  # records the module's content hash + what it can do
terraform plan              # fine
ls                          # no PWNED file
```

## 2. The maintainer gets compromised

```sh
cd ../..
./attack.sh                 # attacker moves tag v1.0.0 to new code
cd lab/infra
rm -rf .terraform && terraform init    # what every fresh CI runner does
```

Terraform downloads the new code **without a single warning**. The version didn't change, and `.terraform.lock.hcl` has no entry for modules at all.

## 3. Run tfcap before you plan

```sh
tfcap verify
echo $?                     # 1: in CI, the pipeline stops here
```

You should see `MUTATED module.network`, plus what the new code does: runs a script during plan, reads `~/.aws`, dumps env vars, posts them to a host.

## 4. Optional: see what you just avoided

```sh
terraform plan
cat PWNED-during-plan.txt
```

The module's code ran during **plan**, before any approval step. Here it only wrote a note. In a real attack, that's where your credentials leave.

## Variant: a malicious "patch release"

Instead of moving a tag, the attacker publishes `v1.0.1`, and your dependency bot bumps it:

```sh
./reset.sh && ./setup.sh
cd lab/infra && terraform init && tfcap lock && cd ../..
./attack.sh release
cd lab/infra
sed -i '' 's/ref=v1.0.0/ref=v1.0.1/' main.tf    # on Linux: sed -i 's/…/…/' main.tf
terraform init -upgrade
tfcap verify                # "upgraded ref=v1.0.0 → ref=v1.0.1" + only the NEW capabilities
```

## Clean up

```sh
./reset.sh                  # deletes ./lab, nothing else
```
