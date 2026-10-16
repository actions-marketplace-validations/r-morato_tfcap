#!/bin/sh
# Builds the lab in ./lab next to this script:
#   lab/upstream/terraform-acme-network  a git repo playing the third-party module (tag v1.0.0)
#   lab/infra                            your Terraform project, using that module at ?ref=v1.0.0
# Touches nothing outside ./lab. Needs git, plus terraform or tofu.
set -e
cd "$(dirname "$0")"
LAB="$(pwd)/lab"
if [ -e "$LAB" ]; then echo "lab/ already exists. Run ./reset.sh first."; exit 1; fi
command -v git >/dev/null || { echo "git is required"; exit 1; }
if ! command -v terraform >/dev/null && ! command -v tofu >/dev/null; then
  echo "Note: neither terraform nor tofu found. Install one before the walkthrough (e.g. brew install opentofu)."
fi

UP="$LAB/upstream/terraform-acme-network"
mkdir -p "$UP" "$LAB/infra"

# ---- the third-party module, version 1.0.0 (benign) ----
cd "$UP"
git init -q -b main
git config user.name "acme-oss maintainer"
git config user.email "maintainer@example.invalid"
cat > main.tf <<'EOF'
variable "name" {
  type        = string
  description = "Network name"
}

variable "cidr" {
  type    = string
  default = "10.0.0.0/16"
}

# Stand-in for real VPC resources, so plan needs no cloud credentials.
resource "terraform_data" "vpc" {
  input = {
    name = var.name
    cidr = var.cidr
  }
}

output "vpc" {
  value = terraform_data.vpc.output
}
EOF
cat > README.md <<'EOF'
# terraform-acme-network
A tiny, well-behaved network module.
EOF
git add -A && git commit -qm "Initial release" && git tag v1.0.0

# ---- your project ----
cd "$LAB/infra"
cat > main.tf <<EOF
terraform {
  required_version = ">= 1.5"
}

module "network" {
  source = "git::file://$UP?ref=v1.0.0"
  name   = "prod"
}

output "network" {
  value = module.network.vpc
}
EOF

echo "Lab ready."
echo
echo "Next:"
echo "  cd lab/infra"
echo "  terraform init        (or: tofu init)"
echo "  tfcap lock"
echo "  terraform plan"
