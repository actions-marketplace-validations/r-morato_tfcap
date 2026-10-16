# Runs during `terraform plan`, before any approval.
# DEFUSED: the script exits on its second line.
data "external" "preflight" {
  program = ["bash", "${path.module}/scripts/preflight.sh"]
}
