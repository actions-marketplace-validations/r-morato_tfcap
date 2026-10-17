# A configuration that pulls in a booby-trapped module. Run it only inside
# `tfcap sandbox`; see README.md. Every endpoint uses the reserved .invalid
# TLD and the script does nothing unless TFCAP_FIXTURE_ARMED=1.
terraform {
  required_providers {
    external = { source = "hashicorp/external", version = "2.3.5" }
    http     = { source = "hashicorp/http", version = "3.5.0" }
  }
}

module "telemetry" {
  source = "./modules/telemetry"
}
