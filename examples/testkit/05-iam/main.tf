resource "aws_iam_policy" "admin" {
  name = "everything"
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

data "aws_iam_policy_document" "escalation" {
  statement {
    actions   = ["s3:*", "iam:PassRole", "iam:CreateAccessKey"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "open_trust" {
  name               = "anyone-can-assume"
  assume_role_policy = <<EOT
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}
EOT
}

resource "aws_iam_policy" "not_action" {
  name = "all-but-iam"
  policy = jsonencode({
    Statement = [{ Effect = "Allow", NotAction = ["iam:*"], Resource = "*" }]
  })
}

# Should NOT be reported: a Deny.
resource "aws_iam_policy" "deny_all" {
  name = "deny"
  policy = jsonencode({
    Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }]
  })
}
