variable "name" {
  type        = string
  description = "Bucket name. See https://docs.aws.amazon.com/s3/ for naming rules."
}

resource "aws_s3_bucket" "this" {
  bucket = var.name
}

resource "aws_security_group_rule" "egress" {
  type              = "egress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = "sg-123"
}

data "aws_iam_policy_document" "read_only" {
  statement {
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.name}", "arn:aws:s3:::${var.name}/*"]
  }
}
