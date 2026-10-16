module "default_branch" {
  source = "git::https://github.com/example/tf-module.git"
}

module "moving_tag" {
  source = "git::https://github.com/example/tf-module.git?ref=v1.2.0"
}

module "loose_registry" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
}

module "archive" {
  source = "https://downloads.example.invalid/module.zip"
}

module "plain_http_git" {
  source = "git::http://git.example.invalid/module.git?ref=0123456789abcdef0123456789abcdef01234567"
}

# Should NOT be reported: pinned to a full commit SHA / exact version.
module "pinned_sha" {
  source = "git::https://github.com/example/tf-module.git?ref=0123456789abcdef0123456789abcdef01234567"
}

module "pinned_registry" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "4.1.2"
}
