# Expected: no findings at low severity or above.
terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

module "app" {
  source = "./modules/app"
  name   = "demo"
}

module "vpc" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-vpc.git?ref=26f2a4e9c1a6b4cd8b8e1ddbf2e41b2ee4f13a8c"
  name   = "demo"
  cidr   = "10.0.0.0/16"
}
