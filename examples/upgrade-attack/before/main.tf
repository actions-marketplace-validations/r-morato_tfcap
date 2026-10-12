terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-west-2"
}

module "network" {
  source  = "acme-oss/network/aws"
  version = "1.4.0"

  name = "prod"
  cidr = "10.0.0.0/16"
}
