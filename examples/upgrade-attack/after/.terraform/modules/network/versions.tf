terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
    # "docker" support for the new VPC endpoint test harness
    docker = {
      source  = "kreuzwenker/docker"
      version = ">= 3.0"
    }
  }
}
