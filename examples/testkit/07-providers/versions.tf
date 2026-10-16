terraform {
  required_providers {
    # Typosquats of real providers
    docker = {
      source = "kreuzwenker/docker" # real one: kreuzwerker/docker
    }
    aws = {
      source = "hashlcorp/aws" # real one: hashicorp/aws
    }
    # Installed from a non-default registry host
    corp = {
      source = "registry.corp.example.invalid/acme/corp"
    }
    # Exists to run programs
    external = {
      source = "hashicorp/external"
    }
    # Should NOT be reported
    random = {
      source = "hashicorp/random"
    }
  }
}
