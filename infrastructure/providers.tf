terraform {
    required_version = ">= 1.15.0"

    required_providers {
      aws = {
        source = "hashicorp/aws"
        version = "~> 6.0"
      }

      tls = {
        source = "hashicorp/tls"
        version = "~>4.0"
      }

      github = {
        source = "integrations/github"
        version = "~>6.0"
      }
    }
  
}

provider "aws" {
    region = "us-east-1"
}

data "aws_caller_identity" "current" {}

resource "random_string" "suffix" {
  length = 6
  special = false 
  upper = false
}

data "external" "github_token" {
  program = ["sh", "-c", "echo \"{\\\"token\\\":\\\"$(gh auth token)\\\"}\""]
}
provider "github" {
  owner = "GreatOne33"
  token = data.external.github_token.result.token
}
