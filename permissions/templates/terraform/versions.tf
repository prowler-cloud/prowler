# Terraform Provider Configuration
###################################
terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.83"
    }
  }
}

provider "aws" {
  region = "us-east-1"
  default_tags {
    tags = {
      "Name"      = "ProwlerScan",
      "Terraform" = "true",
      "Service"   = "https://prowler.com",
      "Support"   = "support@prowler.com"
    }
  }
}
