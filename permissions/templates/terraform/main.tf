# Variables
###################################
variable "external_id" {
  type        = string
  description = "This is the External ID that Prowler will use to assume the role ProwlerScan IAM Role."
}

variable "account_id" {
  type        = string
  description = "AWS Account ID that will assume the role created, if you are deploying this template to be used in Prowler Cloud please do not edit this."
  default     = "232136659152"
}

variable "iam_principal" {
  type        = string
  description = "The IAM principal type and name that will be allowed to assume the role created, leave an * for all the IAM principals in your AWS account. If you are deploying this template to be used in Prowler Cloud please do not edit this."
  default     = "role/prowler*"
}

##### PLEASE, DO NOT EDIT BELOW THIS LINE #####


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

data "aws_partition" "current" {}


# IAM Role
###################################
data "aws_iam_policy_document" "prowler_assume_role_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${var.account_id}:root"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values = [
        var.external_id,
      ]
    }
    condition {
      test     = "StringLike"
      variable = "aws:PrincipalArn"
      values = [
        "arn:${data.aws_partition.current.partition}:iam::${var.account_id}:${var.iam_principal}",
      ]
    }
  }
}

resource "aws_iam_role" "prowler_scan" {
  name               = "ProwlerScan"
  assume_role_policy = data.aws_iam_policy_document.prowler_assume_role_policy.json

}

resource "aws_iam_policy" "prowler_scan_policy" {
  name        = "ProwlerScan"
  description = "Prowler Scan Policy"
  policy      = file("../../prowler-additions-policy.json")
}

resource "aws_iam_role_policy_attachment" "prowler_scan_policy_attachment" {
  role       = aws_iam_role.prowler_scan.name
  policy_arn = aws_iam_policy.prowler_scan_policy.arn
}

resource "aws_iam_role_policy_attachment" "prowler_scan_securityaudit_policy_attachment" {
  role       = aws_iam_role.prowler_scan.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/SecurityAudit"
}

resource "aws_iam_role_policy_attachment" "prowler_scan_viewonly_policy_attachment" {
  role       = aws_iam_role.prowler_scan.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/job-function/ViewOnlyAccess"
}
