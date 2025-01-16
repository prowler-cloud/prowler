# Variables
###################################
variable "external_id" {
  type        = string
  description = "IAM Role External ID - Please input your External ID here below"
}

variable "account_id" {
  type        = string
  description = "AWS Account ID that will assume the role created, if you are deploying this template to be used in Prowler Cloud please use the default AWS Account ID"
  default     = "232136659152"
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
        "arn:${data.aws_partition.current.partition}:iam::${var.account_id}:role/prowler*",
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
