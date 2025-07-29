# Local validation for conditional requirements
###################################
locals {
  s3_integration_validation = (
    !var.enable_s3_integration ||
    (var.enable_s3_integration && var.s3_integration_bucket_name != "" && var.s3_integration_bucket_account != "")
  )
}

# Validation check using check block (Terraform 1.5+)
check "s3_integration_requirements" {
  assert {
    condition     = !var.enable_s3_integration || (var.s3_integration_bucket_name != "" && var.s3_integration_bucket_account != "")
    error_message = "When enable_s3_integration is true, both s3_integration_bucket_name and s3_integration_bucket_account must be provided and non-empty."
  }
}

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

# S3 Integration Module
###################################
module "s3_integration" {
  count = var.enable_s3_integration ? 1 : 0

  source = "./s3-integration"

  s3_integration_bucket_name    = var.s3_integration_bucket_name
  s3_integration_bucket_account = var.s3_integration_bucket_account

  prowler_role_name = aws_iam_role.prowler_scan.name
}
