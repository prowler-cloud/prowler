# Prowler Realtime Detection and Remediation: remediation-only IAM role (optional).
#
# Lets Prowler fix a small, fixed set of misconfigurations automatically (and undo them). It is separate from the
# read-only ProwlerScan role: without it Prowler can only alert and propose pull requests. Every action is one a listed
# fix or its undo needs; the resource comes from the event, so most statements cannot name it in advance. Destroy the
# stack to revoke.
#
# If you deploy this to be used in Prowler Cloud, do not edit account_id and iam_principal.
#
# What Prowler can do at runtime through this role, and nothing else:
#   - Close internet-open ports (22, 3389, all) on the security group named in an event, revoking only 0.0.0.0/0 and ::/0 rules (undo recorded)
#   - Turn on the four public access block settings of the S3 bucket named in an event (undo recorded)
#   - Turn on the account-wide S3 public access block (undo recorded; can affect buckets that are public on purpose)
#   - Start CloudTrail logging again on trails that were stopped (not revertible)
#   - Enable EBS encryption by default in the region; existing volumes are not changed (undo recorded)
#   - Set PubliclyAccessible to false on the RDS database named in an event (undo recorded)

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.83"
    }
  }
}

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${var.account_id}:root"]
    }
    condition {
      test     = "StringEquals"
      variable = "sts:ExternalId"
      values   = [var.external_id]
    }
    condition {
      test     = "StringLike"
      variable = "aws:PrincipalArn"
      values   = ["arn:${data.aws_partition.current.partition}:iam::${var.account_id}:${var.iam_principal}"]
    }
  }
}

data "aws_iam_policy_document" "fixes" {
  statement {
    sid       = "SecurityGroupIngress"
    actions   = ["ec2:DescribeSecurityGroups", "ec2:RevokeSecurityGroupIngress", "ec2:AuthorizeSecurityGroupIngress"]
    resources = ["*"]
  }
  statement {
    sid       = "EbsDefaultEncryption"
    actions   = ["ec2:GetEbsEncryptionByDefault", "ec2:EnableEbsEncryptionByDefault", "ec2:DisableEbsEncryptionByDefault"]
    resources = ["*"]
  }
  statement {
    sid       = "BucketPublicAccessBlock"
    actions   = ["s3:GetBucketPublicAccessBlock", "s3:PutBucketPublicAccessBlock"]
    resources = ["arn:${data.aws_partition.current.partition}:s3:::*"]
  }
  statement {
    sid       = "AccountPublicAccessBlock"
    actions   = ["s3:GetAccountPublicAccessBlock", "s3:PutAccountPublicAccessBlock"]
    resources = ["*"]
  }
  statement {
    sid       = "CloudTrailLogging"
    actions   = ["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:StartLogging"]
    resources = ["*"]
  }
  statement {
    sid       = "RdsPrivate"
    actions   = ["rds:DescribeDBInstances", "rds:ModifyDBInstance"]
    resources = ["arn:${data.aws_partition.current.partition}:rds:*:${data.aws_caller_identity.current.account_id}:db:*"]
  }
  statement {
    sid       = "WhoAmI"
    actions   = ["sts:GetCallerIdentity"]
    resources = ["*"]
  }
}

resource "aws_iam_role" "prowler_remediation" {
  name                 = "ProwlerRemediation"
  max_session_duration = 3600
  assume_role_policy   = data.aws_iam_policy_document.assume_role.json
}

resource "aws_iam_role_policy" "fixes" {
  name   = "ProwlerRealtimeFixes"
  role   = aws_iam_role.prowler_remediation.id
  policy = data.aws_iam_policy_document.fixes.json
}
