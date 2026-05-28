# EventBridge Connection (stores the API key in Secrets Manager under the hood)
###################################
resource "aws_cloudwatch_event_connection" "prowler" {
  name               = "ProwlerEventsConnection"
  authorization_type = "API_KEY"

  auth_parameters {
    api_key {
      key   = "x-api-key"
      value = var.prowler_api_key
    }
  }
}

# EventBridge API Destination (the HTTPS target)
###################################
resource "aws_cloudwatch_event_api_destination" "prowler" {
  name                = "ProwlerEventsApiDestination"
  invocation_endpoint = var.prowler_webhook_url
  http_method         = "POST"
  connection_arn      = aws_cloudwatch_event_connection.prowler.arn
}

# IAM Role assumed by EventBridge to call the API Destination
###################################
data "aws_iam_policy_document" "events_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "prowler_events_invoke" {
  name               = "ProwlerEventsInvoke"
  assume_role_policy = data.aws_iam_policy_document.events_assume_role.json
}

resource "aws_iam_role_policy" "prowler_events_invoke" {
  name = "InvokeApiDestination"
  role = aws_iam_role.prowler_events_invoke.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "events:InvokeApiDestination"
      Resource = aws_cloudwatch_event_api_destination.prowler.arn
    }]
  })
}

# Rule: forward selected CloudTrail management events to Prowler Cloud
###################################
resource "aws_cloudwatch_event_rule" "prowler_security_changes" {
  name        = "ProwlerSecurityChanges"
  description = "Forwards CloudTrail management events (SG, IAM, S3, CloudTrail, KMS, RDS, Lambda) to Prowler Cloud."
  state       = "ENABLED"

  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = [
        "ec2.amazonaws.com",
        "iam.amazonaws.com",
        "s3.amazonaws.com",
        "s3control.amazonaws.com",
        "cloudtrail.amazonaws.com",
        "kms.amazonaws.com",
        "rds.amazonaws.com",
        "lambda.amazonaws.com",
      ]
      eventName = [
        # EC2 / Security Groups
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress",
        "RevokeSecurityGroupEgress",
        "CreateSecurityGroup",
        "DeleteSecurityGroup",
        "ModifySecurityGroupRules",
        "ModifySnapshotAttribute",
        "ModifyImageAttribute",
        # IAM
        "AttachRolePolicy",
        "DetachRolePolicy",
        "PutRolePolicy",
        "DeleteRolePolicy",
        "AttachUserPolicy",
        "DetachUserPolicy",
        "PutUserPolicy",
        "DeleteUserPolicy",
        "AttachGroupPolicy",
        "DetachGroupPolicy",
        "PutGroupPolicy",
        "DeleteGroupPolicy",
        "CreatePolicy",
        "CreatePolicyVersion",
        "DeletePolicy",
        "UpdateAssumeRolePolicy",
        "CreateRole",
        "DeleteRole",
        "CreateUser",
        "DeleteUser",
        "CreateAccessKey",
        "DeleteAccessKey",
        "CreateLoginProfile",
        "UpdateLoginProfile",
        "DeleteLoginProfile",
        "DeactivateMFADevice",
        "EnableMFADevice",
        "UpdateAccountPasswordPolicy",
        "DeleteAccountPasswordPolicy",
        # S3 (bucket-level + account-level via s3control)
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketEncryption",
        "DeleteBucketEncryption",
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock",
        "PutBucketAcl",
        "PutBucketVersioning",
        "PutBucketLogging",
        "CreateBucket",
        "DeleteBucket",
        "PutPublicAccessBlock",
        "DeletePublicAccessBlock",
        # CloudTrail tampering
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
        "PutEventSelectors",
        # KMS
        "DisableKey",
        "ScheduleKeyDeletion",
        "CancelKeyDeletion",
        "PutKeyPolicy",
        "CreateGrant",
        # RDS
        "ModifyDBInstance",
        "ModifyDBCluster",
        "CreateDBInstance",
        "DeleteDBInstance",
        "DeleteDBCluster",
        "AuthorizeDBSecurityGroupIngress",
        "ModifyDBSnapshotAttribute",
        # Lambda
        "AddPermission",
        "RemovePermission",
        "CreateFunctionUrlConfig",
        "UpdateFunctionUrlConfig",
        "DeleteFunctionUrlConfig",
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "to_prowler" {
  rule     = aws_cloudwatch_event_rule.prowler_security_changes.name
  arn      = aws_cloudwatch_event_api_destination.prowler.arn
  role_arn = aws_iam_role.prowler_events_invoke.arn
}
