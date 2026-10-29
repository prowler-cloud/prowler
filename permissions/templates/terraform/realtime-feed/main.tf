# Prowler Realtime Detection and Remediation: real-time feed.
#
# EventBridge forwards risky AWS API calls recorded by CloudTrail to an SQS queue, and Prowler Cloud reads the queue with
# the ProwlerScan role. Without it Prowler still works, using CloudTrail LookupEvents with a delay of a few minutes.
# Apply it in each region you want to watch. Global-service events (IAM, S3 account settings) arrive in us-east-1.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.83"
    }
  }
}

locals {
  event_names = [
    "AuthorizeSecurityGroupIngress", "PutBucketPublicAccessBlock", "DeleteBucketPublicAccessBlock",
    "PutAccountPublicAccessBlock", "DeletePublicAccessBlock", "PutBucketPolicy", "StopLogging", "DeleteTrail",
    "UpdateTrail", "StopConfigurationRecorder", "DeleteConfigurationRecorder", "DeleteFlowLogs", "ScheduleKeyDeletion",
    "DisableKey", "DisableEbsEncryptionByDefault", "CreateVolume", "RunInstances", "CreateDBInstance",
    "ModifyDBInstance", "AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy", "CreateAccessKey", "ConsoleLogin",
  ]
}

resource "aws_sqs_queue" "events" {
  name                      = "prowler-realtime-events"
  message_retention_seconds = 3600
  receive_wait_time_seconds = 20
  sqs_managed_sse_enabled   = true
  tags                      = { prowler = "realtime-feed" }
}

resource "aws_cloudwatch_event_rule" "risky_api_calls" {
  name        = "prowler-realtime-risky-api-calls"
  description = "Risky changes that can break compliance checks, forwarded to Prowler Realtime"
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
    detail        = { eventName = local.event_names }
  })
}

resource "aws_cloudwatch_event_target" "queue" {
  rule      = aws_cloudwatch_event_rule.risky_api_calls.name
  target_id = "prowler-realtime-queue"
  arn       = aws_sqs_queue.events.arn
}

data "aws_iam_policy_document" "queue" {
  statement {
    sid       = "AllowEventBridge"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.events.arn]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = [aws_cloudwatch_event_rule.risky_api_calls.arn]
    }
  }
}

resource "aws_sqs_queue_policy" "events" {
  queue_url = aws_sqs_queue.events.id
  policy    = data.aws_iam_policy_document.queue.json
}

resource "aws_iam_role_policy" "read_feed" {
  name = "ProwlerRealtimeFeed"
  role = var.prowler_scan_role_name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "ReadRealtimeQueue"
      Effect   = "Allow"
      Action   = ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
      Resource = aws_sqs_queue.events.arn
    }]
  })
}
