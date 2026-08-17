# EventBridge Connection holding the Prowler Cloud API key
###################################
resource "aws_cloudwatch_event_connection" "prowler_realtime" {
  name               = "ProwlerRealtimeDetection"
  description        = "Holds the Prowler Cloud API key used to authenticate forwarded events"
  authorization_type = "API_KEY"

  auth_parameters {
    api_key {
      key   = "x-api-key"
      value = var.prowler_api_key
    }
  }
}

# EventBridge API Destination pointing at the Prowler Cloud endpoint
###################################
resource "aws_cloudwatch_event_api_destination" "prowler_realtime" {
  name                = "ProwlerRealtimeDetection"
  description         = "Prowler Cloud endpoint that receives the forwarded CloudTrail events"
  invocation_endpoint = var.prowler_webhook_url
  http_method         = "POST"
  connection_arn      = aws_cloudwatch_event_connection.prowler_realtime.arn
}

# IAM Role assumed by EventBridge to invoke the API Destination
###################################
data "aws_iam_policy_document" "prowler_realtime_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }

    # Built from the rule name to avoid a circular dependency with the rule
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:rule/ProwlerRealtimeDetection"]
    }
  }
}

resource "aws_iam_role" "prowler_realtime_invoke" {
  name               = "ProwlerRealtimeInvoke"
  assume_role_policy = data.aws_iam_policy_document.prowler_realtime_assume_role.json
}

resource "aws_iam_role_policy" "prowler_realtime_invoke" {
  name = "InvokeApiDestination"
  role = aws_iam_role.prowler_realtime_invoke.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "events:InvokeApiDestination"
      Resource = aws_cloudwatch_event_api_destination.prowler_realtime.arn
    }]
  })
}

# Rule matching the CloudTrail management events tracked by Prowler real-time detection
###################################
resource "aws_cloudwatch_event_rule" "prowler_realtime" {
  name        = "ProwlerRealtimeDetection"
  description = "Forwards the CloudTrail management events tracked by Prowler real-time detection to Prowler Cloud"
  state       = "ENABLED"

  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = [
        "ec2.amazonaws.com",
        "rds.amazonaws.com",
        "iam.amazonaws.com",
        "s3.amazonaws.com",
        "s3-control.amazonaws.com",
        "cloudtrail.amazonaws.com",
        "config.amazonaws.com",
        "guardduty.amazonaws.com",
      ]
      eventName = [
        # Security group opened to 0.0.0.0/0
        "AuthorizeSecurityGroupIngress",
        "ModifySecurityGroupRules",
        # RDS instance made publicly accessible
        "CreateDBInstance",
        "ModifyDBInstance",
        # Administrator privileges attached to a principal
        "AttachUserPolicy",
        "AttachRolePolicy",
        "AttachGroupPolicy",
        "PutUserPolicy",
        "PutRolePolicy",
        # S3 bucket policy or ACL grants public access
        "PutBucketPolicy",
        "PutBucketAcl",
        # S3 Block Public Access weakened
        "PutAccountPublicAccessBlock",
        "DeleteAccountPublicAccessBlock",
        "PutBucketPublicAccessBlock",
        "DeleteBucketPublicAccessBlock",
        # CloudTrail logging stopped or trail deleted
        "StopLogging",
        "DeleteTrail",
        "UpdateTrail",
        # AWS Config recorder stopped or deleted
        "StopConfigurationRecorder",
        "DeleteConfigurationRecorder",
        # GuardDuty detector disabled or deleted
        "UpdateDetector",
        "DeleteDetector",
      ]
    }
  })
}

resource "aws_cloudwatch_event_target" "prowler_realtime" {
  rule      = aws_cloudwatch_event_rule.prowler_realtime.name
  target_id = "ProwlerCloud"
  arn       = aws_cloudwatch_event_api_destination.prowler_realtime.arn
  role_arn  = aws_iam_role.prowler_realtime_invoke.arn
}
