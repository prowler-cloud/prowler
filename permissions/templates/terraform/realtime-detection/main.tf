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

    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values = [
        aws_cloudwatch_event_rule.prowler_realtime.arn,
        aws_cloudwatch_event_rule.prowler_realtime_hello.arn,
      ]
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

# Dead-letter queue for the events EventBridge could not deliver
###################################
resource "aws_sqs_queue" "prowler_realtime_dlq" {
  name                      = "ProwlerRealtimeDetectionDLQ"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

# EventBridge writes to the DLQ as a service, not through the invoke role, so it needs a queue policy
data "aws_iam_policy_document" "prowler_realtime_dlq" {
  statement {
    sid       = "AllowEventBridgeDeadLetterDelivery"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.prowler_realtime_dlq.arn]

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values = [
        aws_cloudwatch_event_rule.prowler_realtime.arn,
        aws_cloudwatch_event_rule.prowler_realtime_hello.arn,
      ]
    }
  }
}

resource "aws_sqs_queue_policy" "prowler_realtime_dlq" {
  queue_url = aws_sqs_queue.prowler_realtime_dlq.id
  policy    = data.aws_iam_policy_document.prowler_realtime_dlq.json
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

  # Retries cover an endpoint outage; whatever outlives the window is dead-lettered
  retry_policy {
    maximum_event_age_in_seconds = 86400
    maximum_retry_attempts       = 185
  }

  dead_letter_config {
    arn = aws_sqs_queue.prowler_realtime_dlq.arn
  }
}

# Rule carrying the synthetic hello event, which no CloudTrail pattern would match
###################################
resource "aws_cloudwatch_event_rule" "prowler_realtime_hello" {
  name        = "ProwlerRealtimeDetectionHello"
  description = "Forwards the Prowler real-time detection hello event used to verify the connection"
  state       = "ENABLED"

  event_pattern = jsonencode({
    source        = ["prowler.simulation"]
    "detail-type" = ["test_connection"]
  })
}

resource "aws_cloudwatch_event_target" "prowler_realtime_hello" {
  rule      = aws_cloudwatch_event_rule.prowler_realtime_hello.name
  target_id = "ProwlerCloud"
  arn       = aws_cloudwatch_event_api_destination.prowler_realtime.arn
  role_arn  = aws_iam_role.prowler_realtime_invoke.arn

  retry_policy {
    maximum_event_age_in_seconds = 86400
    maximum_retry_attempts       = 185
  }

  dead_letter_config {
    arn = aws_sqs_queue.prowler_realtime_dlq.arn
  }
}

# Hello event emitter, the same function the CloudFormation template runs, so both
# onboarding paths leave the same footprint in the account
###################################
data "archive_file" "prowler_realtime_hello" {
  type        = "zip"
  source_file = "${path.module}/hello.py"
  output_path = "${path.module}/hello.zip"
}

# Declared explicitly so the function does not leave a log group with unlimited retention behind
resource "aws_cloudwatch_log_group" "prowler_realtime_hello" {
  name              = "/aws/lambda/ProwlerRealtimeHello"
  retention_in_days = 30
}

data "aws_iam_policy_document" "prowler_realtime_hello_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "prowler_realtime_hello" {
  name               = "ProwlerRealtimeHello"
  assume_role_policy = data.aws_iam_policy_document.prowler_realtime_hello_assume_role.json
}

resource "aws_iam_role_policy" "prowler_realtime_hello" {
  name = "PutHelloEvent"
  role = aws_iam_role.prowler_realtime_hello.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "events:PutEvents"
        Resource = "arn:${data.aws_partition.current.partition}:events:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:event-bus/default"
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.prowler_realtime_hello.arn}:*"
      },
    ]
  })
}

resource "aws_lambda_function" "prowler_realtime_hello" {
  function_name    = "ProwlerRealtimeHello"
  description      = "Emits the Prowler real-time detection hello event"
  role             = aws_iam_role.prowler_realtime_hello.arn
  runtime          = "python3.13"
  handler          = "hello.handler"
  timeout          = 30
  filename         = data.archive_file.prowler_realtime_hello.output_path
  source_code_hash = data.archive_file.prowler_realtime_hello.output_base64sha256

  depends_on = [aws_cloudwatch_log_group.prowler_realtime_hello]
}

# Emitting the event is the last step: the rule, the target and every policy it
# depends on must already exist, and none of them is referenced here
resource "aws_lambda_invocation" "prowler_realtime_hello" {
  function_name = aws_lambda_function.prowler_realtime_hello.function_name
  input         = "{}"

  # Re-emits the event when the endpoint changes, like the CloudFormation custom resource
  triggers = {
    webhook_url = var.prowler_webhook_url
  }

  depends_on = [
    aws_cloudwatch_event_target.prowler_realtime_hello,
    aws_iam_role_policy.prowler_realtime_hello,
    aws_iam_role_policy.prowler_realtime_invoke,
    aws_sqs_queue_policy.prowler_realtime_dlq,
  ]
}
