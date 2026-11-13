output "prowler_realtime_rule_arn" {
  description = "ARN of the EventBridge rule forwarding the tracked CloudTrail events to Prowler Cloud"
  value       = aws_cloudwatch_event_rule.prowler_realtime.arn
}

output "prowler_realtime_api_destination_arn" {
  description = "ARN of the EventBridge API destination targeting Prowler Cloud"
  value       = aws_cloudwatch_event_api_destination.prowler_realtime.arn
}

output "prowler_realtime_dlq_url" {
  description = "URL of the dead-letter queue holding the events EventBridge could not deliver"
  value       = aws_sqs_queue.prowler_realtime_dlq.id
}

output "prowler_realtime_dlq_arn" {
  description = "ARN of the dead-letter queue holding the events EventBridge could not deliver"
  value       = aws_sqs_queue.prowler_realtime_dlq.arn
}

output "prowler_realtime_hello_status" {
  description = "Whether the hello event was accepted by EventBridge on apply. Prowler Cloud confirms the connection when the event reaches the endpoint"
  value       = try(jsondecode(aws_lambda_invocation.prowler_realtime_hello.result), null)
}

output "prowler_realtime_invoke_role_arn" {
  description = "ARN of the IAM role assumed by EventBridge to invoke the API destination"
  value       = aws_iam_role.prowler_realtime_invoke.arn
}
