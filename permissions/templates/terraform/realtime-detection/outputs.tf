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

output "prowler_realtime_invoke_role_arn" {
  description = "ARN of the IAM role assumed by EventBridge to invoke the API destination"
  value       = aws_iam_role.prowler_realtime_invoke.arn
}
