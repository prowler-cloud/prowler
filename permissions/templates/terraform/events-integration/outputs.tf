output "prowler_events_rule_arn" {
  description = "ARN of the EventBridge rule forwarding events to Prowler Cloud"
  value       = aws_cloudwatch_event_rule.prowler_security_changes.arn
}

output "prowler_events_api_destination_arn" {
  description = "ARN of the EventBridge API Destination targeting Prowler Cloud"
  value       = aws_cloudwatch_event_api_destination.prowler.arn
}

output "prowler_events_invoke_role_arn" {
  description = "ARN of the IAM role assumed by EventBridge to invoke the API Destination"
  value       = aws_iam_role.prowler_events_invoke.arn
}
