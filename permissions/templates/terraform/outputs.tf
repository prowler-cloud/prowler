# Outputs
###################################
output "prowler_role_arn" {
  description = "ARN of the Prowler scan role"
  value       = aws_iam_role.prowler_scan.arn
}

output "prowler_role_name" {
  description = "Name of the Prowler scan role"
  value       = aws_iam_role.prowler_scan.name
}

output "external_id" {
  description = "External ID used for role assumption"
  value       = var.external_id
  sensitive   = true
}

output "s3_integration_enabled" {
  description = "Whether S3 integration is enabled"
  value       = var.enable_s3_integration
}

output "realtime_detection_enabled" {
  description = "Whether real-time detection is enabled"
  value       = var.enable_realtime_detection
}

output "prowler_realtime_rule_arn" {
  description = "ARN of the EventBridge rule forwarding the tracked CloudTrail events to Prowler Cloud (null if real-time detection is disabled)"
  value       = try(module.realtime_detection[0].prowler_realtime_rule_arn, null)
}

output "prowler_realtime_api_destination_arn" {
  description = "ARN of the EventBridge API destination targeting Prowler Cloud (null if real-time detection is disabled)"
  value       = try(module.realtime_detection[0].prowler_realtime_api_destination_arn, null)
}

output "prowler_realtime_dlq_url" {
  description = "URL of the dead-letter queue holding the events EventBridge could not deliver (null if real-time detection is disabled)"
  value       = try(module.realtime_detection[0].prowler_realtime_dlq_url, null)
}

output "prowler_realtime_hello_status" {
  description = "Result of the hello event emitted on apply (null if real-time detection is disabled)"
  value       = try(module.realtime_detection[0].prowler_realtime_hello_status, null)
}
