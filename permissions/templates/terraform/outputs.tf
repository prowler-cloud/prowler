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

output "events_integration_enabled" {
  description = "Whether real-time events integration is enabled"
  value       = var.enable_events_integration
}

output "prowler_events_rule_arn" {
  description = "ARN of the EventBridge rule forwarding events to Prowler Cloud (null if disabled)"
  value       = try(module.events_integration[0].prowler_events_rule_arn, null)
}

output "prowler_events_api_destination_arn" {
  description = "ARN of the EventBridge API Destination targeting Prowler Cloud (null if disabled)"
  value       = try(module.events_integration[0].prowler_events_api_destination_arn, null)
}
