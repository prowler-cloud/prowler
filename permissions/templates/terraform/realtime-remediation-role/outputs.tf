output "role_arn" {
  description = "Paste this ARN in Prowler Cloud, Realtime, Credentials for remediation only."
  value       = aws_iam_role.prowler_remediation.arn
}
