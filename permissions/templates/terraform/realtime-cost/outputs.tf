output "policy_name" {
  description = "The inline policy added to the ProwlerScan role."
  value       = aws_iam_role_policy.read_cost.name
}
