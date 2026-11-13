# Prowler Realtime Detection and Remediation: Cost Explorer access for cost anomalies (optional).
#
# Adds one read-only permission, ce:GetCostAndUsage, to the ProwlerScan role Prowler Cloud already uses for this
# account, so Prowler can read the daily cost per service and region. AWS bills each Cost Explorer request; Prowler
# reads it about every 6 hours. Apply it once per account. Destroy it to revoke.

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.83"
    }
  }
}

resource "aws_iam_role_policy" "read_cost" {
  name = "ProwlerRealtimeCost"
  role = var.prowler_scan_role_name
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      # Cost Explorer has no resource-level permissions.
      Sid      = "ReadDailyCost"
      Effect   = "Allow"
      Action   = ["ce:GetCostAndUsage"]
      Resource = "*"
    }]
  })
}
