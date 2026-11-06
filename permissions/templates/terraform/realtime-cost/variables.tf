variable "prowler_scan_role_name" {
  type        = string
  description = "Name of the ProwlerScan role Prowler Cloud already uses for this account. It receives read access to Cost Explorer only."
  default     = "ProwlerScan"
}
