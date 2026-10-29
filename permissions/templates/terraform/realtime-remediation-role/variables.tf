variable "external_id" {
  type        = string
  description = "The External ID Prowler uses to assume this role. Use the same value you enter in Prowler Cloud."

  validation {
    condition     = length(var.external_id) >= 8
    error_message = "external_id must be at least 8 characters."
  }
}

variable "account_id" {
  type        = string
  description = "AWS account ID that assumes the role. If you deploy this to be used in Prowler Cloud, do not edit this."
  default     = "232136659152"

  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be a valid AWS account ID."
  }
}

variable "iam_principal" {
  type        = string
  description = "IAM principal allowed to assume the role. If you deploy this to be used in Prowler Cloud, do not edit this."
  default     = "role/prowler*"
}
