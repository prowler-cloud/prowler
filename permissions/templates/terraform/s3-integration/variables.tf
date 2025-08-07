variable "s3_integration_bucket_name" {
  type        = string
  description = "The S3 bucket name where Prowler will store scan reports for your cloud providers."

  validation {
    condition     = length(var.s3_integration_bucket_name) > 0
    error_message = "s3_integration_bucket_name must not be empty."
  }
}

variable "s3_integration_bucket_account_id" {
  type        = string
  description = "The AWS Account ID owner of the S3 Bucket."

  validation {
    condition     = length(var.s3_integration_bucket_account_id) == 12 && can(tonumber(var.s3_integration_bucket_account_id))
    error_message = "s3_integration_bucket_account_id must be a valid 12-digit AWS Account ID."
  }
}

variable "prowler_role_name" {
  type        = string
  description = "Name of the Prowler scan IAM role to attach the S3 policy to."

  validation {
    condition     = length(var.prowler_role_name) > 0
    error_message = "prowler_role_name must not be empty."
  }
}
