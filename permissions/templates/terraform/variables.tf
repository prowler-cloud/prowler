# Variables
###################################
variable "external_id" {
  type        = string
  description = "This is the External ID that Prowler will use to assume the role ProwlerScan IAM Role."

  validation {
    condition     = length(var.external_id) > 0
    error_message = "ExternalId must not be empty."
  }
}

variable "account_id" {
  type        = string
  description = "AWS Account ID that will assume the role created, if you are deploying this template to be used in Prowler Cloud please do not edit this."
  default     = "232136659152"

  validation {
    condition     = length(var.account_id) == 12
    error_message = "AccountId must be a valid AWS Account ID."
  }
}

variable "iam_principal" {
  type        = string
  description = "The IAM principal type and name that will be allowed to assume the role created, leave an * for all the IAM principals in your AWS account. If you are deploying this template to be used in Prowler Cloud please do not edit this."
  default     = "role/prowler*"
}

variable "enable_organizations" {
  type        = bool
  description = "Enable AWS Organizations discovery permissions. Set to true only when deploying this role in the management account."
  default     = false
}

variable "enable_s3_integration" {
  type        = bool
  description = "Enable S3 integration for storing Prowler scan reports."
  default     = false
}

variable "s3_integration_bucket_name" {
  type        = string
  description = "The S3 bucket name where Prowler will store scan reports for your cloud providers. Required if enable_s3_integration is true."
  default     = ""

  validation {
    condition     = length(var.s3_integration_bucket_name) > 0 || var.s3_integration_bucket_name == ""
    error_message = "s3_integration_bucket_name must be a valid S3 bucket name."
  }
}

variable "s3_integration_bucket_account_id" {
  type        = string
  description = "The AWS Account ID owner of the S3 Bucket. Required if enable_s3_integration is true."
  default     = ""

  validation {
    condition     = var.s3_integration_bucket_account_id == "" || (length(var.s3_integration_bucket_account_id) == 12 && can(tonumber(var.s3_integration_bucket_account_id)))
    error_message = "s3_integration_bucket_account_id must be a valid 12-digit AWS Account ID or empty."
  }
}
