variable "prowler_webhook_url" {
  type        = string
  description = "Prowler Cloud webhook URL that will receive events. Provided in Prowler Cloud onboarding."

  validation {
    condition     = can(regex("^https://", var.prowler_webhook_url))
    error_message = "prowler_webhook_url must be an HTTPS URL."
  }
}

variable "prowler_api_key" {
  type        = string
  description = "Per-tenant API key used to authenticate events sent to Prowler Cloud. Provided in Prowler Cloud onboarding."
  sensitive   = true

  validation {
    condition     = length(var.prowler_api_key) > 0
    error_message = "prowler_api_key must not be empty."
  }
}
