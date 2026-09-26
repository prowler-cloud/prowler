variable "prowler_webhook_url" {
  type        = string
  description = "Prowler Cloud endpoint that receives the events. Provided during Prowler Cloud onboarding."

  validation {
    condition     = can(regex("^https://", var.prowler_webhook_url))
    error_message = "prowler_webhook_url must be an HTTPS URL."
  }
}

variable "prowler_api_key" {
  type        = string
  description = "Prowler Cloud API key used to authenticate the events sent to the endpoint above."
  sensitive   = true

  validation {
    condition     = length(var.prowler_api_key) > 0
    error_message = "prowler_api_key must not be empty."
  }
}
