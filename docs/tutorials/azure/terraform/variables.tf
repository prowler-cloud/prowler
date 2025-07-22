variable "app_name" {
  description = "Name of the Prowler App Registration"
  type        = string
  default     = "Prowler Security Scanner"
}

variable "subscription_ids" {
  description = "List of Azure subscription IDs to grant Prowler access to"
  type        = list(string)
  validation {
    condition     = length(var.subscription_ids) > 0
    error_message = "At least one subscription ID must be provided."
  }
}

variable "client_secret_expiry" {
  description = "Client secret expiry duration (e.g., '8760h' for 1 year)"
  type        = string
  default     = "8760h"
}