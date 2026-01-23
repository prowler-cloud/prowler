# =============================================================================
# Terraform script to create test secrets across 3 Azure KeyVaults
#
# Creates:
#   - 500 secrets in existing KeyVault (test-azure-speedup)
#   - 2 new KeyVaults with 500 secrets each (test-azure-speedup-2, test-azure-speedup-3)
#   - Total: 3 vaults, 1500 secrets
#
# Usage:
#   1. cd scripts/
#   2. terraform init
#   3. terraform plan
#   4. terraform apply
#   5. To cleanup: terraform destroy
# =============================================================================

terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

# =============================================================================
# VARIABLES
# =============================================================================

variable "subscription_id" {
  description = "Azure Subscription ID"
  type        = string
  default     = "0b070121-2ad4-4e44-aba0-39dcd5310b60"
}

variable "resource_group_name" {
  description = "Name of the existing resource group"
  type        = string
  default     = "Dev-Test"
}

variable "keyvault_name" {
  description = "Name of the existing KeyVault"
  type        = string
  default     = "test-azure-speedup"
}

variable "secret_count" {
  description = "Number of test secrets to create in existing KeyVault"
  type        = number
  default     = 500
}

variable "additional_vault_secret_count" {
  description = "Number of test secrets to create per additional KeyVault"
  type        = number
  default     = 500
}

variable "secret_prefix" {
  description = "Prefix for secret names"
  type        = string
  default     = "prowler-test-secret"
}

# =============================================================================
# DATA - Reference existing resources
# =============================================================================

data "azurerm_client_config" "current" {}

data "azurerm_resource_group" "existing" {
  name = var.resource_group_name
}

data "azurerm_key_vault" "existing" {
  name                = var.keyvault_name
  resource_group_name = var.resource_group_name
}

# =============================================================================
# SECRETS - Create 500 test secrets in existing KeyVault
# =============================================================================

resource "azurerm_key_vault_secret" "test_secrets" {
  count        = var.secret_count
  name         = "${var.secret_prefix}-${format("%03d", count.index + 1)}"
  value        = "test-value-${count.index + 1}"
  key_vault_id = data.azurerm_key_vault.existing.id

  # Every 3rd secret expires in 6 months, others have no expiration
  expiration_date = count.index % 3 == 0 ? timeadd(timestamp(), "4320h") : null

  content_type = "text/plain"

  tags = {
    environment = "test"
    purpose     = "prowler-integration-testing"
    index       = tostring(count.index + 1)
  }
}

# =============================================================================
# ADDITIONAL KEYVAULTS - Create 2 new KeyVaults for parallelization testing
# =============================================================================

resource "azurerm_key_vault" "additional" {
  count               = 2
  name                = "test-azure-speedup-${count.index + 2}"
  location            = data.azurerm_resource_group.existing.location
  resource_group_name = var.resource_group_name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  sku_name            = "standard"

  enable_rbac_authorization  = true
  soft_delete_retention_days = 7
  purge_protection_enabled   = false

  tags = {
    environment = "test"
    purpose     = "prowler-integration-testing"
    vault_index = tostring(count.index + 2)
  }
}

# =============================================================================
# ADDITIONAL SECRETS - Create 500 secrets per additional KeyVault (1000 total)
# =============================================================================

resource "azurerm_key_vault_secret" "additional_secrets" {
  count        = var.additional_vault_secret_count * 2
  name         = "${var.secret_prefix}-${format("%03d", (count.index % var.additional_vault_secret_count) + 1)}"
  value        = "test-value-additional-${count.index + 1}"
  key_vault_id = azurerm_key_vault.additional[floor(count.index / var.additional_vault_secret_count)].id

  # Every 3rd secret expires in 6 months, others have no expiration
  expiration_date = count.index % 3 == 0 ? timeadd(timestamp(), "4320h") : null

  content_type = "text/plain"

  tags = {
    environment = "test"
    purpose     = "prowler-integration-testing"
    vault_index = tostring(floor(count.index / var.additional_vault_secret_count) + 2)
    index       = tostring((count.index % var.additional_vault_secret_count) + 1)
  }
}

# =============================================================================
# OUTPUTS
# =============================================================================

output "existing_keyvault_name" {
  description = "Name of the existing KeyVault"
  value       = data.azurerm_key_vault.existing.name
}

output "additional_keyvault_names" {
  description = "Names of the additional KeyVaults created"
  value       = [for kv in azurerm_key_vault.additional : kv.name]
}

output "existing_vault_secrets_count" {
  description = "Number of secrets in existing KeyVault"
  value       = length(azurerm_key_vault_secret.test_secrets)
}

output "additional_vault_secrets_count" {
  description = "Number of secrets in additional KeyVaults (total)"
  value       = length(azurerm_key_vault_secret.additional_secrets)
}

output "total_secrets_count" {
  description = "Total number of secrets across all KeyVaults"
  value       = length(azurerm_key_vault_secret.test_secrets) + length(azurerm_key_vault_secret.additional_secrets)
}

output "total_keyvaults_count" {
  description = "Total number of KeyVaults (existing + additional)"
  value       = 1 + length(azurerm_key_vault.additional)
}

output "secrets_with_expiration" {
  description = "Approximate count of secrets WITH expiration (will trigger PASS in checks)"
  value       = floor((var.secret_count + var.additional_vault_secret_count * 2) / 3) + 1
}

output "secrets_without_expiration" {
  description = "Approximate count of secrets WITHOUT expiration (will trigger FAIL in checks)"
  value       = (var.secret_count + var.additional_vault_secret_count * 2) - floor((var.secret_count + var.additional_vault_secret_count * 2) / 3) - 1
}
