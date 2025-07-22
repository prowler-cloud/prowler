terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.47"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azuread" {}

provider "azurerm" {
  features {}
}

# Get current tenant and client config
data "azuread_client_config" "current" {}

# Create the Prowler App Registration
resource "azuread_application" "prowler" {
  display_name = var.app_name
  owners       = [data.azuread_client_config.current.object_id]

  required_resource_access {
    resource_app_id = "00000003-0000-0000-c000-000000000000" # Microsoft Graph

    resource_access {
      id   = "7ab1d382-f21e-4acd-a863-ba3e13f7da61" # Domain.Read.All
      type = "Role"
    }

    resource_access {
      id   = "246dd0d5-5bd0-4def-940b-0421030a5b68" # Policy.Read.All
      type = "Role"
    }

    resource_access {
      id   = "38d9df27-64da-44fd-b7c5-a6fbac20248f" # UserAuthenticationMethod.Read.All
      type = "Role"
    }
  }
}

# Create Service Principal for the App Registration
resource "azuread_service_principal" "prowler" {
  application_id               = azuread_application.prowler.application_id
  app_role_assignment_required = false
  owners                       = [data.azuread_client_config.current.object_id]
}

# Create client secret
resource "azuread_application_password" "prowler" {
  application_object_id = azuread_application.prowler.object_id
  display_name          = "Prowler Client Secret"
  end_date_relative     = var.client_secret_expiry
}

# Grant admin consent for the required permissions
resource "azuread_app_role_assignment" "domain_read_all" {
  app_role_id         = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"
  principal_object_id = azuread_service_principal.prowler.object_id
  resource_object_id  = azuread_service_principal.msgraph.object_id
}

resource "azuread_app_role_assignment" "policy_read_all" {
  app_role_id         = "246dd0d5-5bd0-4def-940b-0421030a5b68"
  principal_object_id = azuread_service_principal.prowler.object_id
  resource_object_id  = azuread_service_principal.msgraph.object_id
}

resource "azuread_app_role_assignment" "user_auth_method_read_all" {
  app_role_id         = "38d9df27-64da-44fd-b7c5-a6fbac20248f"
  principal_object_id = azuread_service_principal.prowler.object_id
  resource_object_id  = azuread_service_principal.msgraph.object_id
}

# Get Microsoft Graph Service Principal
data "azuread_service_principal" "msgraph" {
  application_id = "00000003-0000-0000-c000-000000000000"
}

# Create custom ProwlerRole
resource "azurerm_role_definition" "prowler_role" {
  for_each = toset(var.subscription_ids)

  name  = "ProwlerRole"
  scope = "/subscriptions/${each.key}"

  description = "Role used for checks that require read-only access to Azure resources and are not covered by the Reader role."

  permissions {
    actions = [
      "Microsoft.Web/sites/host/listkeys/action",
      "Microsoft.Web/sites/config/list/Action"
    ]
  }

  assignable_scopes = [
    "/subscriptions/${each.key}"
  ]
}

# Assign Reader role to subscriptions
resource "azurerm_role_assignment" "prowler_reader" {
  for_each = toset(var.subscription_ids)

  scope                = "/subscriptions/${each.key}"
  role_definition_name = "Reader"
  principal_id         = azuread_service_principal.prowler.object_id
}

# Assign custom ProwlerRole to subscriptions
resource "azurerm_role_assignment" "prowler_custom" {
  for_each = toset(var.subscription_ids)

  scope              = "/subscriptions/${each.key}"
  role_definition_id = azurerm_role_definition.prowler_role[each.key].role_definition_resource_id
  principal_id       = azuread_service_principal.prowler.object_id

  depends_on = [azurerm_role_definition.prowler_role]
}