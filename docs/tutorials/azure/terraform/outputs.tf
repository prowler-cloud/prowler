output "application_id" {
  description = "The Application (Client) ID of the Prowler App Registration"
  value       = azuread_application.prowler.application_id
}

output "tenant_id" {
  description = "The Azure AD Tenant ID"
  value       = data.azuread_client_config.current.tenant_id
}

output "client_secret" {
  description = "The client secret for the Prowler App Registration (sensitive)"
  value       = azuread_application_password.prowler.value
  sensitive   = true
}

output "service_principal_object_id" {
  description = "The Object ID of the Prowler Service Principal"
  value       = azuread_service_principal.prowler.object_id
}

output "prowler_env_commands" {
  description = "Environment variable commands to configure Prowler authentication"
  value = <<-EOT
    # Set these environment variables to use Prowler with service principal authentication:
    export AZURE_CLIENT_ID="${azuread_application.prowler.application_id}"
    export AZURE_CLIENT_SECRET="${azuread_application_password.prowler.value}"
    export AZURE_TENANT_ID="${data.azuread_client_config.current.tenant_id}"
    
    # Run Prowler with service principal authentication:
    prowler azure --sp-env-auth
  EOT
  sensitive = true
}