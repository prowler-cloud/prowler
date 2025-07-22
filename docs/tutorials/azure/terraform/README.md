# Terraform Infrastructure for Prowler Azure Authentication

This directory contains Terraform configuration to automatically set up all required Azure resources for Prowler security scanning, eliminating the manual setup process.

## What This Creates

- **App Registration** in Azure AD/Entra ID
- **Service Principal** with client secret
- **API Permissions** (Domain.Read.All, Policy.Read.All, UserAuthenticationMethod.Read.All)
- **Custom ProwlerRole** with additional read permissions
- **Role Assignments** (Reader + ProwlerRole) across specified subscriptions

## Prerequisites

1. **Terraform** (>= 1.5) - [Install Guide](https://developer.hashicorp.com/terraform/tutorials/aws-get-started/install-cli)
2. **Azure CLI** - [Install Guide](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli)
3. **Azure Account** with appropriate permissions:
   - Application Administrator (to create app registrations)
   - User Access Administrator or Owner (for role assignments)

## Quick Start

1. **Login to Azure**:
   ```bash
   az login
   ```

2. **Configure subscriptions**:
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   # Edit terraform.tfvars with your subscription IDs
   ```

3. **Deploy**:
   ```bash
   ./deploy.sh
   ```

4. **Use the output credentials with Prowler**:
   ```bash
   # The script will display the exact commands needed
   export AZURE_CLIENT_ID="..."
   export AZURE_CLIENT_SECRET="..."
   export AZURE_TENANT_ID="..."
   
   prowler azure --sp-env-auth
   ```

## Manual Terraform Commands

If you prefer to run Terraform commands manually:

```bash
# Initialize
terraform init

# Plan
terraform plan

# Apply
terraform apply

# View outputs (including secrets)
terraform output -raw prowler_env_commands
```

## Configuration Options

Edit `terraform.tfvars`:

```hcl
# Application name
app_name = "Prowler Security Scanner"

# Subscription IDs to scan
subscription_ids = [
  "12345678-1234-1234-1234-123456789012",
  "87654321-4321-4321-4321-210987654321"
]

# Client secret expiry (1 year default)
client_secret_expiry = "8760h"
```

## Outputs

After deployment, you'll get:
- `application_id` - Client ID for Prowler
- `tenant_id` - Your Azure AD tenant ID  
- `client_secret` - Client secret (sensitive)
- `prowler_env_commands` - Ready-to-use environment setup

## Cleanup

To remove all created resources:

```bash
terraform destroy
```

## Troubleshooting

**Permission denied errors**: Ensure your Azure account has Application Administrator and User Access Administrator roles.

**Role assignment failures**: The account running Terraform needs Owner or User Access Administrator on target subscriptions.

**API permission issues**: Admin consent is automatically granted, but verify in Azure Portal if needed.