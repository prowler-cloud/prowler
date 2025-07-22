# Automated Azure Authentication Setup for Prowler

This guide provides multiple Infrastructure as Code (IaC) options to automate the complete Azure authentication setup for Prowler, eliminating the time-consuming manual process.

## Available Options

| Option | Best For | Time to Deploy | Prerequisites |
|--------|----------|----------------|---------------|
| **[Azure CLI Scripts](./scripts/)** | Quickest setup, any environment | 2-3 minutes | Azure CLI, jq |
| **[Terraform](./terraform/)** | Terraform environments, GitOps | 5 minutes | Terraform, Azure CLI |
| **ARM Templates** | Native Azure tooling | 10+ minutes | Azure CLI, manual steps |

## Recommended: Azure CLI Scripts

For most users, we recommend the Azure CLI scripts as they provide the most complete automation:

### Quick Setup

```bash
cd scripts/
./setup-prowler.sh
```

### What It Does

- ✅ Creates App Registration in Azure AD
- ✅ Generates Service Principal and client secret
- ✅ Assigns all required API permissions
- ✅ Creates custom ProwlerRole across subscriptions
- ✅ Assigns Reader + ProwlerRole to specified subscriptions
- ✅ Provides ready-to-use environment variables

### Usage After Setup

```bash
# Source the generated configuration
source prowler-config.env

# Run Prowler
prowler azure --sp-env-auth
```

### Cleanup

```bash
./cleanup-prowler.sh
```

## Alternative: Terraform

If you prefer Terraform or need to integrate with existing Terraform workflows:

```bash
cd terraform/
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your subscription IDs
./deploy.sh
```

## Comparison with Manual Setup

### Before (Manual Process)
- 📋 **15+ manual steps** across Azure Portal and CLI
- ⏱️ **15-30 minutes** per setup
- 🔄 **Error-prone** and hard to reproduce
- 😩 **Tedious** for multiple subscriptions
- 📖 **Requires following detailed documentation**

### After (Automated Process)
- 🚀 **1 command** to complete setup
- ⚡ **2-3 minutes** total time
- ✅ **Reliable** and repeatable
- 🎯 **Handles multiple subscriptions automatically**
- 🤖 **Zero manual configuration**

## Prerequisites

### Minimum Azure Permissions Required

- **Application Administrator** (for creating app registrations)
- **User Access Administrator** or **Owner** (for subscription role assignments)

### Tools Required

Choose based on your preferred method:

| Method | Tools Needed |
|--------|-------------|
| Azure CLI Scripts | Azure CLI, jq |
| Terraform | Terraform (≥1.5), Azure CLI |
| ARM Templates | Azure CLI |

## What Gets Created

All methods create the same resources:

1. **Azure AD App Registration**
   - Display name: "Prowler Security Scanner"
   - Required API permissions for Microsoft Graph

2. **Service Principal**
   - Linked to the app registration
   - Client secret with configurable expiry

3. **Custom Role: "ProwlerRole"**
   - Additional read permissions not in built-in Reader role
   - Scoped to specified subscriptions

4. **Role Assignments**
   - Reader role (built-in)
   - ProwlerRole (custom)
   - Applied to all specified subscriptions

## Security Considerations

- ✅ **Least Privilege**: Only necessary read permissions granted
- ✅ **Scoped Access**: Roles limited to specified subscriptions
- ✅ **Rotation Ready**: Client secrets can be easily regenerated
- ✅ **Clean Removal**: All resources can be completely removed

## Multi-Subscription Support

All automated methods support multiple subscriptions:

- Specify multiple subscription IDs during setup
- ProwlerRole is created in each subscription
- Role assignments are applied across all subscriptions
- Single service principal works across all subscriptions

## Getting Started

1. **Choose your method** based on the table above
2. **Ensure you have the required permissions** in Azure AD and subscriptions
3. **Follow the specific guide** for your chosen method
4. **Test Prowler** with the generated credentials

## Troubleshooting

### Common Issues

**"Insufficient privileges"**: Ensure you have Application Administrator role in Azure AD

**"Cannot assign roles"**: Ensure you have User Access Administrator or Owner on target subscriptions

**"Admin consent required"**: Some permissions may need manual admin consent in Azure Portal

### Getting Help

- Check the README in each method's directory for detailed troubleshooting
- Scripts provide detailed error messages and suggestions
- All methods are re-runnable if something fails partway through

## Migration from Manual Setup

If you previously set up Prowler manually:

1. **Optional**: Clean up existing resources first
2. **Run automated setup** with same subscription IDs
3. **Update your environment variables** with new credentials
4. **Test that Prowler works** with new setup

The automated setup will create new resources alongside existing ones (no conflicts).