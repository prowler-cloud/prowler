# Azure CLI Scripts for Prowler Authentication

This directory contains shell scripts to completely automate the Prowler Azure authentication setup, requiring zero manual configuration.

## What This Automates

- ✅ App Registration creation
- ✅ Service Principal creation  
- ✅ Client secret generation
- ✅ API permissions assignment (Domain.Read.All, Policy.Read.All, UserAuthenticationMethod.Read.All)
- ✅ Admin consent (when possible)
- ✅ Custom ProwlerRole creation across subscriptions
- ✅ Reader + ProwlerRole assignments
- ✅ Environment variable configuration

## Prerequisites

- **Azure CLI** installed and authenticated (`az login`)
- **jq** for JSON parsing (usually pre-installed on most systems)
- **Permissions**:
  - Application Administrator (for app registration)
  - User Access Administrator or Owner (for subscription role assignments)

## Quick Start

### Setup Prowler Authentication

```bash
# Make script executable (if needed)
chmod +x setup-prowler.sh

# Run the setup
./setup-prowler.sh
```

The script will:
1. Check prerequisites
2. Show available subscriptions and prompt for selection
3. Create app registration with all required permissions
4. Create custom roles across subscriptions
5. Assign all necessary roles
6. Display final configuration

### Use Prowler

After setup completes:

```bash
# Option 1: Source the generated config file
source prowler-config.env
prowler azure --sp-env-auth

# Option 2: Export variables manually (shown in script output)
export AZURE_CLIENT_ID="..."
export AZURE_CLIENT_SECRET="..."
export AZURE_TENANT_ID="..."
prowler azure --sp-env-auth
```

### Cleanup (Optional)

To remove all created resources:

```bash
./cleanup-prowler.sh
```

## Script Features

### Interactive Configuration
- Lists all available subscriptions
- Validates subscription ID format
- Confirms actions before execution
- Provides clear success/error feedback

### Error Handling
- Checks for existing resources to avoid conflicts
- Handles permissions gracefully (warns if admin consent fails)
- Validates prerequisites upfront
- Provides detailed error messages

### Security Best Practices
- Generates unique client secrets
- Uses least-privilege permissions
- Creates scoped custom roles
- Saves configuration securely

## Troubleshooting

### Permission Errors

If you get permission errors:

1. **For app registration**: Ensure your account has `Application Administrator` role in Azure AD
2. **For subscriptions**: Ensure your account has `Owner` or `User Access Administrator` on target subscriptions

### Admin Consent Issues

If admin consent fails automatically:
1. Go to Azure Portal > Azure AD > App registrations
2. Find "Prowler Security Scanner"
3. Click "API permissions" > "Grant admin consent"

### Script Fails Mid-Execution

The scripts are designed to be re-runnable. If something fails:
1. Fix the underlying issue
2. Re-run the script - it will skip already-completed steps

## Comparison with Manual Setup

| Task | Manual Setup | Script Setup |
|------|-------------|-------------|
| Time Required | 15-30 minutes | 2-3 minutes |
| Steps | 15+ manual steps | 1 command |
| Error Prone | High | Low |
| Repeatable | No | Yes |
| Multi-subscription | Tedious | Automated |

## Files Created

- `prowler-config.env` - Environment variables for Prowler
- Script logs (if any errors occur)

## Security Notes

- Client secrets are displayed once and saved to `prowler-config.env`
- Store secrets securely and rotate them regularly
- The cleanup script removes all traces when no longer needed