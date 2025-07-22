# Azure CLI Scripts for Prowler Authentication

This directory contains shell scripts to completely automate the Prowler Azure authentication setup, requiring zero manual configuration.

## Quick Start Options

### Option 1: All-in-One Installation (Recommended for New Users)

These scripts handle everything, including installing prerequisites:

```bash
# For single subscription setup:
./all-in-one-single-sub.sh

# For multi-subscription setup:
./all-in-one-multi-sub.sh
```

### Option 2: Core Setup Scripts (For Users with Azure CLI Already)

If you already have Azure CLI and jq installed:

```bash
# For single subscription setup:
./single-subscription-setup.sh

# For multi-subscription setup:
./multi-subscription-setup.sh
```

## What These Scripts Automate

- ✅ Azure CLI installation (all-in-one scripts only)
- ✅ App Registration creation
- ✅ Service Principal creation  
- ✅ Client secret generation
- ✅ API permissions assignment (Domain.Read.All, Policy.Read.All, UserAuthenticationMethod.Read.All)
- ✅ Admin consent (when possible)
- ✅ Custom ProwlerRole creation across subscriptions
- ✅ Reader + ProwlerRole assignments
- ✅ Environment variable configuration

## Script Differences

| Script | Prerequisites | Target | Best For |
|--------|--------------|--------|----------|
| **all-in-one-single-sub.sh** | Installs Azure CLI & jq | Current subscription | New users, single subscription |
| **all-in-one-multi-sub.sh** | Installs Azure CLI & jq | Multiple subscriptions | New users, multiple subscriptions |
| **single-subscription-setup.sh** | Requires Azure CLI & jq | Current subscription | Experienced users, single subscription |
| **multi-subscription-setup.sh** | Requires Azure CLI & jq | Multiple subscriptions | Experienced users, multiple subscriptions |

## Prerequisites

### Permissions Required

- **Application Administrator** or **Global Administrator** (for app registration and admin consent)
- **User Access Administrator** or **Owner** (for subscription role assignments)

### About Admin Consent

To programmatically grant admin consent for API permissions, you need:
- **Global Administrator** or 
- **Privileged Role Administrator** and **Application Administrator** roles

If you don't have these roles, the script will guide you through granting admin consent manually with a browser-based workflow. This is a common scenario and the script handles it automatically.

## Usage with Prowler App

After running any of these scripts, you'll receive credentials (Client ID, Client Secret, Tenant ID) that you can enter directly into the Prowler App:

1. Open Prowler App
2. Go to Configuration > Cloud Providers > Add Cloud Provider > Microsoft Azure
3. Enter the credentials provided by the script
4. Complete the setup in the Prowler App

## Usage with Prowler CLI

After setup completes:

```bash
# Source the generated config file
source prowler-config.env

# Run Prowler against Azure
prowler azure --sp-env-auth
```

## Troubleshooting

### Permission Errors

If you get permission errors:

1. **For app registration**: Ensure your account has `Application Administrator` role in Azure AD
2. **For subscriptions**: Ensure your account has `Owner` or `User Access Administrator` on target subscriptions

### Admin Consent Issues

The scripts now handle admin consent issues interactively by:
1. Detecting when automated consent fails
2. Providing a direct URL to the consent page
3. Offering to open the browser automatically
4. Guiding you through the consent process
5. Validating that consent was successfully granted

If you encounter any issues with admin consent:
1. Ensure you're logged in with an account that has **Global Administrator** rights
2. Go to Azure Portal > Azure AD > App registrations
3. Find "Prowler Security Scanner"
4. Click "API permissions" > "Grant admin consent"
5. Verify that all permissions show green checkmarks