# Azure Prowler Setup Script - Customer Instructions

## Overview
This package contains scripts to set up Azure authentication for Prowler security scanning. The scripts will create the necessary Azure service principal and permissions for Prowler to scan your Azure subscriptions.

## What This Script Does
- Creates an Azure App Registration named "Prowler Security Scanner"
- Generates secure credentials for Prowler
- Sets up the minimal required permissions for security scanning
- Configures role assignments across your subscriptions

## Prerequisites

### Required Software
- **Azure CLI** - The script can install this automatically
- **Bash shell** - Available on Linux, macOS, and Windows (WSL/Git Bash)
- **Internet connection**

### Required Azure Permissions
You need ONE of the following permission combinations:

**Option 1 (Recommended):**
- **Global Administrator** role

**Option 2:**
- **Application Administrator** role + **Global Administrator** role (for admin consent)
- **User Access Administrator** or **Owner** role on target subscriptions

## Quick Start

### Step 1: Choose Your Setup Script

**For Single Subscription:**
```bash
bash all-in-one-single-sub.sh
```

**For Multiple Subscriptions:**
```bash
bash all-in-one-multi-sub.sh
```

### Step 2: Follow the Interactive Prompts
The script will guide you through:
1. Azure CLI login
2. Subscription selection
3. App registration creation
4. Permission setup
5. Admin consent (if required)

### Step 3: Collect Your Credentials
After successful completion, you'll receive:
- **Client ID** (Application ID)
- **Client Secret** 🔐 **KEEP SECURE**
- **Tenant ID**
- Configuration file: `prowler-config.env`

## What to Provide Back

### ✅ Required Credentials to Share:
- **Client ID**: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- **Client Secret**: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` 🔐 **SECURE TRANSMISSION REQUIRED**
- **Tenant ID**: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- **Subscription IDs**: List of configured subscriptions

### ⚠️ Security Notes:
- Share credentials through secure channels only (encrypted email, secure file transfer)
- Do not include credentials in screenshots or plain text emails
- Delete credentials from your system after secure transmission

## Expected Runtime
- Single subscription: 3-5 minutes
- Multiple subscriptions: 5-10 minutes
- Additional time may be needed for manual admin consent

## Troubleshooting

If you encounter issues, run the troubleshooting script:
```bash
bash troubleshoot-azure-auth.sh
```

This will automatically diagnose and fix common problems.

### Common Issues:

**"Insufficient privileges to complete the operation"**
- You need Application Administrator or Global Administrator role
- Contact your Azure admin for the required permissions

**"Admin consent required"**
- The script will provide a URL for manual consent
- You or your Global Administrator needs to approve the permissions

**"Subscription not found"**
- Verify you have access to the subscription
- Check that you're logged into the correct Azure tenant

## Security Notes

### What Permissions Does This Create?
- **Microsoft Graph API:**
  - `Domain.Read.All` - Read domain information
  - `Policy.Read.All` - Read security policies
  - `UserAuthenticationMethod.Read.All` - Read authentication methods

- **Azure Subscriptions:**
  - `Reader` role - Read Azure resources
  - `ProwlerRole` (custom) - Additional security-specific read permissions

### Data Access
The service principal created can:
- ✅ Read configuration and security settings
- ✅ List resources and their properties
- ❌ Cannot modify or delete any resources
- ❌ Cannot access application data or user content

## Cleanup

To remove all created resources:
```bash
bash cleanup-prowler.sh
```

This will delete:
- The app registration
- Service principal
- Role assignments
- Custom roles

## Support

If you need assistance:
1. Run the troubleshooting script first
2. Check the error messages carefully
3. Contact your system administrator for Azure permission issues
4. When requesting support, provide Client ID and Tenant ID only

---

**🔒 Remember: Keep your Client Secret secure and use secure transmission methods when sharing credentials.**