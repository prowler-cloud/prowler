# Prowler Azure Setup - Customer Guide

## What You'll Be Running

This package contains secure scripts to set up Azure authentication for Prowler security scanning. The scripts will create the necessary Azure service principal and permissions.

## Prerequisites

### Required Permissions
You need **ONE** of these permission combinations:
- **Global Administrator** role (easiest option)
- **Application Administrator** + **User Access Administrator** on subscriptions

### Required Software
- Azure CLI (script can install this automatically)
- Bash shell (Linux/macOS terminal, or Windows WSL/Git Bash)

## Quick Setup

### Option 1: Single Subscription
```bash
bash all-in-one-single-sub.sh
```

### Option 2: Multiple Subscriptions  
```bash
bash all-in-one-multi-sub.sh
```

## What Happens During Setup

1. **Prerequisites Check** - Installs Azure CLI and required tools
2. **Azure Login** - You'll log into your Azure account
3. **App Registration** - Creates "Prowler Security Scanner" app
4. **Permissions Setup** - Configures minimal read-only security permissions
5. **Credential Generation** - Creates secure authentication credentials

## Expected Output

After successful setup, you'll receive:
- **Client ID** (Application ID)
- **Client Secret** 🔐 **KEEP SECURE**
- **Tenant ID**
- Configuration file: `prowler-config.env`

## What to Share Back

### ✅ Required Credentials to Share:
- **Client ID**: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- **Client Secret**: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` 🔐 **SECURE TRANSMISSION REQUIRED**
- **Tenant ID**: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`
- **Subscription IDs**: List of configured subscriptions

### ⚠️ Security Notes:
- Share credentials through secure channels only (encrypted email, secure file transfer)
- Do not include credentials in screenshots or plain text emails
- Delete credentials from your system after secure transmission

## Troubleshooting

If you encounter issues:
```bash
bash troubleshoot-azure-auth.sh
```

### Common Solutions:

**"Insufficient privileges"**
- Contact your Azure admin for required roles

**"Admin consent required"**  
- Use the provided URL for manual approval
- Your Global Administrator can approve permissions

## Security Information

### What Access Does This Create?
- **Read-only access** to security configurations
- **Cannot modify** any Azure resources
- **Cannot access** user data or applications

### Specific Permissions:
- Read domain and security policies
- List Azure resources and configurations
- Read authentication methods (for security analysis)

## Cleanup (Optional)

To remove all created resources:
```bash
bash cleanup-prowler.sh
```

## Support

1. First run: `bash troubleshoot-azure-auth.sh`
2. For permission issues, contact your Azure administrator
3. When requesting support, provide Client ID and Tenant ID only

---

**🔒 Remember: Keep your Client Secret secure and never share it in emails or screenshots.**