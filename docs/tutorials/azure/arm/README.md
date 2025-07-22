# ARM Template Deployment for Prowler

This directory contains Azure Resource Manager (ARM) templates for deploying Prowler authentication resources through the Azure Portal.

## ✅ Answer: Yes, App Registrations CAN Be Done via ARM!

You're absolutely correct! App Registrations **can** be created via ARM templates, but there are some practical challenges:

### **Why ARM Templates Are Limited for This Use Case**

1. **Microsoft Graph Resources**: App Registrations use Microsoft Graph API, which requires special handling in ARM
2. **Authentication Context**: ARM deployments need managed identity or service principal with Graph permissions
3. **Admin Consent**: Still requires manual admin consent step for API permissions
4. **Complexity**: Much more complex than Azure CLI approach

### **Current ARM Template Approach**

This template creates **only the custom roles** across subscriptions. For complete automation including App Registration, see the alternatives below.

## Deployment Options

### Option 1: Deploy to Azure Button (Role Creation Only)

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fprowler-cloud%2Fprowler%2Fmaster%2Fdocs%2Ftutorials%2Fazure%2Farm%2FmainTemplate.json)

This creates the ProwlerRole across specified subscriptions.

### Option 2: Complete ARM Template with App Registration

For a complete ARM solution including App Registration, see `complete-template.json` - this uses:
- **Deployment Scripts** with PowerShell + Microsoft Graph
- **Managed Identity** for authentication
- **More complex setup** but fully automated

### Option 3: Hybrid Approach (Recommended)

1. **Deploy ARM template** for custom roles (this template)
2. **Run completion script** for App Registration:

```bash
# After ARM deployment
cd ../scripts
./setup-prowler.sh  # This will detect existing roles and complete setup
```

## ARM Template Deployment Methods

### Portal Deployment
1. Azure Portal > "Deploy a custom template"
2. Upload `mainTemplate.json` 
3. Enter subscription IDs
4. Deploy

### Azure CLI Deployment
```bash
az deployment sub create \
  --location "East US" \
  --template-file mainTemplate.json \
  --parameters subscriptionIds='["sub1","sub2"]'
```

### PowerShell Deployment
```powershell
New-AzSubscriptionDeployment `
  -Location "East US" `
  -TemplateFile "mainTemplate.json" `
  -subscriptionIds @("sub1", "sub2")
```

## What This Template Creates

### ✅ Automated by ARM Template
- **Custom Role**: "ProwlerRole" with additional read permissions  
- **Multi-Subscription**: Deploys to all specified subscriptions
- **Proper Scoping**: Role limited to specified subscriptions only

### ❌ Still Manual (Use Scripts Instead)
- App Registration creation
- Service Principal creation  
- Client secret generation
- API permissions + admin consent
- Role assignments to service principal

## Complete Solution Options

| Method | Portal UI | Manual Steps | Time | Complexity |
|--------|-----------|-------------|------|------------|
| **ARM (this template)** | ✅ | 5 steps | 10+ min | Medium |
| **ARM + Scripts hybrid** | ✅ | 1 step | 5 min | Low |
| **Pure CLI Scripts** | ❌ | 0 steps | 2 min | Lowest |
| **Complete ARM** | ✅ | 1 step | 8 min | High |

## Recommendation by Use Case

### Use ARM Templates If:
- **Organization requires** native Azure tooling
- **Portal deployment** is mandatory  
- **GitOps workflow** with ARM templates
- **Governance** requires template-based deployments

### Use CLI Scripts If:
- **Fastest setup** is priority
- **Zero manual steps** required
- **One-time deployment** (not recurring)
- **Developer/admin** comfort with CLI tools

## Files in This Directory

- `mainTemplate.json` - Role creation template (subscription-scoped)
- `complete-template.json` - Full template with App Registration (complex)
- `mainTemplate.parameters.json` - Parameter file example
- `createUiDefinition.json` - Portal UI definition
- `deploy-to-azure-button.md` - Deploy button documentation

## Advanced: Complete ARM Template

The `complete-template.json` shows how to create App Registrations via ARM using:

```json
{
  "type": "Microsoft.Resources/deploymentScripts",
  "properties": {
    "azPowerShellVersion": "8.3",
    "scriptContent": "Connect-MgGraph; New-MgApplication..."
  }
}
```

This approach works but requires:
- Managed identity with Graph permissions
- PowerShell modules in deployment container  
- More complex error handling

## Quick Start: Hybrid Approach

Best of both worlds - Portal deployment + automation:

```bash
# 1. Deploy ARM template via Portal (creates roles)
# 2. Complete setup with one command:
cd ../scripts && ./setup-prowler.sh
```

The CLI script will detect existing ProwlerRoles and complete the App Registration setup automatically.