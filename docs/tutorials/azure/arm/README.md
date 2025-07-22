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

### Option 1: Deploy to Azure Button (PARTIAL - Role Creation Only)

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fkourosh-forti-hands%2Fprowler%2Fmaster%2Fdocs%2Ftutorials%2Fazure%2Farm%2FmainTemplate.json)

**⚠️ Creates only ProwlerRole - requires 5 additional manual steps**

**After deployment, complete setup using:**
- **Recommended**: Run `../scripts/setup-prowler.sh` (will detect existing roles and complete setup)
- **Manual**: Follow the [original manual setup guide](../create-prowler-service-principal.md) and [subscription setup](../subscriptions.md)

### Option 2: Complete ARM Template with App Registration (NEARLY COMPLETE)

For a complete ARM solution including App Registration, see `complete-template.json` - this uses:
- **Deployment Scripts** with PowerShell + Microsoft Graph
- **Managed Identity** for authentication
- **⚠️ Still requires manual admin consent for API permissions**

### Option 3: Hybrid Approach (MOST COMPLETE)

1. **Deploy ARM template** for custom roles (this template) - **PARTIAL**
2. **Run completion script** for everything else:

```bash
# After ARM deployment
cd ../scripts
./setup-prowler.sh  # Completes ALL remaining steps automatically
```

**✅ This results in 100% complete setup**

## ARM Template Deployment Methods

### Portal Deployment
1. Azure Portal > "Deploy a custom template"
2. Upload `mainTemplate.json` 
3. Enter subscription IDs as an array:
   ```json
   ["subscription-id-1", "subscription-id-2"]
   ```
   > **Important**: When entering subscription IDs, you must include the square brackets even for a single subscription ID: `["subscription-id"]`
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

## Completion Guide After Option 1 Deployment

If you deployed Option 1 (ARM template), you have the ProwlerRole created but need to complete these steps:

### **Recommended: Automated Completion**
```bash
cd ../scripts
./setup-prowler.sh
```
This script will:
- Detect existing ProwlerRole
- Create App Registration
- Generate client secret
- Grant admin consent
- Assign all roles

### **Manual Completion Steps**
1. **Create App Registration** - [Guide](../create-prowler-service-principal.md)
2. **Assign roles to subscriptions** - [Guide](../subscriptions.md)
3. **Export environment variables and run Prowler**

## Complete Solution Options

| Method | Portal UI | Manual Steps | Time | Completeness |
|--------|-----------|-------------|------|-------------|
| **Option 1: ARM (this template)** | ✅ | 5 steps | 10+ min | ⚠️ PARTIAL |
| **Option 2: Complete ARM** | ✅ | 1 step | 8 min | 🟡 NEARLY COMPLETE |
| **Option 3: ARM + Scripts hybrid** | ✅ | 1 step | 5 min | ✅ 100% COMPLETE |
| **Pure CLI Scripts** | ❌ | 0 steps | 2 min | ✅ 100% COMPLETE |

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