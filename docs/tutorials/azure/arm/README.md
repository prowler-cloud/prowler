# ARM Template Deployment for Prowler

This directory contains Azure Resource Manager (ARM) templates for deploying Prowler authentication resources through the Azure Portal.

## ⚠️ Important Limitation

ARM templates have significant limitations with Azure AD/Entra ID resources. This template only creates the **custom ProwlerRole** - you'll still need several manual steps to complete the setup.

**For a fully automated solution, use the [Azure CLI scripts](../scripts/) instead.**

## Deployment Options

### Option 1: Deploy to Azure Button (Easiest)

Click this button to deploy directly from the Azure Portal:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fprowler-cloud%2Fprowler%2Fmaster%2Fdocs%2Ftutorials%2Fazure%2Farm%2FmainTemplate.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2Fprowler-cloud%2Fprowler%2Fmaster%2Fdocs%2Ftutorials%2Fazure%2Farm%2FcreateUiDefinition.json)

### Option 2: Manual Portal Deployment

1. **Go to Azure Portal** > Search "Deploy a custom template"
2. **Build your own template** > Upload `mainTemplate.json`
3. **Fill parameters**:
   - Subscription IDs (array of subscription IDs to configure)
   - Custom Role Name (default: "ProwlerRole")
4. **Review + Create**

### Option 3: Azure CLI Deployment

```bash
# Deploy to subscription scope
az deployment sub create \
  --location "East US" \
  --template-file mainTemplate.json \
  --parameters @mainTemplate.parameters.json
```

## What Gets Deployed

### ✅ Automated by ARM Template
- **Custom Role**: "ProwlerRole" with additional read permissions
- **Role Scoping**: Limited to specified subscriptions
- **Permissions**: `Microsoft.Web/sites/host/listkeys/action`, `Microsoft.Web/sites/config/list/Action`

### ❌ Manual Steps Still Required

1. **Create App Registration**
   ```
   Azure AD > App registrations > New registration
   Name: "Prowler Security Scanner"
   ```

2. **Add API Permissions**
   ```
   API permissions > Add a permission > Microsoft Graph > Application permissions:
   - Domain.Read.All
   - Policy.Read.All  
   - UserAuthenticationMethod.Read.All
   ```

3. **Create Client Secret**
   ```
   Certificates & secrets > New client secret
   Copy the secret value (shown only once)
   ```

4. **Grant Admin Consent**
   ```
   API permissions > Grant admin consent for [tenant]
   ```

5. **Assign Roles to Service Principal**
   
   For each subscription:
   ```
   Subscription > Access control (IAM) > Add role assignment:
   - Role: Reader
   - Members: Prowler Security Scanner
   
   Subscription > Access control (IAM) > Add role assignment:
   - Role: ProwlerRole
   - Members: Prowler Security Scanner
   ```

## Files Description

- `mainTemplate.json` - Main ARM template
- `mainTemplate.parameters.json` - Parameter file example
- `createUiDefinition.json` - Portal UI definition for custom deployment experience
- `deploy-to-azure-button.md` - Deploy button with GitHub links

## Comparison: ARM vs CLI Scripts

| Aspect | ARM Template | CLI Scripts |
|--------|-------------|-------------|
| **Azure Portal UI** | ✅ Native | ❌ Not applicable |
| **Manual Steps** | 🔶 5 manual steps | ✅ Zero manual steps |
| **Time Required** | 🔶 10-15 minutes | ✅ 2-3 minutes |
| **Error Prone** | 🔶 Medium | ✅ Low |
| **Multi-Subscription** | ✅ Supported | ✅ Automated |
| **Cleanup** | 🔶 Manual | ✅ Automated |

## Recommendation

While ARM templates provide a familiar Azure Portal experience, the significant manual steps required make the **[Azure CLI scripts](../scripts/)** the better choice for most users.

Use ARM templates only if:
- You're required to use native Azure tooling
- You need the Portal UI experience
- You don't mind completing manual steps

## After Deployment

Once you complete all manual steps, use Prowler with:

```bash
export AZURE_CLIENT_ID="your-app-id"
export AZURE_CLIENT_SECRET="your-client-secret"
export AZURE_TENANT_ID="your-tenant-id"

prowler azure --sp-env-auth
```

## Troubleshooting

**Template deployment fails**: Ensure you have Owner or User Access Administrator on target subscriptions

**Can't create app registration**: Ensure you have Application Administrator role in Azure AD

**API permissions not granted**: Admin consent must be granted by a Global Administrator or Application Administrator