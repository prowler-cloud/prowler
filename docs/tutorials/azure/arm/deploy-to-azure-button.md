# Deploy to Azure Button

## Quick Deploy

Click the button below to deploy the Prowler custom role directly from the Azure Portal:

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fkourosh-forti-hands%2Fprowler%2Fmaster%2Fdocs%2Ftutorials%2Fazure%2Farm%2FsimplifiedTemplate.json)

## What This Deploys

This ARM template creates the **custom ProwlerRole** in your current subscription. This is only part of the complete setup - you'll still need to manually create the App Registration.

> **Note**: This simplified template creates the role in the current subscription only. For multi-subscription deployments, use the scripts method instead.

### Experiencing Deployment Errors?

If you encounter errors with the template deployment, you can also:

1. **Download the template directly**:
   ```bash
   curl -O https://raw.githubusercontent.com/kourosh-forti-hands/prowler/master/docs/tutorials/azure/arm/simplifiedTemplate.json
   ```

2. **Deploy using the Azure Portal**: 
   - Go to "Deploy a custom template"
   - Choose "Build your own template in the editor"
   - Load the downloaded file

### Created Resources

- Custom role definition: "ProwlerRole"
- Role permissions for additional read-only access needed by Prowler
- Role scoped to specified subscriptions

### Manual Steps Still Required

After deploying the template, you must complete these steps:

1. **Create App Registration**
   - Go to Azure AD > App registrations > New registration
   - Name: "Prowler Security Scanner"

2. **Add API Permissions**
   - Microsoft Graph: Domain.Read.All (Application)
   - Microsoft Graph: Policy.Read.All (Application)  
   - Microsoft Graph: UserAuthenticationMethod.Read.All (Application)

3. **Create Client Secret**
   - Go to Certificates & secrets > New client secret

4. **Grant Admin Consent**
   - Click "Grant admin consent" in API permissions

5. **Assign Roles**
   - Assign "Reader" role to service principal on subscriptions
   - Assign "ProwlerRole" to service principal on subscriptions

## Alternative: Fully Automated Setup

For a completely automated setup with zero manual steps, use the **Azure CLI scripts** instead:

```bash
cd docs/tutorials/azure/scripts/
./setup-prowler.sh
```

This approach is recommended as it eliminates all manual configuration.