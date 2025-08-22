# Azure Authentication in Prowler

Prowler for Azure supports multiple authentication types. To use a specific method, pass the appropriate flag during execution:

- [**Service Principal Application**](https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals?tabs=browser#service-principal-object) (**Recommended**)
- Existing **AZ CLI credentials**
- **Interactive browser authentication**
- [**Managed Identity**](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview) authentication

> ⚠️ **Important:** For Prowler App, only Service Principal authentication is supported.

### Service Principal Application Authentication

Enable Prowler authentication using a Service Principal Application by setting up the following environment variables:

```console
export AZURE_CLIENT_ID="XXXXXXXXX"
export AZURE_TENANT_ID="XXXXXXXXX"
export AZURE_CLIENT_SECRET="XXXXXXX"
```

Execution with the `--sp-env-auth` flag fails if these variables are not set or exported.

Refer to the [Create Prowler Service Principal](create-prowler-service-principal.md#how-to-create-prowler-service-principal-application) guide for detailed setup instructions.

### Azure Authentication Methods

Prowler for Azure supports the following authentication methods:

- **AZ CLI Authentication (`--az-cli-auth`)** – Automated authentication using stored AZ CLI credentials.
- **Managed Identity Authentication (`--managed-identity-auth`)** – Automated authentication via Azure Managed Identity.
- **Browser Authentication (`--browser-auth`)** – Requires the user to authenticate using the default browser. The `tenant-id` parameter is mandatory for this method.

### Required Permissions

Prowler for Azure requires two types of permission scopes:

#### Microsoft Entra ID Permissions

These permissions allow Prowler to retrieve metadata from the assumed identity and perform specific Entra checks. While not mandatory for execution, they enhance functionality.

Required permissions:

- `Directory.Read.All`
- `Policy.Read.All`
- `UserAuthenticationMethod.Read.All` (used for Entra multifactor authentication checks)

    ???+ note
        Replace `Directory.Read.All` with `Domain.Read.All` for more restrictive permissions. Note that Entra checks related to DirectoryRoles and GetUsers will not run with this permission.


#### Subscription Scope Permissions

These permissions are required to perform security checks against Azure resources. The following **RBAC roles** must be assigned per subscription to the entity used by Prowler:

- `Reader` – Grants read-only access to Azure resources.
- `ProwlerRole` – A custom role with minimal permissions, defined in the [prowler-azure-custom-role](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-azure-custom-role.json).

???+ note
    The `assignableScopes` field in the JSON custom role file must be updated to reflect the correct subscription or management group. Use one of the following formats: `/subscriptions/<subscription-id>` or `/providers/Microsoft.Management/managementGroups/<management-group-id>`.

### Assigning Permissions

To properly configure permissions, follow these guides:

- [Microsoft Entra ID permissions](create-prowler-service-principal.md#assigning-the-proper-permissions)
- [Azure subscription permissions](subscriptions.md#assign-the-appropriate-permissions-to-the-identity-that-is-going-to-be-assumed-by-prowler)

???+ warning
     Some permissions in `ProwlerRole` involve **write access**. If a `ReadOnly` lock is attached to certain resources, you may encounter errors, and findings for those checks will not be available.

#### Checks Requiring `ProwlerRole`

The following security checks require the `ProwlerRole` permissions for execution. Ensure the role is assigned to the identity assumed by Prowler before running these checks:

- `app_function_access_keys_configured`
- `app_function_ftps_deployment_disabled`
