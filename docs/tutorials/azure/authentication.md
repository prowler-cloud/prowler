# Azure Authentication in Prowler

Prowler for Azure supports multiple authentication types. Authentication methods vary between Prowler App and Prowler CLI:

**Prowler App:**

- [**Service Principal Application**](#service-principal-application-authentication-recommended)

**Prowler CLI:**

- [**Service Principal Application**](#service-principal-application-authentication-recommended) (**Recommended**)
- [**AZ CLI credentials**](#az-cli-authentication)
- [**Interactive browser authentication**](#browser-authentication)
- [**Managed Identity Authentication**](#managed-identity-authentication)

## Required Permissions

Prowler for Azure requires two types of permission scopes:

### Microsoft Entra ID Permissions

These permissions allow Prowler to retrieve metadata from the assumed identity and perform specific Entra checks. While not mandatory for execution, they enhance functionality.

#### Assigning Required API Permissions

Assign the following Microsoft Graph permissions:

- `Directory.Read.All`
- `Policy.Read.All`
- `UserAuthenticationMethod.Read.All` (optional, for multifactor authentication (MFA) checks)

???+ note
    Replace `Directory.Read.All` with `Domain.Read.All` for more restrictive permissions. Note that Entra checks related to DirectoryRoles and GetUsers will not run with this permission.

1. Go to your App Registration > "API permissions"

    ![API Permission Page](./img/api-permissions-page.png)

2. Click "+ Add a permission" > "Microsoft Graph" > "Application permissions"

    ![Add API Permission](./img/add-api-permission.png)
    ![Microsoft Graph Detail](./img/microsoft-graph-detail.png)

3. Search and select:

    - `Directory.Read.All`
    - `Policy.Read.All`
    - `UserAuthenticationMethod.Read.All`

    ![Permission Screenshots](./img/domain-permission.png)

4. Click "Add permissions", then grant admin consent

    ![Grant Admin Consent](./img/grant-admin-consent.png)


### Subscription Scope Permissions

These permissions are required to perform security checks against Azure resources. The following **RBAC roles** must be assigned per subscription to the entity used by Prowler:

- `Reader` – Grants read-only access to Azure resources.
- `ProwlerRole` – A custom role with minimal permissions needed for some specific checks, defined in the [prowler-azure-custom-role](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-azure-custom-role.json).


#### Assigning "Reader" Role at the Subscription Level
By default, Prowler scans all accessible subscriptions. If you need to audit specific subscriptions, you must assign the necessary role `Reader` for each one. For streamlined and less repetitive role assignments in multi-subscription environments, refer to the [following section](subscriptions.md#recommendation-for-managing-multiple-subscriptions).

=== "Azure Portal"

  1. To grant Prowler access to scan a specific Azure subscription, follow these steps in Azure Portal:
  Navigate to the subscription you want to audit with Prowler.

  1. In the left menu, select “Access control (IAM)”.

  2. Click “+ Add” and select “Add role assignment”.

  3. In the search bar, enter `Reader`, select it and click “Next”.

  4. In the “Members” tab, click “+ Select members”, then add the accounts to assign this role.

  5. Click “Review + assign” to finalize and apply the role assignment.

  ![Adding the Reader Role to a Subscription](../../img/add-reader-role.gif)

=== "Azure CLI"

  1. Open a terminal and execute the following command to assign the `Reader` role to the identity that is going to be assumed by Prowler:

      ```console
      az role assignment create --role "Reader" --assignee <user, group, or service principal> --scope /subscriptions/<subscription-id>
      ```

  2. If the command is executed successfully, the output is going to be similar to the following:

      ```json
      {
          "condition": null,
          "conditionVersion": null,
          "createdBy": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
          "createdOn": "YYYY-MM-DDTHH:MM:SS.SSSSSS+00:00",
          "delegatedManagedIdentityResourceId": null,
          "description": null,
          "id": "/subscriptions/XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX/providers/Microsoft.Authorization/roleAssignments/XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
          "name": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
          "principalId": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
          "principalName": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
          "principalType": "ServicePrincipal",
          "roleDefinitionId": "/subscriptions/XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX/providers/Microsoft.Authorization/roleDefinitions/XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
          "roleDefinitionName": "Reader",
          "scope": "/subscriptions/XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
          "type": "Microsoft.Authorization/roleAssignments",
          "updatedBy": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
          "updatedOn": "YYYY-MM-DDTHH:MM:SS.SSSSSS+00:00"
      }
      ```

#### Assigning "ProwlerRole" Permissions at the Subscription Level

Some read-only permissions required for specific security checks are not included in the built-in Reader role. To support these checks, Prowler utilizes a custom role, defined in [prowler-azure-custom-role](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-azure-custom-role.json). Once created, this role can be assigned following the same process as the `Reader` role.

The checks requiring this `ProwlerRole` can be found in this [section](../../tutorials/azure/authentication.md#checks-requiring-prowlerrole).

=== "Azure Portal"

    1. Download the [Prowler Azure Custom Role](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-azure-custom-role.json)

        ![Azure Custom Role](./img/download-prowler-role.png)

    2. Modify `assignableScopes` to match your Subscription ID (e.g. `/subscriptions/xxxx-xxxx-xxxx-xxxx`)

    3. Go to your Azure Subscription > "Access control (IAM)"

        ![IAM Page](./img/iam-azure-page.png)

    4. Click "+ Add" > "Add custom role", choose "Start from JSON" and upload the modified file

        ![Add custom role via JSON](./img/add-custom-role-json.png)

    5. Click "Review + Create" to finish

        ![Select review and create](./img/review-and-create.png)

    6. Return to "Access control (IAM)" > "+ Add" > "Add role assignment"

        - Assign the `Reader` role to the Application created in the previous step
        - Then repeat the same process assigning the custom `ProwlerRole`

        ![Role Assignment](./img/add-role-assigment.png)

    ???+ note
        The `assignableScopes` field in the JSON custom role file must be updated to reflect the correct subscription or management group. Use one of the following formats: `/subscriptions/<subscription-id>` or `/providers/Microsoft.Management/managementGroups/<management-group-id>`.

=== "Azure CLI"

1. To create a new custom role, open a terminal and execute the following command:

    ```console
    az role definition create --role-definition '{                                                                                                                   640ms  lun 16 dic 17:04:17 2024
                        "Name": "ProwlerRole",
                        "IsCustom": true,
                        "Description": "Role used for checks that require read-only access to Azure resources and are not covered by the Reader role.",
                        "AssignableScopes": [
                        "/subscriptions/XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX" // USE YOUR SUBSCRIPTION ID
                        ],
                        "Actions": [
                        "Microsoft.Web/sites/host/listkeys/action",
                        "Microsoft.Web/sites/config/list/Action"
                        ]
                    }'
    ```

2. If the command is executed successfully, the output is going to be similar to the following:

    ```json
    {
        "assignableScopes": [
            "/subscriptions/XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
        ],
        "createdBy": null,
        "createdOn": "YYYY-MM-DDTHH:MM:SS.SSSSSS+00:00",
        "description": "Role used for checks that require read-only access to Azure resources and are not covered by the Reader role.",
        "id": "/subscriptions/XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX/providers/Microsoft.Authorization/roleDefinitions/XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
        "name": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
        "permissions": [
            {
                "actions": [
                    "Microsoft.Web/sites/host/listkeys/action",
                    "Microsoft.Web/sites/config/list/Action"
                ],
                "condition": null,
                "conditionVersion": null,
                "dataActions": [],
                "notActions": [],
                "notDataActions": []
            }
        ],
        "roleName": "ProwlerRole",
        "roleType": "CustomRole",
        "type": "Microsoft.Authorization/roleDefinitions",
        "updatedBy": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
        "updatedOn": "YYYY-MM-DDTHH:MM:SS.SSSSSS+00:00"
    }
    ```

### Additional Resources

For more detailed guidance on subscription management and permissions:

- [Azure subscription permissions](subscriptions.md)
- [Create Prowler Service Principal](create-prowler-service-principal.md)

???+ warning
     Some permissions in `ProwlerRole` involve **write access**. If a `ReadOnly` lock is attached to certain resources, you may encounter errors, and findings for those checks will not be available.

#### Checks Requiring `ProwlerRole`

The following security checks require the `ProwlerRole` permissions for execution. Ensure the role is assigned to the identity assumed by Prowler before running these checks:

- `app_function_access_keys_configured`
- `app_function_ftps_deployment_disabled`

---

## Service Principal Application Authentication (Recommended)

This method is required for Prowler App and recommended for Prowler CLI.

### Creating the Service Principal

1. Access Microsoft Entra ID.
2. In the left menu bar, navigate to **"App registrations"**.
3. Click **"+ New registration"** in the menu bar to register a new application
4. Fill the **"Name"**, select the **"Supported account types"** and click **"Register"**. You will be redirected to the applications page.
5. In the left menu bar, select **"Certificates & secrets"**.
6. Under the **"Certificates & secrets"** view, click **"+ New client secret"**.
7. Fill the **"Description"** and **"Expires"** fields, then click **"Add"**.
8. Copy the secret value, as it will be used as `AZURE_CLIENT_SECRET` environment variable.

![Registering an Application in Azure CLI for Prowler](../img/create-sp.gif)

For more information, see [Creating Prowler Service Principal](create-prowler-service-principal.md).

### Environment Variables (CLI)

For Prowler CLI, set up the following environment variables:

```console
export AZURE_CLIENT_ID="XXXXXXXXX"
export AZURE_TENANT_ID="XXXXXXXXX"
export AZURE_CLIENT_SECRET="XXXXXXX"
```

Execution with the `--sp-env-auth` flag fails if these variables are not set or exported.

## AZ CLI Authentication

*Available only for Prowler CLI*

Use stored Azure CLI credentials:

```console
prowler azure --az-cli-auth
```

## Managed Identity Authentication

*Available only for Prowler CLI*

Authenticate via Azure Managed Identity (when running on Azure resources):

```console
prowler azure --managed-identity-auth
```

## Browser Authentication

*Available only for Prowler CLI*

Authenticate using the default browser:

```console
prowler azure --browser-auth --tenant-id <tenant-id>
```

> **Note:** The `tenant-id` parameter is mandatory for browser authentication.
