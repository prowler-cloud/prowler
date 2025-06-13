# Azure Subscription Scope

Prowler performs security scans within the subscription scope in Azure. To execute checks, it requires appropriate permissions to access the subscription and retrieve necessary metadata.

By default, Prowler operates multi-subscription, scanning all subscriptions it has permission to list. If permissions are granted for only a single subscription, Prowler will limit scans to that subscription.

## Configuring Specific Subscription Scans in Prowler

Additionally, Prowler supports restricting scans to specific subscriptions by passing a set of subscription IDs as an input argument. To configure this limitation, use the appropriate command options:

```console
prowler azure --az-cli-auth --subscription-ids <subscription ID 1> <subscription ID 2> ... <subscription ID N>
```

Prowler allows you to specify one or more subscriptions for scanning (up to N), enabling flexible audit configurations.

???+ warning
    The multi-subscription feature is available only in the CLI. In Prowler App, each scan is limited to a single subscription.

## Assigning Permissions for Subscription Scans

To perform scans, ensure that the identity assumed by Prowler has the appropriate permissions.

By default, Prowler scans all accessible subscriptions. If you need to audit specific subscriptions, you must assign the necessary role `Reader` for each one. For streamlined and less repetitive role assignments in multi-subscription environments, refer to the [following section](#recommendation-for-multiple-subscriptions).

### Assigning the Reader Role in Azure Portal

1. To grant Prowler access to scan a specific Azure subscription, follow these steps in Azure Portal:
Navigate to the subscription you want to audit with Prowler.

2. In the left menu, select “Access control (IAM)”.

3. Click “+ Add” and select “Add role assignment”.

4. In the search bar, enter `Reader`, select it and click “Next”.

5. In the “Members” tab, click “+ Select members”, then add the accounts to assign this role.

6. Click “Review + assign” to finalize and apply the role assignment.

![Adding the Reader Role to a Subscription](../../img/add-reader-role.gif)

### From Azure CLI

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

### Prowler Custom Role

Some read-only permissions required for specific security checks are not included in the built-in Reader role. To support these checks, Prowler utilizes a custom role, defined in [prowler-azure-custom-role](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-azure-custom-role.json). Once created, this role can be assigned following the same process as the `Reader` role.

The checks requiring this `ProwlerRole` can be found in the [requirements section](../../getting-started/requirements.md#checks-that-require-prowlerrole).

#### Create ProwlerRole via Azure Portal

1. Download the [prowler-azure-custom-role](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-azure-custom-role.json) file and modify the `assignableScopes` field to match the target subscription. Example format: `/subscriptions/XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`.

2. Access your Azure subscription.

3. Select “Access control (IAM)”.

4. Click “+ Add” and select “Add custom role”.

5. Under “Baseline permissions”, select “Start from JSON” and upload the modified role file.

6. Click “Review + create” to finalize the role creation.

#### Create ProwlerRole via Azure CLI

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

## Recommendation for Managing Multiple Subscriptions

Scanning multiple subscriptions requires creating and assigning roles for each, which can be a time-consuming process. To streamline subscription management and auditing, use management groups in Azure. This approach allows Prowler to efficiently organize and audit multiple subscriptions collectively.

1. **Create a Management Group**: Follow the [official guide](https://learn.microsoft.com/en-us/azure/governance/management-groups/create-management-group-portal) to create a new management group.
![Create management group](../../img/create-management-group.gif)

2. **Assign Roles**: Assign necessary roles to the management group, similar to the [role assignment process](#assign-the-appropriate-permissions-to-the-identity-that-is-going-to-be-assumed-by-prowler).

Role assignment should be done at the management group level instead of per subscription.

3. **Add Subscriptions**: Add all subscriptions you want to audit to the newly created management group. ![Add Subscription to Management Group](../../img/add-sub-to-management-group.gif)
