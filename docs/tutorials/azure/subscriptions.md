# Azure subscriptions scope

The main target for performing the scans in Azure is the subscription scope. Prowler needs to have the proper permissions to access the subscription and retrieve the metadata needed to perform the checks.

By default, Prowler is multi-subscription, which means that is going to scan all the subscriptions is able to list. If you only assign permissions to one subscription, it is going to scan a single one.
Prowler also has the ability to limit the subscriptions to scan to a set passed as input argument, to do so:

```console
prowler azure --az-cli-auth --subscription-ids <subscription ID 1> <subscription ID 2> ... <subscription ID N>
```

Where you can pass from 1 up to N subscriptions to be scanned.

???+ warning
    The multi-subscription feature is only available for the CLI, in the case of Prowler App is only possible to scan one subscription per scan.

## Assign the appropriate permissions to the identity that is going to be assumed by Prowler


Regarding the subscription scope, Prowler, by default, scans all subscriptions it can access. Therefore, it is necessary to add a `Reader` role assignment for each subscription you want to audit. To make it easier and less repetitive to assign roles in environments with multiple subscriptions check the [following section](#recommendation-for-multiple-subscriptions).

### From Azure Portal

1. Access to the subscription you want to scan with Prowler.
2. Select "Access control (IAM)" in the left menu.
3. Click on "+ Add" and select "Add role assignment".
4. In the search bar, type `Reader`, select it and click on "Next".
5. In the Members tab, click on "+ Select members" and add the members you want to assign this role.
6. Click on "Review + assign" to apply the new role.

![Add reader role to subscription](../../img/add-reader-role.gif)

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

Moreover, some additional read-only permissions not included in the built-in reader role are needed for some checks, for this kind of checks we use a custom role. This role is defined in [prowler-azure-custom-role](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-azure-custom-role.json). Once the custom role is created you can assign it in the same way as the `Reader` role.

The checks that needs the `ProwlerRole` can be consulted in the [requirements section](../../getting-started/requirements.md#checks-that-require-prowlerrole).

#### Create ProwlerRole from Azure Portal

1. Download the [prowler-azure-custom-role](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-azure-custom-role.json) file and modify the `assignableScopes` field to be the subscription ID where the role assignment is going to be made, it should be shomething like `/subscriptions/XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX`.
2. Access your subscription.
3. Select "Access control (IAM)".
4. Click on "+ Add" and select "Add custom role".
5. In the "Baseline permissions" select "Start from JSON" and upload the file downloaded and modified in the step 1.
7. Click on "Review + create" to create the new role.

#### Create ProwlerRole from Azure CLI

1. Open a terminal and execute the following command to create a new custom role:
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
3. If the command is executed successfully, the output is going to be similar to the following:
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

## Recommendation for multiple subscriptions

Scanning multiple subscriptions can be tedious due to the need to create and assign roles for each one. To simplify this process, we recommend using management groups to organize and audit subscriptions collectively with Prowler.

1. **Create a Management Group**: Follow the [official guide](https://learn.microsoft.com/en-us/azure/governance/management-groups/create-management-group-portal) to create a new management group.
![Create management group](../../img/create-management-group.gif)
2. **Add all roles**: Assign roles at to the new management group like in the [past section](#assign-the-appropriate-permissions-to-the-identity-that-is-going-to-be-assumed-by-prowler) but at the management group level instead of the subscription level.
3. **Add subscriptions**: Add all the subscriptions you want to audit to the management group.
![Add subscription to management group](../../img/add-sub-to-management-group.gif)
