# How to create Prowler Service Principal Application

To allow Prowler assume an identity to start the scan with the required privileges is necesary to create a Service Principal. This Service Principal is going to be used to authenticate against Azure and retrieve the metadata needed to perform the checks.

To create a Service Principal Application you can use the Azure Portal or the Azure CLI.

## From Azure Portal / Entra Admin Center

1. Access to Microsoft Entra ID
2. In the left menu bar, go to "App registrations"
3. Once there, in the menu bar click on "+ New registration" to register a new application
4. Fill the "Name, select the "Supported account types" and click on "Register. You will be redirected to the applications page.
5. Once in the application page, in the left menu bar, select "Certificates & secrets"
6. In the "Certificates & secrets" view, click on "+ New client secret"
7. Fill the "Description" and "Expires" fields and click on "Add"
8. Copy the value of the secret, it is going to be used as `AZURE_CLIENT_SECRET` environment variable.

![Register an Application page](../img/create-sp.gif)

## From Azure CLI

To create a Service Principal using the Azure CLI, follow the next steps:

1. Open a terminal and execute the following command to create a new Service Principal application:
```console
az ad sp create-for-rbac --name "ProwlerApp"
```
2. The output of the command is going to be similar to the following:
```json
{
"appId": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
"displayName": "ProwlerApp",
"password": "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
"tenant": "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
}
```
3. Save the values of `appId`, `password` and `tenant` to be used as credentials in Prowler.

# Assigning the proper permissions

To allow Prowler to retrieve metadata from the identity assumed and run specific Entra checks, it is needed to assign the following permissions:

- `Directory.Read.All`
- `Policy.Read.All`
- `UserAuthenticationMethod.Read.All` (used only for the Entra checks related with multifactor authentication)

To assign the permissions you can make it from the Azure Portal or using the Azure CLI.

???+ note
    Once you have created and assigned the proper Entra permissions to the application, you can go to this [tutorial](../azure/subscriptions.md) to add the subscription permissions to the application and start scanning your resources.

## From Azure Portal

1. Access to Microsoft Entra ID
2. In the left menu bar, go to "App registrations"
3. Once there, select the application that you have created
4. In the left menu bar, select "API permissions"
5. Then click on "+ Add a permission" and select "Microsoft Graph"
6. Once in the "Microsoft Graph" view, select "Application permissions"
7. Finally, search for "Directory", "Policy" and "UserAuthenticationMethod" select the following permissions:
    - `Directory.Read.All`
    - `Policy.Read.All`
    - `UserAuthenticationMethod.Read.All`
8. Click on "Add permissions" to apply the new permissions.
9. Finally, an admin should click on "Grant admin consent for [your tenant]" to apply the permissions.


![EntraID Permissions](../../img/AAD-permissions.png)

## From Azure CLI

1. Open a terminal and execute the following command to assign the permissions to the Service Principal:
```console
az ad app permission add --id {appId} --api 00000003-0000-0000-c000-000000000000 --api-permissions 7ab1d382-f21e-4acd-a863-ba3e13f7da61=Role 246dd0d5-5bd0-4def-940b-0421030a5b68=Role 38d9df27-64da-44fd-b7c5-a6fbac20248f=Role
```
2. The admin consent is needed to apply the permissions, an admin should execute the following command:
```console
az ad app permission admin-consent --id {appId}
```
