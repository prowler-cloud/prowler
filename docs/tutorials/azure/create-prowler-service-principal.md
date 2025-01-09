# How to create Prowler Service Principal

To allow Prowler assume an identity to start the scan with the required privileges is necesary to create a Service Principal. To create one follow the next steps:

1. Access to Microsoft Entra ID
2. In the left menu bar, go to "App registrations"
3. Once there, in the menu bar click on "+ New registration" to register a new application
4. Fill the "Name, select the "Supported account types" and click on "Register. You will be redirected to the applications page.
5. Once in the application page, in the left menu bar, select "Certificates & secrets"
6. In the "Certificates & secrets" view, click on "+ New client secret"
7. Fill the "Description" and "Expires" fields and click on "Add"
8. Copy the value of the secret, it is going to be used as `AZURE_CLIENT_SECRET` environment variable.

![Register an Application page](../img/create-sp.gif)

## Assigning the proper permissions

To allow Prowler to retrieve metadata from the identity assumed and specific Entra checks, it is needed to assign the following permissions:

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
9. Finally, click on "Grant admin consent for [your tenant]" to apply the permissions.


![EntraID Permissions](../../img/AAD-permissions.png)
