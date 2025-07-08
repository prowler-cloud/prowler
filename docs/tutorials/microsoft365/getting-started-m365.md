# Getting Started with M365 on Prowler Cloud/App

Set up your M365 account to enable security scanning using Prowler Cloud/App.

## Requirements

To configure your M365 account, you'll need:

1. Obtain a domain from the Entra ID portal.

2. Access Prowler Cloud/App and add a new cloud provider `Microsoft 365`.

3. Configure your M365 account:

    3.1 Create the Service Principal app.

    3.2 Grant the required API permissions.

    3.3 Assign the required roles to your user.

4. Add the credentials to Prowler Cloud/App.

## Step 1: Obtain your Domain

Go to the Entra ID portal, then you can search for `Domain` or go to Identity > Settings > Domain Names.

![Search Domain Names](./img/search-domain-names.png)

<br>

![Custom Domain Names](./img/custom-domain-names.png)

Once you are there just select the domain you want to use as unique identifier for your M365 account in Prowler Cloud/App.

---

## Step 2: Access Prowler Cloud/App

1. Go to [Prowler Cloud](https://cloud.prowler.com/) or launch [Prowler App](../prowler-app.md)
2. Navigate to `Configuration` > `Cloud Providers`

    ![Cloud Providers Page](../img/cloud-providers-page.png)

3. Click on `Add Cloud Provider`

    ![Add a Cloud Provider](../img/add-cloud-provider.png)

4. Select `Microsoft 365`

    ![Select Microsoft 365](./img/select-m365-prowler-cloud.png)

5. Add the Domain ID and an optional alias, then click `Next`

    ![Add Domain ID](./img/add-domain-id.png)

---

## Step 3: Configure your M365 account


### Create the Service Principal app

A Service Principal is required to grant Prowler the necessary privileges.

1. Access **Microsoft Entra ID**

    ![Overview of Microsoft Entra ID](./img/microsoft-entra-id.png)

2. Navigate to `Applications` > `App registrations`

    ![App Registration nav](./img/app-registration-menu.png)

3. Click `+ New registration`, complete the form, and click `Register`

    ![New Registration](./img/new-registration.png)

4. Go to `Certificates & secrets` > `Client secrets` > `+ New client secret`

    ![Certificate & Secrets nav](./img/certificates-and-secrets.png)

5. Fill in the required fields and click `Add`, then copy the generated `value` (that value will be `AZURE_CLIENT_SECRET`)

    ![New Client Secret](./img/new-client-secret.png)

With this done you will have all the needed keys, summarized in the following table

| Value | Description |
|-------|-------------|
| Client ID | Application (client) ID |
| Client Secret | AZURE_CLIENT_SECRET |
| Tenant ID | Directory (tenant) ID |

---

### Grant required Graph API permissions

Assign the following Microsoft Graph permissions:

- `AuditLog.Read.All`: Required for Entra service.
- `Directory.Read.All`: Required for all services.
- `Policy.Read.All`: Required for all services.
- `SharePointTenantSettings.Read.All`: Required for SharePoint service.
- `User.Read` (IMPORTANT: this is set as **delegated**): Required for the sign-in only if using user authentication.

???+ note
    You can replace `Directory.Read.All` with `Domain.Read.All` is a more restrictive permission but you won't be able to run the Entra checks related with DirectoryRoles and GetUsers.

    > If you do this you will need to add also the `Organization.Read.All` permission to the service principal application in order to authenticate.

Follow these steps to assign the permissions:

1. Go to your App Registration > Select your Prowler App created before > click on `API permissions`

    ![API Permission Page](./img/api-permissions-page.png)

2. Click `+ Add a permission` > `Microsoft Graph` > `Application permissions`

    ![Add API Permission](./img/add-app-api-permission.png)

3. Search and select every permission below and once all are selected click on `Add permissions`:
    - `AuditLog.Read.All`: Required for Entra service.
    - `Directory.Read.All`
    - `Policy.Read.All`
    - `SharePointTenantSettings.Read.All`


    ![Permission Screenshots](./img/directory-permission.png)

    ![Application Permissions](./img/app-permissions.png)

---


### Grant PowerShell modules permissions

The permissions you need to grant depends on whether you are using user credentials or service principal to authenticate to the M365 modules.

???+ warning "Warning"
    Make sure you add the correct set of permissions for the authentication method you are using.


#### If using application(service principal) authentication (Recommended)

To grant the permissions for the PowerShell modules via application authentication, you need to add the necessary APIs to your app registration.

???+ warning "Warning"
    You need to have a license that allows you to use the APIs.

1. Add Exchange API:

    - Search and select`Office 365 Exchange Online` API in **APIs my organization uses**.

    ![Office 365 Exchange Online API](./img/search-exchange-api.png)

    - Select `Exchange.ManageAsApp` permission and click on `Add permissions`.

    ![Exchange.ManageAsApp Permission](./img/exchange-permission.png)

    You also need to assign the `Exchange Administrator` role to the app. For that go to `Roles and administrators` and in the `Administrative roles` section click `here` to go to the directory level assignment:

    ![Roles and administrators](./img/here.png)

    Once in the directory level assignment, search for `Exchange Administrator` and click on it to open the assginments page of that role.

    ![Exchange Administrator Role](./img/exchange-administrator-role.png)

    Click on `Add assignments`, search for your app and click on `Assign`.

    You have to select it as `Active` and click on `Assign` to assign the role to the app.

    ![Assign Exchange Administrator Role](./img/assign-exchange-administrator-role.png)

2. Add Teams API:

    - Search and select `Skype and Teams Tenant Admin API` API in **APIs my organization uses**.

    ![Skype and Teams Tenant Admin API](./img/search-skype-teams-tenant-admin-api.png)

    - Select `application_access` permission and click on `Add permissions`.

    ![application_access Permission](./img/teams-permission.png)

3. Click on `Grant admin consent for <your-tenant-name>` to grant admin consent.

    ![Grant Admin Consent](./img/grant-external-api-permissions.png)

    The final result of permission assignment should be this:

    ![Final Permission Assignment](./img/final-permissions.png)

---

#### If using user authentication

This method is not recommended because it requires a user with MFA enabled and Microsoft will not allow MFA capable users to authenticate programmatically after 1st September 2025. See [Microsoft documentation](https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication?tabs=dotnet) for more information.

???+ warning
    Remember that if the user is newly created, you need to sign in with that account first, as Microsoft will prompt you to change the password. If you don’t complete this step, user authentication will fail because Microsoft marks the initial password as expired.


1. Search and select:

    - `User.Read`

    ![Permission Screenshots](./img/directory-permission-delegated.png)

2. Click `Add permissions`, then **grant admin consent**

    ![Grant Admin Consent](./img/grant-admin-consent.png)

    The final result of permission assignment should be this:

    ![Final Permission Assignment](./img/final-permissions-m365.png)

3. Assign **required roles** to your **user**

    Assign one of the following roles to your User:

    - `Global Reader` (recommended): this allows you to read all roles needed.
    - `Exchange Administrator` and `Teams Administrator`: user needs both roles but with this [roles](https://learn.microsoft.com/en-us/exchange/permissions-exo/permissions-exo#microsoft-365-permissions-in-exchange-online) you can access to the same information as a Global Reader (here you only read so that's why we recomend that role).

    Follow these steps to assign the role:

    1. Go to Users > All Users > Click on the email for the user you will use

        ![User Overview](./img/user-info-page.png)

    2. Click `Assigned Roles`

        ![User Roles](./img/user-role-page.png)

    3. Click on `Add assignments`, then search and select:

        - `Global Reader` This is the recommended, if you want to use the others just search for them

        ![Global Reader Screenshots](./img/global-reader.png)

    4. Click on next, then assign the role as `Active`, and click on `Assign` to grant admin consent

        ![Grant Admin Consent for Role](./img/grant-admin-consent-for-role.png)

---

## Step 4: Add credentials to Prowler Cloud/App

1. Go to your App Registration overview and copy the `Client ID` and `Tenant ID`

    ![App Overview](./img/app-overview.png)


2. Go to Prowler Cloud/App and paste:

    - `Client ID`
    - `Tenant ID`
    - `AZURE_CLIENT_SECRET` from earlier

    If you are using user authentication, also add:
    - `M365_USER` the user using the correct assigned domain, more info [here](../../getting-started/requirements.md#service-principal-and-user-credentials-authentication-recommended)
    - `M365_PASSWORD` the password of the user

    ![Prowler Cloud M365 Credentials](./img/m365-credentials.png)

3. Click `Next`

    ![Next Detail](./img/click-next-m365.png)

4. Click `Launch Scan`

    ![Launch Scan M365](./img/launch-scan.png)
