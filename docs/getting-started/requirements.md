# Prowler Requirements



## Azure

Prowler for Azure supports multiple authentication types. To use a specific method, pass the appropriate flag during execution:

- [**Service Principal Application**](https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals?tabs=browser#service-principal-object) (**Recommended**)
- Existing **AZ CLI credentials**
- **Interactive browser authentication**
- [**Managed Identity**](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview) authentication

> ⚠️ **Important:** For Prowler App, only Service Principal authentication is supported.

### Service Principal Application Authentication

To allow Prowler to authenticate using a Service Principal Application, set up the following environment variables:

```console
export AZURE_CLIENT_ID="XXXXXXXXX"
export AZURE_TENANT_ID="XXXXXXXXX"
export AZURE_CLIENT_SECRET="XXXXXXX"
```

If you execute Prowler with the `--sp-env-auth` flag and these variables are not set or exported, execution will fail.

Refer to the [Create Prowler Service Principal](../tutorials/azure/create-prowler-service-principal.md#how-to-create-prowler-service-principal-application) guide for detailed setup instructions.

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
        You can replace `Directory.Read.All` with `Domain.Read.All` that is a more restrictive permission but you won't be able to run the Entra checks related with DirectoryRoles and GetUsers.


#### Subscription Scope Permissions

These permissions are required to perform security checks against Azure resources. The following **RBAC roles** must be assigned per subscription to the entity used by Prowler:

- `Reader` – Grants read-only access to Azure resources.
- `ProwlerRole` – A custom role with minimal permissions, defined in the [prowler-azure-custom-role](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-azure-custom-role.json).

???+ note
    The `assignableScopes` field in the JSON custom role file must be updated to reflect the correct subscription or management group. Use one of the following formats: `/subscriptions/<subscription-id>` or `/providers/Microsoft.Management/managementGroups/<management-group-id>`.

### Assigning Permissions

To properly configure permissions, follow these guides:

- [Microsoft Entra ID permissions](../tutorials/azure/create-prowler-service-principal.md#assigning-the-proper-permissions)
- [Azure subscription permissions](../tutorials/azure/subscriptions.md#assign-the-appropriate-permissions-to-the-identity-that-is-going-to-be-assumed-by-prowler)

???+ warning
     Some permissions in `ProwlerRole` involve **write access**. If a `ReadOnly` lock is attached to certain resources, you may encounter errors, and findings for those checks will not be available.

#### Checks Requiring `ProwlerRole`

The following security checks require the `ProwlerRole` permissions for execution. Ensure the role is assigned to the identity assumed by Prowler before running these checks:

- `app_function_access_keys_configured`
- `app_function_ftps_deployment_disabled`

## Google Cloud

### Authentication

Prowler follows the same credential discovery process as the [Google authentication libraries](https://cloud.google.com/docs/authentication/application-default-credentials#search_order):

1. **Environment Variable Authentication** – Uses the [`GOOGLE_APPLICATION_CREDENTIALS` environment variable](https://cloud.google.com/docs/authentication/application-default-credentials#GAC).
2. **Google Cloud CLI Credentials** – Uses credentials configured via the [Google Cloud CLI](https://cloud.google.com/docs/authentication/application-default-credentials#personal).
3. **Service Account Authentication** – Retrieves the attached service account credentials from the metadata server. More details [here](https://cloud.google.com/docs/authentication/application-default-credentials#attached-sa).

### Required Permissions

Prowler for Google Cloud requires the following permissions:

#### IAM Roles
- **Reader (`roles/reader`)** – Must be granted at the **project, folder, or organization** level to allow scanning of target projects.

#### Project-Level Settings

At least one project must have the following configurations:

- **Identity and Access Management (IAM) API (`iam.googleapis.com`)** – Must be enabled via:

    - The [Google Cloud API UI](https://console.cloud.google.com/apis/api/iam.googleapis.com/metrics), or
    - The `gcloud` CLI:
    ```sh
    gcloud services enable iam.googleapis.com --project <your-project-id>
    ```

- **Service Usage Consumer (`roles/serviceusage.serviceUsageConsumer`)** IAM Role – Required for resource scanning.

- **Quota Project Setting** – Define a quota project using either:

    - The `gcloud` CLI:
    ```sh
    gcloud auth application-default set-quota-project <project-id>
    ```
    - Setting an environment variable:
    ```sh
    export GOOGLE_CLOUD_QUOTA_PROJECT=<project-id>
    ```

### Default Project Scanning

By default, Prowler scans **all accessible GCP projects**. To limit the scan to specific projects, use the `--project-ids` flag.

## Microsoft 365

Prowler for Microsoft 365 (M365) supports the following authentication methods:

- [**Service Principal Application**](https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals?tabs=browser#service-principal-object) (**Recommended**)
- **Service Principal Application with Microsoft User Credentials**
- **Stored AZ CLI credentials**
- **Interactive browser authentication**

???+ warning
    Prowler App supports the **Service Principal** authentication method and the **Service Principal with User Credentials** authentication method, but this last one will be deprecated in September once Microsoft will enforce MFA in all tenants not allowing User authentication without interactive method.

### Service Principal Authentication (Recommended)

**Authentication flag:** `--sp-env-auth`

To enable Prowler to authenticate as the **Service Principal Application**, configure the following environment variables:

```console
export AZURE_CLIENT_ID="XXXXXXXXX"
export AZURE_CLIENT_SECRET="XXXXXXXXX"
export AZURE_TENANT_ID="XXXXXXXXX"
```

If these variables are not set or exported, execution using `--sp-env-auth` will fail.

Refer to the [Create Prowler Service Principal](../tutorials/microsoft365/getting-started-m365.md#create-the-service-principal-app) guide for setup instructions.

If the external API permissions described in the mentioned section above are not added only checks that work through MS Graph will be executed. This means that the full provider will not be executed.

???+ note
    In order to scan all the checks from M365 required permissions to the service principal application must be added. Refer to the [External API Permissions Assignment](../tutorials/microsoft365/getting-started-m365.md#grant-powershell-modules-permissions) section for more information.

### Service Principal and User Credentials Authentication

Authentication flag: `--env-auth`

???+ warning
    This method is not recommended anymore, we recommend just use the **Service Principal Application** authentication method instead.

This method builds upon the Service Principal authentication by adding User Credentials. Configure the following environment variables: `M365_USER` and `M365_PASSWORD`.

```console
export AZURE_CLIENT_ID="XXXXXXXXX"
export AZURE_CLIENT_SECRET="XXXXXXXXX"
export AZURE_TENANT_ID="XXXXXXXXX"
export M365_USER="your_email@example.com"
export M365_PASSWORD="examplepassword"
```

These two new environment variables are **required** in this authentication method to execute the PowerShell modules needed to retrieve information from M365 services. Prowler uses Service Principal authentication to access Microsoft Graph and user credentials to authenticate to Microsoft PowerShell modules.

- `M365_USER` should be your Microsoft account email using the **assigned domain in the tenant**. This means it must look like `example@YourCompany.onmicrosoft.com` or `example@YourCompany.com`, but it must be the exact domain assigned to that user in the tenant.

    ???+ warning
        If the user is newly created, you need to sign in with that account first, as Microsoft will prompt you to change the password. If you don’t complete this step, user authentication will fail because Microsoft marks the initial password as expired.

    ???+ warning
        If the user is newly created, you need to sign in with that account first, as Microsoft will prompt you to change the password. If you don’t complete this step, user authentication will fail because Microsoft marks the initial password as expired.

    ???+ warning
        The user must not be MFA capable. Microsoft does not allow MFA capable users to authenticate programmatically. See [Microsoft documentation](https://learn.microsoft.com/en-us/entra/identity-platform/scenario-desktop-acquire-token-username-password?tabs=dotnet) for more information.

    ???+ warning
        Using a tenant domain other than the one assigned — even if it belongs to the same tenant — will cause Prowler to fail, as Microsoft authentication will not succeed.

    Ensure you are using the right domain for the user you are trying to authenticate with.

    ![User Domains](../tutorials/microsoft365/img/user-domains.png)

- `M365_PASSWORD` must be the user password.

    ???+ note
        Before we asked for a encrypted password, but now we ask for the user password directly. Prowler will now handle the password encryption for you.



### Interactive Browser Authentication

**Authentication flag:** `--browser-auth`

This authentication method requires the user to authenticate against Azure using the default browser to start the scan. The `--tenant-id` flag is also required.

With these credentials, you will only be able to run checks that rely on Microsoft Graph. This means you won't be able to run the entire provider. To perform a full M365 security scan, use the **recommended authentication method**.

Since this is a **delegated permission** authentication method, necessary permissions should be assigned to the user rather than the application.

### Required Permissions

To run the full Prowler provider, including PowerShell checks, two types of permission scopes must be set in **Microsoft Entra ID**.

#### For Service Principal Authentication (`--sp-env-auth`) - Recommended

When using service principal authentication, you need to add the following **Application Permissions** configured to:

**Microsoft Graph API Permissions:**

- `AuditLog.Read.All`: Required for Entra service.
- `Directory.Read.All`: Required for all services.
- `Policy.Read.All`: Required for all services.
- `SharePointTenantSettings.Read.All`: Required for SharePoint service.
- `User.Read` (IMPORTANT: this must be set as **delegated**): Required for the sign-in.

**External API Permissions:**

- `Exchange.ManageAsApp` from external API `Office 365 Exchange Online`: Required for Exchange PowerShell module app authentication. You also need to assign the `Global Reader` role to the app.
- `application_access` from external API `Skype and Teams Tenant Admin API`: Required for Teams PowerShell module app authentication.

???+ note
    `Directory.Read.All` can be replaced with `Domain.Read.All` that is a more restrictive permission but you won't be able to run the Entra checks related with DirectoryRoles and GetUsers.

    > If you do this you will need to add also the `Organization.Read.All` permission to the service principal application in order to authenticate.

???+ note
    This is the **recommended authentication method** because it allows you to run the full M365 provider including PowerShell checks, providing complete coverage of all available security checks, same as the Service Principal Authentication + User Credentials Authentication but this last one will be deprecated in September once Microsoft will enforce MFA in all tenants not allowing User authentication without interactive method.


#### For Service Principal + User Credentials Authentication (`--env-auth`)

When using service principal with user credentials authentication, you need **both** sets of permissions:

**1. Service Principal Application Permissions**:
- You **will need** all the Microsoft Graph API permissions listed above.
- You **won't need** the External API permissions listed above.

**2. User-Level Permissions**: These are set at the `M365_USER` level, so the user used to run Prowler must have one of the following roles:

- `Global Reader` (recommended): this allows you to read all roles needed.
- `Exchange Administrator` and `Teams Administrator`: user needs both roles but with this [roles](https://learn.microsoft.com/en-us/exchange/permissions-exo/permissions-exo#microsoft-365-permissions-in-exchange-online) you can access to the same information as a Global Reader (since only read access is needed, Global Reader is recommended).


#### For Browser Authentication (`--browser-auth`)

When using browser authentication, permissions are delegated to the user, so the user must have the appropriate permissions rather than the application.

???+ warning
    With browser authentication, you will only be able to run checks that work through MS Graph API. PowerShell module checks will not be executed.

### Assigning Permissions and Roles

For guidance on assigning the necessary permissions and roles, follow these instructions:
- [Grant API Permissions](../tutorials/microsoft365/getting-started-m365.md#grant-required-graph-api-permissions)
- [Assign Required Roles](../tutorials/microsoft365/getting-started-m365.md#if-using-user-authentication)

### Supported PowerShell Versions

PowerShell is required to run certain M365 checks.

**Supported versions:**
- **PowerShell 7.4 or higher** (7.5 is recommended)

#### Why Is PowerShell 7.4+ Required?

- **PowerShell 5.1** (default on some Windows systems) does not support required cmdlets.
- Older [cross-platform PowerShell versions](https://learn.microsoft.com/en-us/powershell/scripting/install/powershell-support-lifecycle?view=powershell-7.5) are **unsupported**, leading to potential errors.

???+ note
    Installing PowerShell is only necessary if you install Prowler via **pip or other sources**. **SDK and API containers include PowerShell by default.**

### Installing PowerShell

Installing PowerShell is different depending on your OS.

- [Windows](https://learn.microsoft.com/es-es/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.5#install-powershell-using-winget-recommended): you will need to update PowerShell to +7.4 to be able to run prowler, if not some checks will not show findings and the provider could not work as expected. This version of PowerShell is [supported](https://learn.microsoft.com/es-es/powershell/scripting/install/installing-powershell-on-windows?view=powershell-7.4#supported-versions-of-windows) on Windows 10, Windows 11, Windows Server 2016 and higher versions.

```console
winget install --id Microsoft.PowerShell --source winget
```


- [MacOS](https://learn.microsoft.com/es-es/powershell/scripting/install/installing-powershell-on-macos?view=powershell-7.5#install-the-latest-stable-release-of-powershell): installing PowerShell on MacOS needs to have installed [brew](https://brew.sh/), once you have it is just running the command above, Pwsh is only supported in macOS 15 (Sequoia) x64 and Arm64, macOS 14 (Sonoma) x64 and Arm64, macOS 13 (Ventura) x64 and Arm64

```console
brew install powershell/tap/powershell
```

Once it's installed run `pwsh` on your terminal to verify it's working.

- Linux: installing PowerShell on Linux depends on the distro you are using:

    - [Ubuntu](https://learn.microsoft.com/es-es/powershell/scripting/install/install-ubuntu?view=powershell-7.5#installation-via-package-repository-the-package-repository): The required version for installing PowerShell +7.4 on Ubuntu are Ubuntu 22.04 and Ubuntu 24.04. The recommended way to install it is downloading the package available on PMC. You just need to follow the following steps:

    ```console
    ###################################
    # Prerequisites

    # Update the list of packages
    sudo apt-get update

    # Install pre-requisite packages.
    sudo apt-get install -y wget apt-transport-https software-properties-common

    # Get the version of Ubuntu
    source /etc/os-release

    # Download the Microsoft repository keys
    wget -q https://packages.microsoft.com/config/ubuntu/$VERSION_ID/packages-microsoft-prod.deb

    # Register the Microsoft repository keys
    sudo dpkg -i packages-microsoft-prod.deb

    # Delete the Microsoft repository keys file
    rm packages-microsoft-prod.deb

    # Update the list of packages after we added packages.microsoft.com
    sudo apt-get update

    ###################################
    # Install PowerShell
    sudo apt-get install -y powershell

    # Start PowerShell
    pwsh
    ```

    - [Alpine](https://learn.microsoft.com/es-es/powershell/scripting/install/install-alpine?view=powershell-7.5#installation-steps): The only supported version for installing PowerShell +7.4 on Alpine is Alpine 3.20. The unique way to install it is downloading the tar.gz package available on [PowerShell github](https://github.com/PowerShell/PowerShell/releases/download/v7.5.0/powershell-7.5.0-linux-musl-x64.tar.gz). You just need to follow the following steps:

    ```console
    # Install the requirements
    sudo apk add --no-cache \
        ca-certificates \
        less \
        ncurses-terminfo-base \
        krb5-libs \
        libgcc \
        libintl \
        libssl3 \
        libstdc++ \
        tzdata \
        userspace-rcu \
        zlib \
        icu-libs \
        curl

    apk -X https://dl-cdn.alpinelinux.org/alpine/edge/main add --no-cache \
        lttng-ust \
        openssh-client \

    # Download the powershell '.tar.gz' archive
    curl -L https://github.com/PowerShell/PowerShell/releases/download/v7.5.0/powershell-7.5.0-linux-musl-x64.tar.gz -o /tmp/powershell.tar.gz

    # Create the target folder where powershell will be placed
    sudo mkdir -p /opt/microsoft/powershell/7

    # Expand powershell to the target folder
    sudo tar zxf /tmp/powershell.tar.gz -C /opt/microsoft/powershell/7

    # Set execute permissions
    sudo chmod +x /opt/microsoft/powershell/7/pwsh

    # Create the symbolic link that points to pwsh
    sudo ln -s /opt/microsoft/powershell/7/pwsh /usr/bin/pwsh

    # Start PowerShell
    pwsh
    ```

    - [Debian](https://learn.microsoft.com/es-es/powershell/scripting/install/install-debian?view=powershell-7.5#installation-on-debian-11-or-12-via-the-package-repository): The required version for installing PowerShell +7.4 on Debian are Debian 11 and Debian 12. The recommended way to install it is downloading the package available on PMC. You just need to follow the following steps:

    ```console
    ###################################
    # Prerequisites

    # Update the list of packages
    sudo apt-get update

    # Install pre-requisite packages.
    sudo apt-get install -y wget

    # Get the version of Debian
    source /etc/os-release

    # Download the Microsoft repository GPG keys
    wget -q https://packages.microsoft.com/config/debian/$VERSION_ID/packages-microsoft-prod.deb

    # Register the Microsoft repository GPG keys
    sudo dpkg -i packages-microsoft-prod.deb

    # Delete the Microsoft repository GPG keys file
    rm packages-microsoft-prod.deb

    # Update the list of packages after we added packages.microsoft.com
    sudo apt-get update

    ###################################
    # Install PowerShell
    sudo apt-get install -y powershell

    # Start PowerShell
    pwsh
    ```

    - [Rhel](https://learn.microsoft.com/es-es/powershell/scripting/install/install-rhel?view=powershell-7.5#installation-via-the-package-repository): The required version for installing PowerShell +7.4 on Red Hat are RHEL 8 and RHEL 9. The recommended way to install it is downloading the package available on PMC. You just need to follow the following steps:

    ```console
    ###################################
    # Prerequisites

    # Get version of RHEL
    source /etc/os-release
    if [ ${VERSION_ID%.*} -lt 8 ]
    then majorver=7
    elif [ ${VERSION_ID%.*} -lt 9 ]
    then majorver=8
    else majorver=9
    fi

    # Download the Microsoft RedHat repository package
    curl -sSL -O https://packages.microsoft.com/config/rhel/$majorver/packages-microsoft-prod.rpm

    # Register the Microsoft RedHat repository
    sudo rpm -i packages-microsoft-prod.rpm

    # Delete the downloaded package after installing
    rm packages-microsoft-prod.rpm

    # Update package index files
    sudo dnf update
    # Install PowerShell
    sudo dnf install powershell -y
    ```

- [Docker](https://learn.microsoft.com/es-es/powershell/scripting/install/powershell-in-docker?view=powershell-7.5#use-powershell-in-a-container): The following command download the latest stable versions of PowerShell:

    ```console
    docker pull mcr.microsoft.com/dotnet/sdk:9.0
    ```

    To start an interactive shell of Pwsh you just need to run:

    ```console
    docker run -it mcr.microsoft.com/dotnet/sdk:9.0 pwsh
    ```

### Required PowerShell Modules

Prowler relies on several PowerShell cmdlets to retrieve necessary data.
These cmdlets come from different modules that must be installed.

#### Automatic Installation

The required modules are automatically installed when running Prowler with the `--init-modules` flag.

Example command:

```console
python3 prowler-cli.py m365 --verbose --log-level ERROR --env-auth --init-modules
```
If the modules are already installed, running this command will not cause issues—it will simply verify that the necessary modules are available.

???+ note
    Prowler installs the modules using `-Scope CurrentUser`.
    If you encounter any issues with services not working after the automatic installation, try installing the modules manually using `-Scope AllUsers` (administrator permissions are required for this).
    The command needed to install a module manually is:
    ```powershell
    Install-Module -Name "ModuleName" -Scope AllUsers -Force
    ```

#### Modules Version

- [ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement/3.6.0) (Minimum version: 3.6.0) Required for checks across Exchange, Defender, and Purview.
- [MicrosoftTeams](https://www.powershellgallery.com/packages/MicrosoftTeams/6.6.0) (Minimum version: 6.6.0) Required for all Teams checks.
- [MSAL.PS](https://www.powershellgallery.com/packages/MSAL.PS/4.32.0): Required for Exchange module via application authentication.

[MSAL.PS](https://www.powershellgallery.com/packages/MSAL.PS/4.32.0): Required for Exchange module via application authentication.

## GitHub

Prowler supports multiple [authentication methods for GitHub](https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api).

### Supported Authentication Methods

- **Personal Access Token (PAT)**
- **OAuth App Token**
- **GitHub App Credentials**

These options provide flexibility for scanning and analyzing your GitHub account, repositories, organizations, and applications. Choose the authentication method that best suits your security needs.

???+ note
    GitHub App Credentials support less checks than other authentication methods.

## Infrastructure as Code (IaC)

Prowler's Infrastructure as Code (IaC) provider enables you to scan local or remote infrastructure code for security and compliance issues using [Trivy](https://trivy.dev/). This provider supports a wide range of IaC frameworks and requires no cloud authentication for local scans.

### Authentication

- For local scans, no authentication is required.
- For remote repository scans, authentication can be provided via:
    - [**GitHub Username and Personal Access Token (PAT)**](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-personal-access-token-classic)
    - [**GitHub OAuth App Token**](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens#creating-a-fine-grained-personal-access-token)
    - [**Git URL**](https://git-scm.com/docs/git-clone#_git_urls)

### Supported Scanners

The IaC provider leverages Trivy to support multiple scanners, including:

- Vulnerability
- Misconfiguration
- Secret
- License
