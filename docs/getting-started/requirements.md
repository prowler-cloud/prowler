# Prowler Requirements

Prowler is built in Python and utilizes the following SDKs:

- [AWS SDK (Boto3)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html#)
- [Azure SDK](https://azure.github.io/azure-sdk-for-python/)
- [GCP API Python Client](https://github.com/googleapis/google-api-python-client/)
- [Kubernetes SDK](https://github.com/kubernetes-client/python)
- [M365 Graph SDK](https://github.com/microsoftgraph/msgraph-sdk-python)
- [Github REST API SDK](https://github.com/PyGithub/PyGithub)

## AWS

Prowler requires AWS credentials to function properly. You can authenticate using any method outlined in the [AWS CLI configuration guide](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-precedence).

### Authentication Steps

Ensure your AWS CLI is correctly configured with valid credentials and region settings. You can achieve this via:

```console
aws configure
```

or

```console
export AWS_ACCESS_KEY_ID="ASXXXXXXX"
export AWS_SECRET_ACCESS_KEY="XXXXXXXXX"
export AWS_SESSION_TOKEN="XXXXXXXXX"
```

#### Required IAM Permissions

The credentials used must be associated with a user or role that has appropriate permissions for security checks. Attach the following AWS managed policies to ensure access:

  - `arn:aws:iam::aws:policy/SecurityAudit`
  - `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`

#### Additional Permissions

For certain checks, additional read-only permissions are required. Attach the following custom policy to your role:

[prowler-additions-policy.json](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-additions-policy.json)

If you intend to send findings to
[AWS Security Hub](https://aws.amazon.com/security-hub), attach the following custom policy:

[prowler-security-hub.json](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-security-hub.json).

### Multi-Factor Authentication (MFA)

If your IAM entity requires Multi-Factor Authentication (MFA), you can use the `--mfa` flag. Prowler will prompt you to enter the following values to initiate a new session:

- **ARN of your MFA device**
- **TOTP (Time-Based One-Time Password)**

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

- `Domain.Read.All`
- `Policy.Read.All`
- `UserAuthenticationMethod.Read.All` (used for Entra multifactor authentication checks)

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
- **Viewer (`roles/viewer`)** – Must be granted at the **project, folder, or organization** level to allow scanning of target projects.

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

- [**Service Principal Application**](https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals?tabs=browser#service-principal-object)
- **Service Principal Application with Microsoft User Credentials** (**Recommended**)
- **Stored AZ CLI credentials**
- **Interactive browser authentication**

> ⚠️ **Important:** Prowler App **only** supports the **Service Principal with User Credentials** authentication method.

### Service Principal Authentication

**Authentication flag:** `--sp-env-auth`

To enable Prowler to authenticate as a **Service Principal**, configure the following environment variables:

```console
export AZURE_CLIENT_ID="XXXXXXXXX"
export AZURE_CLIENT_SECRET="XXXXXXXXX"
export AZURE_TENANT_ID="XXXXXXXXX"
```

If these variables are not set or exported, execution using `--sp-env-auth` will fail.

Refer to the [Create Prowler Service Principal](../tutorials/microsoft365/getting-started-m365.md#create-the-service-principal-app) guide for setup instructions.

???+ note
    Using this authentication method allows you to perform only MS Graph-based checks. To scan all M365 security checks, use the recommended authentication method.

### Service Principal and User Credentials Authentication (Recommended)

Authentication flag: `--env-auth`

This method builds upon the Service Principal authentication by adding User Credentials. Configure the following environment variables: `M365_USER` and `M365_PASSWORD`.

```console
export AZURE_CLIENT_ID="XXXXXXXXX"
export AZURE_CLIENT_SECRET="XXXXXXXXX"
export AZURE_TENANT_ID="XXXXXXXXX"
export M365_USER="your_email@example.com"
export M365_PASSWORD="examplepassword"
```
**Why Use This Method?**

`M365_USER` and `M365_PASSWORD` are required to execute PowerShell modules that retrieve data from M365 services.

**Prowler uses:**

Service Principal authentication for Microsoft Graph access.

User Credentials for Microsoft PowerShell module authentication.

**User Credentials Format**

- `M365_USER` must match the assigned domain in the tenant. Examples:

    ✅ `example@YourCompany.onmicrosoft.com`

    ✅ `example@YourCompany.com`

    ❌ Using a domain different from all of the assigned domains on the tenant will fail.

    ???+ warning
        If the user is newly created, you need to sign in with that account first, as Microsoft will prompt you to change the password. If you don’t complete this step, user authentication will fail because Microsoft marks the initial password as expired.

    ???+ warning
        The user must not be MFA capable. Microsoft does not allow MFA capable users to authenticate programmatically. See [Microsoft documentation](https://learn.microsoft.com/en-us/entra/identity-platform/scenario-desktop-acquire-token-username-password?tabs=dotnet) for more information.

    Ensure you are using the right domain for the user you are trying to authenticate with.

    ![User Domains](../tutorials/microsoft365/img/user-domains.png)

- `M365_PASSWORD` must be the user password.

    ???+ note
        Previously, Prowler required an encrypted password. Now, Prowler automatically handles encryption, so you only need to provide the password directly.

### Interactive Browser Authentication

**Authentication flag:** `--browser-auth`

This authentication method requires the user to authenticate against Azure using the default browser to start the scan. The `--tenant-id` flag is also required.

With these credentials, you will only be able to run checks that rely on Microsoft Graph. This means you won't be able to run the entire provider. To perform a full M365 security scan, use the **recommended authentication method**.

Since this is a **delegated permission** authentication method, necessary permissions should be assigned to the user rather than the application.

### Required Permissions

To run the full Prowler provider, including PowerShell checks, two types of permission scopes must be set in **Microsoft Entra ID**.

#### Service Principal Application Permissions

These permissions are assigned at the **application level** and are required to retrieve identity-related data:

- `AuditLog.Read.All`: Required for Entra service.
- `Domain.Read.All`: Required for all services.
- `Organization.Read.All`: Required for retrieving tenant information.
- `Policy.Read.All`: Required for all services.
- `SharePointTenantSettings.Read.All`: Required for SharePoint service.
- `User.Read` (IMPORTANT: this must be set as **delegated**): Required for the sign-in.

#### PowerShell Module Permissions

These permissions are assigned at the **user level** (`M365_USER`). The user running Prowler must have **one** of the following roles:

- `Global Reader` (**Recommended**) – Provides read-only access to all required resources.
- `Exchange Administrator` **and** `Teams Administrator` – Both roles are required in case that you don't use Global Reader, this is why Global Reader is preferred since only read access is needed.
  Refer to Microsoft's documentation on [Exchange Online permissions](https://learn.microsoft.com/en-us/exchange/permissions-exo/permissions-exo#microsoft-365-permissions-in-exchange-online) for more details.

### Assigning Permissions and Roles

For guidance on assigning the necessary permissions and roles, follow these instructions:
- [Grant API Permissions](../tutorials/microsoft365/getting-started-m365.md#grant-required-api-permissions)
- [Assign Required Roles](../tutorials/microsoft365/getting-started-m365.md#assign-required-roles-to-your-user)

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

[ExchangeOnlineManagement](https://www.powershellgallery.com/packages/ExchangeOnlineManagement/3.6.0) (Minimum version: 3.6.0) Required for checks across Exchange, Defender, and Purview.

[MicrosoftTeams](https://www.powershellgallery.com/packages/MicrosoftTeams/6.6.0) (Minimum version: 6.6.0) Required for all Teams checks.

## GitHub

Prowler supports multiple [authentication methods for GitHub](https://docs.github.com/en/rest/authentication/authenticating-to-the-rest-api).

### Supported Authentication Methods

- **Personal Access Token (PAT)**
- **OAuth App Token**
- **GitHub App Credentials**

These options provide flexibility for scanning and analyzing your GitHub account, repositories, organizations, and applications. Choose the authentication method that best suits your security needs.

???+ note
    GitHub App Credentials support less checks than other authentication methods.
