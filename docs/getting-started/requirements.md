# Requirements

Prowler has been written in Python using the [AWS SDK (Boto3)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html#), [Azure SDK](https://azure.github.io/azure-sdk-for-python/) and [GCP API Python Client](https://github.com/googleapis/google-api-python-client/).
## AWS

Since Prowler uses AWS Credentials under the hood, you can follow any authentication method as described [here](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-precedence).

### Authentication

Make sure you have properly configured your AWS-CLI with a valid Access Key and Region or declare AWS variables properly (or instance profile/role):

```console
aws configure
```

or

```console
export AWS_ACCESS_KEY_ID="ASXXXXXXX"
export AWS_SECRET_ACCESS_KEY="XXXXXXXXX"
export AWS_SESSION_TOKEN="XXXXXXXXX"
```

Those credentials must be associated to a user or role with proper permissions to do all checks. To make sure, add the following AWS managed policies to the user or role being used:

  - `arn:aws:iam::aws:policy/SecurityAudit`
  - `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`

???+ note
    Moreover, some read-only additional permissions are needed for several checks, make sure you attach also the custom policy [prowler-additions-policy.json](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-additions-policy.json) to the role you are using. If you want Prowler to send findings to [AWS Security Hub](https://aws.amazon.com/security-hub), make sure you also attach the custom policy [prowler-security-hub.json](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-security-hub.json).

### Multi-Factor Authentication

If your IAM entity enforces MFA you can use `--mfa` and Prowler will ask you to input the following values to get a new session:

- ARN of your MFA device
- TOTP (Time-Based One-Time Password)

## Azure

Prowler for Azure supports the following authentication types:

- [Service principal application](https://learn.microsoft.com/en-us/entra/identity-platform/app-objects-and-service-principals?tabs=browser#service-principal-object) by environment variables (recommended)
- Current az cli credentials stored
- Interactive browser authentication
- [Managed identity](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview) authentication

### Service Principal authentication

To allow Prowler assume the service principal identity to start the scan it is needed to configure the following environment variables:

```console
export AZURE_CLIENT_ID="XXXXXXXXX"
export AZURE_TENANT_ID="XXXXXXXXX"
export AZURE_CLIENT_SECRET="XXXXXXX"
```

If you try to execute Prowler with the `--sp-env-auth` flag and those variables are empty or not exported, the execution is going to fail.
Follow the instructions in the [Create Prowler Service Principal](../tutorials/azure/create-prowler-service-principal.md) section to create a service principal.

### AZ CLI / Browser / Managed Identity authentication

The other three cases does not need additional configuration, `--az-cli-auth` and `--managed-identity-auth` are automated options. To use `--browser-auth`  the user needs to authenticate against Azure using the default browser to start the scan, also `tenant-id` is required.

### Permissions

To use each one you need to pass the proper flag to the execution. Prowler for Azure handles two types of permission scopes, which are:

- **Microsoft Entra ID permissions**: Used to retrieve metadata from the identity assumed by Prowler and specific Entra checks (not mandatory to have access to execute the tool). The permissions required by the tool are the following:
    - `Directory.Read.All`
    - `Policy.Read.All`
    - `UserAuthenticationMethod.Read.All`
- **Subscription scope permissions**: Required to launch the checks against your resources, mandatory to launch the tool. It is required to add the following RBAC builtin roles per subscription to the entity that is going to be assumed by the tool:
    - `Reader`
    - `ProwlerRole` (custom role defined in [prowler-azure-custom-role](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-azure-custom-role.json))

To assign the permissions, follow the instructions in the [Microsoft Entra ID permissions](../tutorials/azure/create-prowler-service-principal.md#assigning-the-proper-permissions) section and the [Azure subscriptions permissions](../tutorials/azure/subscriptions.md#assigning-proper-permissions) section, respectively.

#### Checks that require ProwlerRole

The following checks require the `ProwlerRole` custom role to be executed, if you want to run them, make sure you have assigned the role to the identity that is going to be assumed by Prowler:

- `app_function_access_keys_configured`
- `app_function_ftps_deployment_disabled`

## Google Cloud

### Authentication

Prowler will follow the same credentials search as [Google authentication libraries](https://cloud.google.com/docs/authentication/application-default-credentials#search_order):

1. [GOOGLE_APPLICATION_CREDENTIALS environment variable](https://cloud.google.com/docs/authentication/application-default-credentials#GAC)
2. [User credentials set up by using the Google Cloud CLI](https://cloud.google.com/docs/authentication/application-default-credentials#personal)
3. [The attached service account, returned by the metadata server](https://cloud.google.com/docs/authentication/application-default-credentials#attached-sa)

Those credentials must be associated to a user or service account with proper permissions to do all checks. To make sure, add the `Viewer` role to the member associated with the credentials.

???+ note
    By default, `prowler` will scan all accessible GCP Projects, use flag `--project-ids` to specify the projects to be scanned.
