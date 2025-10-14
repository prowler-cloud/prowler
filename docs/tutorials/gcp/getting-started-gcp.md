# Getting Started With GCP on Prowler

## Prowler App

### Step 1: Get the GCP Project ID

1. Go to the [GCP Console](https://console.cloud.google.com/)
2. Locate the Project ID on the welcome screen

![Get the Project ID](./img/project-id-console.png)

### Step 2: Access Prowler Cloud or Prowler App

1. Navigate to [Prowler Cloud](https://cloud.prowler.com/) or launch [Prowler App](../prowler-app.md)
2. Go to "Configuration" > "Cloud Providers"

    ![Cloud Providers Page](../img/cloud-providers-page.png)

3. Click "Add Cloud Provider"

    ![Add a Cloud Provider](../img/add-cloud-provider.png)

4. Select "Google Cloud Platform"

    ![Select GCP](./img/select-gcp.png)

5. Add the Project ID and optionally provide a provider alias, then click "Next"

    ![Add Project ID](./img/add-project-id.png)

### Step 3: Set Up GCP Authentication

Choose the preferred authentication mode before proceeding:

**User Credentials (Application Default Credentials)**

* Quick scan as current user
* Uses Google Cloud CLI authentication
* Credentials may time out

**Service Account Key File**

* Authenticates as a service identity
* Stable and auditable
* Recommended for production

For detailed instructions on how to set up authentication, see [Authentication](./authentication.md).

6. Once credentials are configured, return to Prowler App and enter the required values:

    For "Service Account Key":

    - `Service Account Key JSON`

    For "Application Default Credentials":

    - `client_id`
    - `client_secret`
    - `refresh_token`

    ![Enter the Credentials](./img/enter-credentials-prowler-cloud.png)

7. Click "Next", then "Launch Scan"

    ![Launch Scan GCP](./img/launch-scan.png)

---

## Prowler CLI

### Credentials Lookup Order

Prowler follows the same credential search process as [Google authentication libraries](https://cloud.google.com/docs/authentication/application-default-credentials#search_order), checking credentials in this order:

1. [`GOOGLE_APPLICATION_CREDENTIALS` environment variable](https://cloud.google.com/docs/authentication/application-default-credentials#GAC)
2. [`CLOUDSDK_AUTH_ACCESS_TOKEN` + optional `GOOGLE_CLOUD_PROJECT`](https://cloud.google.com/sdk/gcloud/reference/auth/print-access-token)
3. [User credentials set up by using the Google Cloud CLI](https://cloud.google.com/docs/authentication/application-default-credentials#personal)
4. [Attached service account (e.g., Cloud Run, GCE, Cloud Functions)](https://cloud.google.com/docs/authentication/application-default-credentials#attached-sa)

???+ note
    The credentials must belong to a user or service account with the necessary permissions.
    For detailed instructions on how to set the permissions, see [Authentication > Required Permissions](./authentication.md#required-permissions).

???+ note
    Prowler will use the enabled Google Cloud APIs to get the information needed to perform the checks.

### Configure GCP Credentials

To authenticate with GCP, use one of the following methods:

```console
gcloud auth application-default login
```

or set the credentials file path:

```console
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/credentials.json"
```

These credentials must belong to a user or service account with the necessary permissions to perform security checks.

For more authentication details, see the [Authentication](./authentication.md) page.

### Project Specification

To scan specific projects, specify them with the following command:

```console
prowler gcp --project-ids <project-id-1> <project-id-2>
```

### Service Account Impersonation

For service account impersonation, use the `--impersonate-service-account` flag:

```console
prowler gcp --impersonate-service-account <service-account-email>
```

More details on authentication methods in the [Authentication](./authentication.md) page.
