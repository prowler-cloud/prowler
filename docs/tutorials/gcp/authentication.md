# GCP Authentication in Prowler

## Required Permissions

Prowler for Google Cloud requires the following permissions:

### IAM Roles
- **Reader (`roles/reader`)** – Must be granted at the **project, folder, or organization** level to allow scanning of target projects.

### Project-Level Settings

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

???+ note
    `prowler` will scan the GCP project associated with the credentials.

## Credentials lookup order

Prowler follows the same credential search process as [Google authentication libraries](https://cloud.google.com/docs/authentication/application-default-credentials#search_order), checking credentials in this order:

1. [`GOOGLE_APPLICATION_CREDENTIALS` environment variable](https://cloud.google.com/docs/authentication/application-default-credentials#GAC)
2. [`CLOUDSDK_AUTH_ACCESS_TOKEN` + optional `GOOGLE_CLOUD_PROJECT`](https://cloud.google.com/sdk/gcloud/reference/auth/print-access-token)
3. [User credentials set up by using the Google Cloud CLI](https://cloud.google.com/docs/authentication/application-default-credentials#personal)
4. [Attached service account (e.g., Cloud Run, GCE, Cloud Functions)](https://cloud.google.com/docs/authentication/application-default-credentials#attached-sa)

???+ note
    The credentials must belong to a user or service account with the necessary permissions.
    To ensure full access, assign the roles/reader IAM role to the identity being used.

???+ note
    Prowler will use the enabled Google Cloud APIs to get the information needed to perform the checks.




## Using an Access Token

For existing access tokens (e.g., generated with `gcloud auth print-access-token`), run Prowler with:

```bash
export CLOUDSDK_AUTH_ACCESS_TOKEN=$(gcloud auth print-access-token)
prowler gcp --project-ids <project-id>
```

???+ note
    When using this method, also set the default project explicitly:
    ```bash
    export GOOGLE_CLOUD_PROJECT=<project-id>
    ```




## Impersonating a GCP Service Account

To impersonate a GCP service account, use the `--impersonate-service-account` argument followed by the service account email:

```console
prowler gcp --impersonate-service-account <service-account-email>
```

This command leverages the default credentials to impersonate the specified service account.
