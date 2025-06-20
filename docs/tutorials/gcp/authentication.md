# GCP Authentication in Prowler

## Default Authentication

By default, Prowler uses your User Account credentials. You can configure authentication as follows:

- `gcloud init` to use a new account, or
- `gcloud config set account <account>` to use an existing account.

Then, obtain your access credentials using: `gcloud auth application-default login`.

## Using Service Account Keys

Alternatively, Service Account keys can be generated and downloaded in JSON format. Follow the steps in the Google Cloud IAM guide (https://cloud.google.com/iam/docs/creating-managing-service-account-keys) to create and manage service account keys. Provide the path to the key file using:

```console
prowler gcp --credentials-file path
```

???+ note
    `prowler` will scan the GCP project associated with the credentials.

## Using an access token

If you already have an access token (e.g., generated with `gcloud auth print-access-token`), you can run Prowler with:

```bash
export CLOUDSDK_AUTH_ACCESS_TOKEN=$(gcloud auth print-access-token)
prowler gcp --project-ids <project-id>
```

???+ note
    If using this method, it's recommended to also set the default project explicitly:
    ```bash
    export GOOGLE_CLOUD_PROJECT=<project-id>
    ```

## Credentials lookup order

Prowler follows the same credential search process as [Google authentication libraries](https://cloud.google.com/docs/authentication/application-default-credentials#search_order), checking credentials in this order:

1. [`GOOGLE_APPLICATION_CREDENTIALS` environment variable](https://cloud.google.com/docs/authentication/application-default-credentials#GAC)
2. [`CLOUDSDK_AUTH_ACCESS_TOKEN` + optional `GOOGLE_CLOUD_PROJECT`](https://cloud.google.com/sdk/gcloud/reference/auth/print-access-token)
3. [User credentials set up by using the Google Cloud CLI](https://cloud.google.com/docs/authentication/application-default-credentials#personal)
4. [Attached service account (e.g., Cloud Run, GCE, Cloud Functions)](https://cloud.google.com/docs/authentication/application-default-credentials#attached-sa)

???+ note
    The credentials must belong to a user or service account with the necessary permissions.
    To ensure full access, assign the roles/viewer IAM role to the identity being used.

???+ note
    Prowler will use the enabled Google Cloud APIs to get the information needed to perform the checks.


## Required Permissions

To ensure full functionality, Prowler for Google Cloud needs the following permissions to be set:

- **Viewer (`roles/viewer`) IAM role**: granted at the project / folder / org level in order to scan the target projects

- **Project level settings**: you need to have at least one project with the below settings:
    - Identity and Access Management (IAM) API (`iam.googleapis.com`) enabled by either using the
    [Google Cloud API UI](https://console.cloud.google.com/apis/api/iam.googleapis.com/metrics) or
    by using the gcloud CLI `gcloud services enable iam.googleapis.com --project <your-project-id>` command
    - Service Usage Consumer (`roles/serviceusage.serviceUsageConsumer`) IAM role
    - Set the quota project to be this project by either running `gcloud auth application-default set-quota-project <project-id>` or by setting an environment variable:
    `export GOOGLE_CLOUD_QUOTA_PROJECT=<project-id>`


The above settings must be associated to a user or service account.

???+ note
    Prowler will use the enabled Google Cloud APIs to get the information needed to perform the checks.

## Impersonating a GCP Service Account in Prowler

To impersonate a GCP service account, use the `--impersonate-service-account` argument followed by the service account email:

```console
prowler gcp --impersonate-service-account <service-account-email>
```

This command leverages the default credentials to impersonate the specified service account.
