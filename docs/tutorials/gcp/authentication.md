# GCP authentication

Prowler will use by default your User Account credentials, you can configure it using:

- `gcloud init` to use a new account
- `gcloud config set account <account>` to use an existing account

Then, obtain your access credentials using: `gcloud auth application-default login`

Otherwise, you can generate and download Service Account keys in JSON format (refer to https://cloud.google.com/iam/docs/creating-managing-service-account-keys) and provide the location of the file with the following argument:

```console
prowler gcp --credentials-file path
```

???+ note
    `prowler` will scan the GCP project associated with the credentials.


## Needed permissions

Prowler for Google Cloud needs the following permissions to be set:

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

## Impersonate Service Account

If you want to impersonate a GCP service account, you can use the `--impersonate-service-account` argument:

```console
prowler gcp --impersonate-service-account <service-account-email>
```

This argument will use the default credentials to impersonate the service account provided.
