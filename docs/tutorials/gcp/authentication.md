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

Prowler follows the same credential search process as [Google authentication libraries](https://cloud.google.com/docs/authentication/application-default-credentials#search_order), checking credentials in this order:

1. [GOOGLE\_APPLICATION\_CREDENTIALS environment variable](https://cloud.google.com/docs/authentication/application-default-credentials#GAC)
2. [User credentials set up via Google Cloud CLI](https://cloud.google.com/docs/authentication/application-default-credentials#personal)
3. [The attached service account, returned by the metadata server](https://cloud.google.com/docs/authentication/application-default-credentials#attached-sa)

These credentials must be associated with a user or service account with the necessary permissions to perform security checks.

## Required Permissions

To ensure full functionality, assign the `Viewer` role to the account linked to the credentials:

???+ note
    Google Cloud API Access: Prowler leverages enabled Google Cloud APIs to gather the necessary information for security checks. Ensure that required APIs are active in your Google Cloud environment.

## Impersonating a GCP Service Account in Prowler

To impersonate a GCP service account, use the `--impersonate-service-account` argument followed by the service account email:

```console
prowler gcp --impersonate-service-account <service-account-email>
```

This command leverages the default credentials to impersonate the specified service account.
