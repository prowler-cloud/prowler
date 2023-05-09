# GCP authentication

Prowler will use by default your User Account credentials, you can configure it using:

- `gcloud init` to use a new account
- `gcloud config set account <account>` to use an existing account

Then, obtain your access credentials using: `gcloud auth application-default login`

Otherwise, you can generate and download Service Account keys in JSON format (refer to https://cloud.google.com/iam/docs/creating-managing-service-account-keys) and provide the location of the file with the following argument:

```console
prowler gcp --credentials-file path
```

> `prowler` will scan the GCP project associated with the credentials.


Prowler will follow the same credentials search as [Google authentication libraries](https://cloud.google.com/docs/authentication/application-default-credentials#search_order):

1. [GOOGLE_APPLICATION_CREDENTIALS environment variable](https://cloud.google.com/docs/authentication/application-default-credentials#GAC)
2. [User credentials set up by using the Google Cloud CLI](https://cloud.google.com/docs/authentication/application-default-credentials#personal)
3. [The attached service account, returned by the metadata server](https://cloud.google.com/docs/authentication/application-default-credentials#attached-sa)

Those credentials must be associated to a user or service account with proper permissions to do all checks. To make sure, add the following roles to the member associated with the credentials:

  - Viewer
  - Security Reviewer
  - Stackdriver Account Viewer
