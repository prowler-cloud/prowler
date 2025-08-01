# Scanning a Specific GCP Organization

By default, Prowler scans all Google Cloud projects accessible to the authenticated user.

To limit the scan to projects within a specific Google Cloud organization, use the `--organization-id` option with the GCP organization’s ID:

```console
prowler gcp --organization-id organization-id
```

???+ warning
    Ensure the credentials used have one of the following roles at the organization level:
    Cloud Asset Viewer (`roles/cloudasset.viewer`), or Cloud Asset Owner (`roles/cloudasset.owner`).

???+ note
    With this option, Prowler retrieves all projects under the specified Google Cloud organization, including those organized within folders and nested subfolders. This ensures full visibility across the entire organization’s hierarchy.

???+ note
    To obtain the Google Cloud organization ID, use:

    ```console
    gcloud organizations list
    ```
