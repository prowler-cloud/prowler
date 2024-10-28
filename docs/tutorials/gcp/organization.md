# GCP Organization

By default, Prowler scans all Google Cloud projects accessible to the authenticated user.

To limit the scan to projects within a specific Google Cloud organization, use the `--organization-id` option with the GCP organization ID:

```console
prowler gcp --organization-id organization-id
```

???+ warning
    Make sure that the used credentials have the role Cloud Asset Viewer (`roles/cloudasset.viewer`) or Cloud Asset Owner (`roles/cloudasset.owner`) on the organization level.

???+ note
    With this option, Prowler retrieves all projects within the specified organization, including those organized in folders and nested subfolders. This ensures that every project under the organization’s hierarchy is scanned, providing full visibility across the entire organization.

???+ note
    To find the organization ID, use the following command:

    ```console
    gcloud organizations list
    ```
