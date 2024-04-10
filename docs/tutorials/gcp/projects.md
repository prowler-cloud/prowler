# GCP Projects

By default, Prowler is multi-project, which means that is going to scan all the Google Cloud projects that the authenticated user has access to. If you want to scan a specific project(s), you can use the `--project-ids` argument.

```console
prowler gcp --project-ids project-id1 project-id2
```

???+ note
    You can use asterisk `*` to scan projects that match a pattern. For example, `prowler gcp --project-ids "prowler*"` will scan all the projects that start with `prowler`.

???+ note
    If you want to know the projects that you have access to, you can use the following command:

    ```console
    prowler gcp --list-project-ids
    ```

### Exclude Projects

If you want to exclude some projects from the scan, you can use the `--exclude-project-ids` argument.

```console
prowler gcp --exclude-project-ids project-id1 project-id2
```

???+ note
    You can use asterisk `*` to exclude projects that match a pattern. For example, `prowler gcp --exclude-project-ids "sys*"` will exclude all the projects that start with `sys`.
