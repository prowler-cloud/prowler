# GCP Project Scanning in Prowler

By default, Prowler operates in a multi-project mode, scanning all Google Cloud projects accessible to the authenticated user.

## Specifying Projects

To limit the scan to specific projects, use the `--project-ids` argument followed by the desired project ID(s).

```console
prowler gcp --project-ids project-id1 project-id2
```

### Pattern-Based Project Selection

Use an asterisk `*` to scan projects that match a pattern. For example, `prowler gcp --project-ids "prowler*"` will scan all the projects that start with `prowler`.

### Listing Accessible Projects

To view a list of projects the user has access to, run:

```console
prowler gcp --list-project-ids
```

### Excluding Projects in Prowler

#### Project Exclusion

To exclude specific Google Cloud projects from the scan, use the `--excluded-project-ids` argument followed by the project ID(s):

```console
prowler gcp --excluded-project-ids project-id1 project-id2
```

#### Pattern-Based Project Exclusion

Use an asterisk `*` to exclude projects that match a pattern. For example, `prowler gcp --excluded-project-ids "sys*"` will exclude all the projects that start with `sys`.
