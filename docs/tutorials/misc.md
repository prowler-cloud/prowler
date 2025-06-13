# Miscellaneous

## Prowler Version

### Showing the Prowler version:

```console
prowler <provider> -V/-v/--version
```

## Prowler Execution Options

Prowler provides various execution settings.

### Verbose Execution

To enable verbose mode in Prowler, similar to Version 2, use:

```console
prowler <provider> --verbose
```

### Filter findings by status

Prowler allows filtering findings based on their status, ensuring reports and CLI display only relevant findings:

```console
prowler <provider> --status [PASS, FAIL, MANUAL]
```

### Disable Exit Code 3

By default, Prowler triggers exit code 3 for failed checks. To disable this behavior:

```console
prowler <provider> -z/--ignore-exit-code-3
```

### Hide Prowler Banner

To run Prowler without displaying the banner:

```console
prowler <provider> -b/--no-banner
```

### Disable Colors in Output

To run Prowler without color formatting:

```console
prowler <provider> --no-color
```

### Checks in Prowler

Prowler provides various security checks per cloud provider. Use the following options to list, execute, or exclude specific checks:

- \*List Available Checks\*
To display all available checks for the chosen provider:

```console
prowler <provider> --list-checks
```

- \*Execute Specific Checks\*
Run one or more specific security checks using:

```console
prowler <provider> -c/--checks s3_bucket_public_access
```

- \*Exclude Specific Checks\*
Exclude checks from execution with:

```console
prowler <provider> -e/--excluded-checks ec2 rds
```

- \*Execute Checks from a JSON File\*
To run checks defined in a JSON file, structure the file as follows:

```json
<checks_list>.json

{
    "<provider>": [
        "<check_name_1",
        "<check_name_2",
        "<check_name_3",
        ...
    ],
    ...
}
```

```console
prowler <provider> -C/--checks-file <checks_list>.json
```

## Custom Checks in Prowler

Prowler supports custom security checks, allowing users to define their own logic.

```console
prowler <provider> -x/--checks-folder <custom_checks_folder>
```

???+ note
    S3 URIs are also supported for custom check folders (e.g., `s3://bucket/prefix/checks_folder/`). Ensure the credentials used have `s3:GetObject` permissions in the specified S3 path.

**Folder Structure for Custom Checks**

Each check must reside in a dedicated subfolder, following this structure:

- `__init__.py` (empty file) – Ensures Python treats the check folder as a package.
- `check_name.py` (name file) – Defines the check’s logic for contextual information.
- `check_name.metadata.json` (metadata file) – Defines the check’s metadata for contextual information.

???+ note
    The check name must start with the service name followed by an underscore (e.g., ec2\_instance\_public\_ip).

To see more information about how to write checks, refer to the [Developer Guide](../developer-guide/checks.md#create-a-new-check-for-a-provider).

???+ note
    If you want to run ONLY your custom check(s), import it with -x (--checks-folder) and then run it with -c (--checks), e.g.: `console prowler aws -x s3://bucket/prowler/providers/aws/services/s3/s3_bucket_policy/ -c s3_bucket_policy`

## Severities

Each of Prowler's checks has a severity, which can be one of the following:

- informational
- low
- medium
- high
- critical

To execute specific severity(s):

```console
prowler <provider> --severity critical high
```

## Service

Prowler has services per provider, there are options related with them:

- List the available services in the provider:

```console
prowler <provider> --list-services
```

- Execute specific service(s):

```console
prowler <provider> -s/--services s3 iam
```

- Exclude specific service(s):

```console
prowler <provider> --excluded-services ec2 rds
```

## Categories

Prowler groups checks in different categories. There are options related with said categories:

- List the available categories in the provider:

```console
prowler <provider> --list-categories
```

- Execute specific category(s):

```console
prowler  <provider> --categories secrets
```
