# Miscellaneous
## Prowler Version
Show Prowler version:
```console
prowler <provider> -V/-v/--version
```
## Verbose
Execute Prowler in verbose mode (like in Version 2):
```console
prowler <provider> --verbose
```
## Filter findings by status
Prowler can filter the findings by their status:
```console
prowler <provider> --status [PASS, FAIL, MANUAL]
```
## Disable Exit Code 3
Prowler does not trigger exit code 3 with failed checks:
```console
prowler <provider> -z/--ignore-exit-code-3
```
## Hide Prowler Banner
Prowler can run without showing its banner:
```console
prowler <provider> -b/--no-banner
```
## Checks
Prowler has checks per provider, there are options related with them:

- List the available checks in the provider:
```console
prowler <provider> --list-checks
```
- Execute specific check(s):
```console
prowler <provider> -c/--checks s3_bucket_public_access
```
- Exclude specific check(s):
```console
prowler <provider> -e/--excluded-checks ec2 rds
```
- Execute checks that appears in a json file:
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
## Custom Checks
Prowler allows you to include your custom checks with the flag:
```console
prowler <provider> -x/--checks-folder <custom_checks_folder>
```

???+ note
    S3 URIs are also supported as folders for custom checks, e.g. `s3://bucket/prefix/checks_folder/`. Make sure that the used credentials have `s3:GetObject` permissions in the S3 path where the custom checks are located.

The custom checks folder must contain one subfolder per check, each subfolder must be named as the check and must contain:

- An empty `__init__.py`: to make Python treat this check folder as a package.
- A `check_name.py` containing the check's logic.
- A `check_name.metadata.json` containing the check's metadata.

???+ note
    The check name must start with the service name followed by an underscore (e.g., ec2_instance_public_ip).

To see more information about how to write checks see the [Developer Guide](../developer-guide/checks.md#create-a-new-check-for-a-provider).

???+ note
    If you want to run ONLY your custom check(s), import it with -x (--checks-folder) and then run it with -c (--checks), e.g.:
    ```console
    prowler aws -x s3://bucket/prowler/providers/aws/services/s3/s3_bucket_policy/ -c s3_bucket_policy
    ```

## Severities
Each of Prowler's checks has a severity, which can be:
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
Prowler groups checks in different categories, there are options related with them:

- List the available categories in the provider:
```console
prowler <provider> --list-categories
```
- Execute specific category(s):
```console
prowler  <provider> --categories
```
