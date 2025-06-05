# AWS Assume Role in Prowler

## Authentication Overview

Prowler leverages the AWS SDK (Boto3) for authentication, following standard AWS authentication methods.

### Running Prowler Against Multiple Accounts

To execute Prowler across multiple AWS accounts using IAM Assume Role, choose one of the following approaches:

1. Custom Profile Configuration

Set up a custom profile inside `~/.aws/config` with the necessary role information.

Then call the profile using `prowler aws -p/--profile your-custom-profile`.

- Role-Chaining Example Profile The `credential_source` parameter can be set to `Environment`, `Ec2InstanceMetadata`, or `EcsContainer`.
- Using an Alternative Named Profile

Instead of the `credential_source` parameter, `source_profile` can be used to specify a separate named profile.

This profile must contain IAM user credentials with permissions to assume the target role. For additional details, refer to the AWS Assume Role documentation: [here](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html).

```
[profile crossaccountrole]
role_arn = arn:aws:iam::234567890123:role/SomeRole
credential_source = EcsContainer
```

2. Using IAM Role Assumption in Prowler

To allow Prowler to retrieve temporary credentials by using `Boto3` and run assessments on the specified account, use the `-R`/`--role <role_arn>` flag.

```sh
prowler aws -R arn:aws:iam::<account_id>:role/<role_name>
```

- Defining Session Duration and External ID

Optionally, specify the session duration (in seconds, default: 3600) and the external ID for role assumption:

```sh
prowler aws -T/--session-duration <seconds> -I/--external-id <external_id> -R arn:aws:iam::<account_id>:role/<role_name>
```

## Custom Role Session Name in Prowler

### Setting a Custom Session Name

Prowler allows you to specify a custom Role Session name using the following flag:

```console
prowler aws --role-session-name <role_session_name>
```

???+ note
    If not specified, it defaults to `ProwlerAssessmentSession`.

## Role MFA Authentication

If your IAM Role is configured with Multi-Factor Authentication (MFA), use `--mfa` along with `-R`/`--role <role_arn>`. Prowler will prompt you to input the following values to obtain a temporary session for the IAM Role provided:

- ARN of your MFA device
- TOTP (Time-Based One-Time Password)

## Creating a Role for One or Multiple Accounts

To create an IAM role that can be assumed in one or multiple AWS accounts, use either a CloudFormation Stack or StackSet and adapt the provided [template](https://github.com/prowler-cloud/prowler/blob/master/permissions/create_role_to_assume_cfn.yaml).

???+ note
    Session Duration Considerations_ Depending on the number of checks performed and the size of your infrastructure, Prowler may require more than 1 hour to complete. Use the `-T <seconds>` option to allow up to 12 hours (43,200 seconds). If you need more than 1 hour, modify the _“Maximum CLI/API session duration”_ setting for the role. Learn more [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html#id_roles_use_view-role-max-session).

    ⚠️ Important: If assuming roles via role chaining, there is a hard limit of 1 hour. Whenever possible, avoid role chaining to prevent session expiration issues. More details are available in footnote 1 below the table in the [AWS IAM guide](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html).
