# AWS Assume Role

Prowler uses the AWS SDK (Boto3) underneath so it uses the same authentication methods.

However, there are few ways to run Prowler against multiple accounts using IAM Assume Role feature depending on each use case:

1. You can just set up your custom profile inside `~/.aws/config` with all needed information about the role to assume then call it with `prowler aws -p/--profile your-custom-profile`.
 - An example profile that performs role-chaining is given below. The `credential_source` can either be set to `Environment`, `Ec2InstanceMetadata`, or `EcsContainer`.
- Alternatively, you could use the `source_profile` instead of `credential_source` to specify a separate named profile that contains IAM user credentials with permission to assume the target the role. More information can be found [here](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-role.html).
```
[profile crossaccountrole]
role_arn = arn:aws:iam::234567890123:role/SomeRole
credential_source = EcsContainer
```

2. You can use `-R`/`--role <role_arn>` and Prowler will get those temporary credentials using `Boto3` and run against that given account.
```sh
prowler aws -R arn:aws:iam::<account_id>:role/<role_name>
```
- Optionally, the session duration (in seconds, by default 3600) and the external ID of this role assumption can be defined:

```sh
prowler aws -T/--session-duration <seconds> -I/--external-id <external_id> -R arn:aws:iam::<account_id>:role/<role_name>
```

## STS Endpoint Region

If you are using Prowler in AWS regions that are not enabled by default you need to use the argument `--sts-endpoint-region` to point the AWS STS API calls `assume-role` and `get-caller-identity` to the non-default region.

## Role MFA

If your IAM Role has MFA configured you can use `--mfa` along with  `-R`/`--role <role_arn>` and Prowler will ask you to input the following values to get a new temporary session for the IAM Role provided:

- ARN of your MFA device
- TOTP (Time-Based One-Time Password)

## Create Role

To create a role to be assumed in one or multiple accounts you can use either as CloudFormation Stack or StackSet the following [template](https://github.com/prowler-cloud/prowler/blob/master/permissions/create_role_to_assume_cfn.yaml) and adapt it.

> _NOTE 1 about Session Duration_: Depending on the amount of checks you run and the size of your infrastructure, Prowler may require more than 1 hour to finish. Use option `-T <seconds>` to allow up to 12h (43200 seconds). To allow more than 1h you need to modify _"Maximum CLI/API session duration"_ for that particular role, read more [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html#id_roles_use_view-role-max-session).

> _NOTE 2 about Session Duration_: Bear in mind that if you are using roles assumed by role chaining there is a hard limit of 1 hour so consider not using role chaining if possible, read more about that, in foot note 1 below the table [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html).
