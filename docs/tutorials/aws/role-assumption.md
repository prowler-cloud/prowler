# AWS Assume Role

Prowler uses the AWS SDK (Boto3) underneath so it uses the same authentication methods.

However, there are few ways to run Prowler against multiple accounts using IAM Assume Role feature depending on each use case:

1. You can just set up your custom profile inside `~/.aws/config` with all needed information about the role to assume then call it with `prowler aws -p/--profile your-custom-profile`.

2. You can use `-R`/`--role <role_arn>` and Prowler will get those temporary credentials using `Boto3` and run against that given account.
```sh
prowler aws -R arn:aws:iam::<account_id>:role/<role_name>
```
- Optionally, the session duration (in seconds, by default 3600) and the external ID of this role assumption can be defined:

```sh
prowler aws -T/--session-duration <seconds> -I/--external-id <external_id> -R arn:aws:iam::<account_id>:role/<role_name>
```

## Create Role

To create a role to be assumed in one or multiple accounts you can use either as CloudFormation Stack or StackSet the following [template](https://github.com/prowler-cloud/prowler/blob/master/permissions/create_role_to_assume_cfn.yaml) and adapt it.

> _NOTE 1 about Session Duration_: Depending on the mount of checks you run and the size of your infrastructure, Prowler may require more than 1 hour to finish. Use option `-T <seconds>` to allow up to 12h (43200 seconds). To allow more than 1h you need to modify _"Maximum CLI/API session duration"_ for that particular role, read more [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html#id_roles_use_view-role-max-session).

> _NOTE 2 about Session Duration_: Bear in mind that if you are using roles assumed by role chaining there is a hard limit of 1 hour so consider not using role chaining if possible, read more about that, in foot note 1 below the table [here](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use.html).
