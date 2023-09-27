# AWS Authentication

Make sure you have properly configured your AWS-CLI with a valid Access Key and Region or declare AWS variables properly (or instance profile/role):

```console
aws configure
```

or

```console
export AWS_ACCESS_KEY_ID="ASXXXXXXX"
export AWS_SECRET_ACCESS_KEY="XXXXXXXXX"
export AWS_SESSION_TOKEN="XXXXXXXXX"
```

Those credentials must be associated to a user or role with proper permissions to do all checks. To make sure, add the following AWS managed policies to the user or role being used:

  - `arn:aws:iam::aws:policy/SecurityAudit`
  - `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`

  > Moreover, some read-only additional permissions are needed for several checks, make sure you attach also the custom policy [prowler-additions-policy.json](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-additions-policy.json) to the role you are using.

  > If you want Prowler to send findings to [AWS Security Hub](https://aws.amazon.com/security-hub), make sure you also attach the custom policy [prowler-security-hub.json](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-security-hub.json).


## Profiles

Prowler can use your custom AWS Profile with:
```console
prowler <provider> -p/--profile <profile_name>
```

## Multi-Factor Authentication

If your IAM entity enforces MFA you can use `--mfa` and Prowler will ask you to input the following values to get a new session:

- ARN of your MFA device
- TOTP (Time-Based One-Time Password)

## STS Endpoint Region

If you are using Prowler in AWS regions that are not enabled by default you need to use the argument `--sts-endpoint-region` to point the AWS STS API calls `assume-role` and `get-caller-identity` to the non-default region, e.g.: `prowler aws --sts-endpoint-region eu-south-2`.
