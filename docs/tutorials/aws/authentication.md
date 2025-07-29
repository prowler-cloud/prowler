# AWS Authentication in Prowler

Proper authentication is required for Prowler to perform security checks across AWS resources. Ensure that AWS-CLI is correctly configured or manually declare AWS credentials before running scans.

## Configure AWS Credentials

Use one of the following methods to authenticate:

```console
aws configure
```

or

```console
export AWS_ACCESS_KEY_ID="ASXXXXXXX"
export AWS_SECRET_ACCESS_KEY="XXXXXXXXX"
export AWS_SESSION_TOKEN="XXXXXXXXX"
```

These credentials must be associated with a user or role with the necessary permissions to perform security checks. 

## Assign Required AWS Permissions
To ensure full functionality, attach the following AWS managed policies to the designated user or role:

- `arn:aws:iam::aws:policy/SecurityAudit`
- `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`

???+ note
    Some security checks require read-only additional permissions. Attach the following custom policies to the role: [prowler-additions-policy.json](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-additions-policy.json). If you want Prowler to send findings to [AWS Security Hub](https://aws.amazon.com/security-hub), make sure to also attach the custom policy: [prowler-security-hub.json](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-security-hub.json).

## AWS Profiles and Service Scanning in Prowler

Prowler supports authentication and security assessments using custom AWS profiles and can optionally scan unused services.

**Using Custom AWS Profiles**

Prowler allows you to specify a custom AWS profile using the following command:

```console
prowler aws -p/--profile <profile_name>
```

## Multi-Factor Authentication (MFA)

If MFA enforcement is required for your IAM entity, you can use `--mfa`. Prowler will prompt you to enter the following in order to get a new session:

- ARN of your MFA device
- TOTP (Time-Based One-Time Password)
