# AWS Authentication in Prowler

Prowler requires AWS credentials to function properly. You can authenticate using the following methods:

- TODO: Add acnhors to each method

## Required Permissions
To ensure full functionality, attach the following AWS managed policies to the designated user or role:

- `arn:aws:iam::aws:policy/SecurityAudit`
- `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`

#### Additional Permissions

For certain checks, additional read-only permissions are required. Attach the following custom policy to your role: [prowler-additions-policy.json](https://github.com/prowler-cloud/prowler/blob/master/permissions/prowler-additions-policy.json)


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



## AWS Profiles

Prowler allows you to specify a custom AWS profile using the following command:

```console
prowler aws -p/--profile <profile_name>
```

## Multi-Factor Authentication (MFA)

If your IAM entity requires Multi-Factor Authentication (MFA), you can use the `--mfa` flag. Prowler will prompt you to enter the following values to initiate a new session:

- **ARN of your MFA device**
- **TOTP (Time-Based One-Time Password)**
