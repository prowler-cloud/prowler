# AWS Authentication in Prowler

Prowler requires AWS credentials to function properly. Authentication is available through the following methods:

## Required Permissions
To ensure full functionality, attach the following AWS managed policies to the designated user or role:

- `arn:aws:iam::aws:policy/SecurityAudit`
- `arn:aws:iam::aws:policy/job-function/ViewOnlyAccess`

### Additional Permissions

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

Specify a custom AWS profile using the following command:

```console
prowler aws -p/--profile <profile_name>
```

## Multi-Factor Authentication (MFA)

For IAM entities requiring Multi-Factor Authentication (MFA), use the `--mfa` flag. Prowler prompts for the following values to initiate a new session:

- **ARN of your MFA device**
- **TOTP (Time-Based One-Time Password)**
