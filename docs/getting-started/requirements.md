# Requirements

Prowler has been written in Python using the [AWS SDK (Boto3)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html#) and [Azure SDK](https://azure.github.io/azure-sdk-for-python/).
## AWS

Since Prowler uses AWS Credentials under the hood, you can follow any authentication method as described [here](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-quickstart.html#cli-configure-quickstart-precedence).

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

  - arn:aws:iam::aws:policy/SecurityAudit
  - arn:aws:iam::aws:policy/job-function/ViewOnlyAccess

  > Moreover, some read-only additional permissions are needed for several checks, make sure you attach also the custom policy [prowler-additions-policy.json](https://github.com/prowler-cloud/prowler/blob/master/iam/prowler-additions-policy.json) to the role you are using.

  > If you want Prowler to send findings to [AWS Security Hub](https://aws.amazon.com/security-hub), make sure you also attach the custom policy [prowler-security-hub.json](https://github.com/prowler-cloud/prowler/blob/master/iam/prowler-security-hub.json).
