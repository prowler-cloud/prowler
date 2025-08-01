# AWS Organizations in Prow

Prowler can integrate with AWS Organizations to allow you to manage the visibility and onboarding of accounts centrally.

If you enable trusted access with your Organization, Prowler can discover accounts as they are created and even automate deployment of the Prowler Scan IAM Role.

> ℹ️ You can enable trusted access in your Management Account from the AWS Console under **AWS Organizations → Settings → Trusted access for AWS CloudFormation StackSets**.

If you are not using StackSets or Prowler, and just want to scan AWS Organization accounts using the CLI, you can assume a role in each account manually, or automate that logic with your own scripts.

## Retrieving AWS Account Details

If AWS Organizations is enabled, Prowler can fetch detailed account information during scans, including:

- Account Name
- Email Address
- ARN
- Organization ID
- Tags

These details will be included alongside each security finding in the output.

### Enabling AWS Organizations Data Retrieval

To retrieve AWS Organizations account details, use the `-O`/`--organizations-role <organizations_role_arn>` argument. If this argument is not provided, Prowler will attempt to fetch the data automatically—provided the AWS account is a delegated administrator for the AWS Organization.

???+ note
    For more information on AWS Organizations delegated administrator, refer to the official documentation [here](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_delegate_policies.html).

The following command is an example:

```shell
prowler aws \
  -O arn:aws:iam::<management_organizations_account_id>:role/<role_name>
```

???+ note
    Ensure the IAM role used in your AWS Organizations management account has the following permissions:`organizations:DescribeAccount` and `organizations:ListTagsForResource`.

Prowler will scan the AWS account and get the account details from AWS Organizations.

### Handling JSON Output

In Prowler's JSON output, tags are encoded in Base64 to prevent formatting errors in CSV or JSON outputs. This ensures compatibility when exporting findings.

```json
  "Account Email": "my-prod-account@domain.com",
  "Account Name": "my-prod-account",
  "Account ARN": "arn:aws:organizations::222222222222:account/o-abcde1234/111111111111",
  "Account Organization": "o-abcde1234",
  "Account tags": "\"eyJUYWdzIjpasf0=\""
```

The additional fields in CSV header output are as follows:

- ACCOUNT\_DETAILS\_EMAIL
- ACCOUNT\_DETAILS\_NAME
- ACCOUNT\_DETAILS\_ARN
- ACCOUNT\_DETAILS\_ORG
- ACCOUNT\_DETAILS\_TAGS

## Deploying Prowler IAM Roles Across AWS Organizations

When onboarding multiple AWS accounts into Prowler Cloud, it’s important to deploy the Prowler Scan IAM Role in each account. The most efficient way to do this across an AWS Organization is by leveraging AWS CloudFormation StackSets, which allows you to roll out infrastructure—like IAM roles—to all accounts centrally from your Management or Delegated Admin account.

If you're using Infrastructure as Code (IaC), we recommend using Terraform to manage this deployment systematically.

### 🧭 Recommended Approach

- **Use StackSets** from the **Management Account** (or a Delegated Admin/Security Account).
- **Use Terraform** to orchestrate the deployment.
- **Use the official CloudFormation template** provided by Prowler.
- Target specific Organizational Units (OUs) or the entire Organization.

> ℹ️ A detailed community-driven article we based this implementation on is available here:
> [Deploy IAM Roles Across an AWS Organization as Code (Unicrons)](https://unicrons.cloud/en/2024/10/14/deploy-iam-roles-across-an-aws-organization-as-code/)
> This guide has been adapted with permission and aligned with Prowler’s IAM role requirements.

---

### 🧩 Step-by-Step Using Terraform

Below is a ready-to-use Terraform snippet that deploys the [Prowler Scan IAM Role CloudFormation template](https://github.com/prowler-cloud/prowler/blob/master/permissions/templates/cloudformation/prowler-scan-role.yml) across your AWS Organization using StackSets:

#### `main.tf`

```hcl
data "aws_caller_identity" "this" {}

data "aws_organizations_organization" "this" {}

module "prowler-scan-role" {
  source = "unicrons/organization-iam-role/aws"

  stack_set_name        = "prowler-scan-role"
  stack_set_description = "Deploy Prowler Scan IAM Role across all organization accounts"
  template_path         = "${path.root}/prowler-scan-role.yaml"

  template_parameters = {
    ExternalId = "<< external ID >>"  # Replace with the actual External ID provided by Prowler Cloud
  }

  # You can also specify specific OU IDs instead of root
  organizational_unit_ids = [data.aws_organizations_organization.this.roots[0].id]
}
```

#### `prowler-scan-role.yaml`

You can download or reference the official CloudFormation template directly from GitHub:

- [prowler-scan-role.yml](https://github.com/prowler-cloud/prowler/blob/master/permissions/templates/cloudformation/prowler-scan-role.yml)

You may store this file locally and reference it in `template_path`, or download it dynamically.

---

### 🛡 IAM Role: External ID Support

Make sure to include the `ExternalId` parameter in your StackSet if required by your organization’s Prowler Cloud setup. This ensures secure cross-account access for scanning.

---

### 🧪 Testing and Validation

After deployment:
- Go to the **CloudFormation Stack Instances** section in the AWS Console to validate the success in each account.
- Ensure the IAM role exists under `prowler-scan-role` with the correct trust policy.
- Run a scan from the Prowler Cloud console or CLI to verify access.

---

If you encounter issues during deployment or need to target specific OUs or environments (e.g. dev/staging/prod), feel free to reach out to the Prowler team via [Slack Community](https://prowler.com/slack) or Support.

## Extra: Run Prowler across all accounts in AWS Organizations by assuming roles

### Running Prowler Across All AWS Organization Accounts

1. To run Prowler across all accounts in AWS Organizations, first retrieve a list of accounts that are not suspended:

    ```shell
    ACCOUNTS_IN_ORGS=$(aws organizations list-accounts \
      --query "Accounts[?Status=='ACTIVE'].Id" \
      --output text \
    )
    ```

2. Then run Prowler to assume a role (same in all members) per each account:

    ```shell
    for accountId in $ACCOUNTS_IN_ORGS;
    do
      prowler aws \
        -O arn:aws:iam::<management_organizations_account_id>:role/<role_name> \
        -R arn:aws:iam::"${accountId}":role/<role_name>;
    done
    ```

???+ note
    This same loop structure can be adapted to scan a predefined list of accounts using a variable like the following: </br>`ACCOUNTS_LIST='11111111111 2222222222 333333333'`
