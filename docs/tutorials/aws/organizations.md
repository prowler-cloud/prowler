# AWS Organizations in Prowler

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

In Prowler’s JSON output, tags are encoded in Base64 to prevent formatting errors in CSV or JSON outputs. This ensures compatibility when exporting findings.

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
