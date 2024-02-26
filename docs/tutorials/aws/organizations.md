# AWS Organizations

## Get AWS Account details from your AWS Organization

Prowler allows you to get additional information of the scanned account from AWS Organizations.

If you have AWS Organizations enabled, Prowler can get your account details like account name, email, ARN, organization id and tags and you will have them next to every finding's output.

In order to do that you can use the argument `-O`/`--organizations-role <organizations_role_arn>`. If this argument is not present Prowler will try to fetch that information automatically if the AWS account is a delegated administrator for the AWS Organization.

> Refer [here](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_delegate_policies.html) for more information about AWS Organizations delegated administrator.

See the following sample command:

```shell
prowler aws \
  -O arn:aws:iam::<management_organizations_account_id>:role/<role_name>
```
???+ note
    Make sure the role in your AWS Organizations management account has the permissions `organizations:DescribeAccount` and `organizations:ListTagsForResource`.

Prowler will scan the AWS account and get the account details from AWS Organizations.

In the JSON output below you can see tags coded in base64 to prevent breaking CSV or JSON due to its format:

```json
  "Account Email": "my-prod-account@domain.com",
  "Account Name": "my-prod-account",
  "Account ARN": "arn:aws:organizations::222222222222:account/o-abcde1234/111111111111",
  "Account Organization": "o-abcde1234",
  "Account tags": "\"eyJUYWdzIjpasf0=\""
```

The additional fields in CSV header output are as follows:

- ACCOUNT_DETAILS_EMAIL
- ACCOUNT_DETAILS_NAME
- ACCOUNT_DETAILS_ARN
- ACCOUNT_DETAILS_ORG
- ACCOUNT_DETAILS_TAGS

## Extra: Run Prowler across all accounts in AWS Organizations by assuming roles

If you want to run Prowler across all accounts of AWS Organizations you can do this:

1. First get a list of accounts that are not suspended:

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
    Using the same for loop it can be scanned a list of accounts with a variable like:
    </br>`ACCOUNTS_LIST='11111111111 2222222222 333333333'`
