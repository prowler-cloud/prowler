# AWS Organizations
## Get AWS Account details from your AWS Organization

Prowler allows you to get additional information of the scanned account in CSV and JSON outputs. When scanning a single account you get the Account ID as part of the output.

If you have AWS Organizations Prowler can get your account details like Account Name, Email, ARN, Organization ID and Tags and you will have them next to every finding in the CSV and JSON outputs.

In order to do that you can use the option `-O`/`--organizations-role <organizations_role_arn>`. See the following sample command:

```shell
prowler aws \
  -O arn:aws:iam::<management_organizations_account_id>:role/<role_name>
```
> Make sure the role in your AWS Organizations management account has the permissions `organizations:ListAccounts*` and `organizations:ListTagsForResource`.

In that command Prowler will scan the account and getting the account details from the AWS Organizations management account assuming a role and creating two reports with those details in JSON and CSV.

In the JSON output below (redacted) you can see tags coded in base64 to prevent breaking CSV or JSON due to its format:

```json
  "Account Email": "my-prod-account@domain.com",
  "Account Name": "my-prod-account",
  "Account ARN": "arn:aws:organizations::222222222222:account/o-abcde1234/111111111111",
  "Account Organization": "o-abcde1234",
  "Account tags": "\"eyJUYWdzIjpasf0=\""
```

The additional fields in CSV header output are as follow:

```csv
ACCOUNT_DETAILS_EMAIL,ACCOUNT_DETAILS_NAME,ACCOUNT_DETAILS_ARN,ACCOUNT_DETAILS_ORG,ACCOUNT_DETAILS_TAGS
```

## Extra: run Prowler across all accounts in AWS Organizations by assuming roles

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

> Using the same for loop it can be scanned a list of accounts with a variable like `ACCOUNTS_LIST='11111111111 2222222222 333333333'`
