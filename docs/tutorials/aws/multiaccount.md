# Scan Multiple AWS Accounts

Prowler can scan multiple accounts when it is executed from one account that can assume a role in those given accounts to scan using [Assume Role feature](role-assumption.md) and [AWS Organizations integration feature](organizations.md).


## Scan multiple specific accounts sequentially

- Declare a variable with all the accounts to scan:

```
ACCOUNTS_LIST='11111111111 2222222222 333333333'
```

- Then run Prowler to assume a role (change `<role_name>` below to yours, that must be the same in all accounts):

```
ROLE_TO_ASSUME=<role_name>
  for accountId in $ACCOUNTS_LIST; do
  prowler aws --role arn:aws:iam::$accountId:role/$ROLE_TO_ASSUME
done
```

## Scan multiple specific accounts in parallel

- Declare a variable with all the accounts to scan:

```
ACCOUNTS_LIST='11111111111 2222222222 333333333'
```

- Then run Prowler to assume a role (change `<role_name>` below to yours, that must be the same in all accounts), in this example it will scan 3 accounts in parallel:

```
ROLE_TO_ASSUME=<role_name>
PARALLEL_ACCOUNTS="3"
for accountId in $ACCOUNTS_LIST; do
    test "$(jobs | wc -l)" -ge $PARALLEL_ACCOUNTS && wait || true
    {
        prowler aws --role arn:aws:iam::$accountId:role/$ROLE_TO_ASSUME
    } &
done
```

## Scan multiple accounts from AWS Organizations in parallel

- Declare a variable with all the accounts to scan. To do so, get the list of your AWS accounts in your AWS Organization by running the following command (will create a variable with all your ACTIVE accounts). Remember to run that command with the permissions needed to get that information in your AWS Organizations Management account.

```
ACCOUNTS_IN_ORG=$(aws organizations list-accounts --query Accounts[?Status==`ACTIVE`].Id --output text)
```

- Then run Prowler to assume a role (change `<role_name>` that must be the same in all accounts and `<management_organizations_account_id>` that must be your AWS Organizations management account ID):

```
ROLE_TO_ASSUME=<role_name>
MGMT_ACCOUNT_ID=<management_organizations_account_id>
PARALLEL_ACCOUNTS="3"
for accountId in $ACCOUNTS_IN_ORG; do
    test "$(jobs | wc -l)" -ge $PARALLEL_ACCOUNTS && wait || true
    {
        prowler aws --role arn:aws:iam::$accountId:role/$ROLE_TO_ASSUME \
        --organizations-role arn:aws:iam::$MGMT_ACCOUNT_ID:role/$ROLE_TO_ASSUME
    } &
done
```
