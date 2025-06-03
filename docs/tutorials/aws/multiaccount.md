# Scanning Multiple AWS Accounts with Prowler

Prowler enables security scanning across multiple AWS accounts by utilizing the  [Assume Role feature](role-assumption.md) and [integration with AWS Organizations feature](organizations.md).

This approach allows execution from a single account with permissions to assume roles in the target accounts.

## Scanning Multiple Accounts Sequentially

To scan specific accounts one at a time:

    - Define a variable containing the AWS account IDs to be scanned:

    ```
    ACCOUNTS_LIST='11111111111 2222222222 333333333'
    ```

    - Run Prowler with an IAM role that exists in all target accounts: (replace the `<role_name>` with to yours, that is to be consistent throughout all accounts):

    ```
    ROLE_TO_ASSUME=<role_name>
        for accountId in $ACCOUNTS_LIST; do
        prowler aws --role arn:aws:iam::$accountId:role/$ROLE_TO_ASSUME
    done
    ```


## Scanning Multiple Accounts in Parallel

    - To scan multiple accounts simultaneously:

    Define the AWS accounts to be scanned with a variable:

    ```
    ACCOUNTS_LIST='11111111111 2222222222 333333333'
    ```

    - Run Prowler with an IAM role that exists in all target accounts: (replace the `<role_name>` with to yours, that is to be consistent throughout all accounts). The following example executes scanning across three accounts in parallel:

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


## Scanning Multiple AWS Organization Accounts in Parallel

Prowler enables parallel security scans across multiple AWS accounts within an AWS Organization.

### Retrieve Active AWS Accounts

To efficiently scan multiple accounts within an AWS Organization, follow these steps:

    - Step 1: Retrieve a List of Active Accounts

    First, declare a variable containing all active accounts in your AWS Organization. Run the following command in your AWS Organizations Management account, ensuring that you have the necessary permissions:

        ```
        ACCOUNTS_IN_ORG=$(aws organizations list-accounts --query Accounts[?Status==`ACTIVE`].Id --output text)
        ```

    - Step 2: Run Prowler with Assumed Roles

    Use Prowler to assume roles across accounts in parallel. Modify <role_name> to match the role that exists in all accounts and <management_organizations_account_id> to your AWS Organizations Management account ID.

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
