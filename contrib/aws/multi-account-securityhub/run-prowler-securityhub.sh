#!/bin/bash
# Run Prowler against All AWS Accounts in an AWS Organization

# Activate Poetry Environment
eval "$(poetry env activate)"

# Show Prowler Version
prowler -v

# Source .awsvariables
# shellcheck disable=SC1091
source .awsvariables

# Get Values from Environment Variables
echo "ROLE:               ${ROLE}"
echo "PARALLEL_ACCOUNTS:  ${PARALLEL_ACCOUNTS}"
echo "REGION:             ${REGION}"

# Function to unset AWS Profile Variables
unset_aws() {
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}
unset_aws

# Find THIS Account AWS Number
CALLER_ARN=$(aws sts get-caller-identity --output text --query "Arn")
PARTITION=$(echo "${CALLER_ARN}" | cut -d: -f2)
THISACCOUNT=$(echo "${CALLER_ARN}" | cut -d: -f5)
echo "THISACCOUNT:    ${THISACCOUNT}"
echo "PARTITION:      ${PARTITION}"

# Function to Assume Role to THIS Account & Create Session
this_account_session() {
    unset_aws
    role_credentials=$(aws sts assume-role --role-arn arn:"${PARTITION}":iam::"${THISACCOUNT}":role/"${ROLE}" --role-session-name ProwlerRun --output json)
    AWS_ACCESS_KEY_ID=$(echo "${role_credentials}" | jq -r .Credentials.AccessKeyId)
    AWS_SECRET_ACCESS_KEY=$(echo "${role_credentials}" | jq -r .Credentials.SecretAccessKey)
    AWS_SESSION_TOKEN=$(echo "${role_credentials}" | jq -r .Credentials.SessionToken)
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}

# Find AWS Master Account
this_account_session
AWSMASTER=$(aws organizations describe-organization --query Organization.MasterAccountId --output text)
echo "AWSMASTER:      ${AWSMASTER}"

# Function to Assume Role to Master Account & Create Session
master_account_session() {
    unset_aws
    role_credentials=$(aws sts assume-role --role-arn arn:"${PARTITION}":iam::"${AWSMASTER}":role/"${ROLE}" --role-session-name ProwlerRun --output json)
    AWS_ACCESS_KEY_ID=$(echo "${role_credentials}" | jq -r .Credentials.AccessKeyId)
    AWS_SECRET_ACCESS_KEY=$(echo "${role_credentials}" | jq -r .Credentials.SecretAccessKey)
    AWS_SESSION_TOKEN=$(echo "${role_credentials}" | jq -r .Credentials.SessionToken)
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}

# Lookup All Accounts in AWS Organization
master_account_session
ACCOUNTS_IN_ORGS=$(aws organizations list-accounts --query Accounts[*].Id --output text)

# Run Prowler against Accounts in AWS Organization
echo "AWS Accounts in Organization"
echo "${ACCOUNTS_IN_ORGS}"
for accountId in ${ACCOUNTS_IN_ORGS}; do
    # shellcheck disable=SC2015
    test "$(jobs | wc -l)" -ge "${PARALLEL_ACCOUNTS}" && wait -n || true
    {
        START_TIME=${SECONDS}
        # Unset AWS Profile Variables
        unset_aws
        # Run Prowler
        echo -e "Assessing AWS Account: ${accountId}, using Role: ${ROLE} on $(date)"
        # Pipe stdout to /dev/null to reduce unnecessary Cloudwatch logs
        prowler aws -R arn:"${PARTITION}":iam::"${accountId}":role/"${ROLE}" --security-hub --send-sh-only-fails -f "${REGION}" > /dev/null
        TOTAL_SEC=$((SECONDS - START_TIME))
        printf "Completed AWS Account: ${accountId} in %02dh:%02dm:%02ds" $((TOTAL_SEC / 3600)) $((TOTAL_SEC % 3600 / 60)) $((TOTAL_SEC % 60))
        echo ""
    } &
done

# Wait for All Prowler Processes to finish
wait
echo "Prowler Assessments Completed against All Accounts in AWS Organization"

# Unset AWS Profile Variables
unset_aws
