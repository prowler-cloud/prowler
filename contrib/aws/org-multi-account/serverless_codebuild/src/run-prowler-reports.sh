#!/bin/bash -e
#
# Run Prowler against All AWS Accounts in an AWS Organization

# Change Directory (rest of the script, assumes your in the ec2-user home directory)
# cd /home/ec2-user || exit

# Show Prowler Version, and Download Prowler, if it doesn't already exist
if ! ./prowler/prowler -V 2>/dev/null; then
    git clone https://github.com/prowler-cloud/prowler.git
    ./prowler/prowler -V
fi

# Source .awsvariables (to read in Environment Variables from CloudFormation Data)
# shellcheck disable=SC1091
# source .awsvariables

# Get Values from Environment Variables Created on EC2 Instance from CloudFormation Data
echo "S3:             $S3"
echo "S3ACCOUNT:      $S3ACCOUNT"
echo "ROLE:           $ROLE"
echo "FORMAT:         $FORMAT"

# CleanUp Last Ran Prowler Reports, as they are already stored in S3.
rm -rf prowler/output/*.html

# Function to unset AWS Profile Variables
unset_aws() {
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}
unset_aws

# Find THIS Account AWS Number
CALLER_ARN=$(aws sts get-caller-identity --output text --query "Arn")
PARTITION=$(echo "$CALLER_ARN" | cut -d: -f2)
THISACCOUNT=$(echo "$CALLER_ARN" | cut -d: -f5)
echo "THISACCOUNT:    $THISACCOUNT"
echo "PARTITION:      $PARTITION"

# Function to Assume Role to THIS Account & Create Session
this_account_session() {
    unset_aws
    role_credentials=$(aws sts assume-role --role-arn arn:"$PARTITION":iam::"$THISACCOUNT":role/"$ROLE" --role-session-name ProwlerRun --output json)
    AWS_ACCESS_KEY_ID=$(echo "$role_credentials" | jq -r .Credentials.AccessKeyId)
    AWS_SECRET_ACCESS_KEY=$(echo "$role_credentials" | jq -r .Credentials.SecretAccessKey)
    AWS_SESSION_TOKEN=$(echo "$role_credentials" | jq -r .Credentials.SessionToken)
    echo "this_account_session done..."
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}

# Find AWS Master Account
this_account_session
AWSMASTER=$(aws organizations describe-organization --query Organization.MasterAccountId --output text)
echo "AWSMASTER:      $AWSMASTER"

# Function to Assume Role to Master Account & Create Session
master_account_session() {
    unset_aws
    role_credentials=$(aws sts assume-role --role-arn arn:"$PARTITION":iam::"$AWSMASTER":role/"$ROLE" --role-session-name ProwlerRun --output json)
    AWS_ACCESS_KEY_ID=$(echo "$role_credentials" | jq -r .Credentials.AccessKeyId)
    AWS_SECRET_ACCESS_KEY=$(echo "$role_credentials" | jq -r .Credentials.SecretAccessKey)
    AWS_SESSION_TOKEN=$(echo "$role_credentials" | jq -r .Credentials.SessionToken)
    echo "master_account_session done..."
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}

# Lookup All Accounts in AWS Organization
master_account_session
ACCOUNTS_IN_ORGS=$(aws organizations list-accounts --query Accounts[*].Id --output text)

# Function to Assume Role to S3 Account & Create Session
s3_account_session() {
    unset_aws
    role_credentials=$(aws sts assume-role --role-arn arn:"$PARTITION":iam::"$S3ACCOUNT":role/"$ROLE" --role-session-name ProwlerRun --output json)
    AWS_ACCESS_KEY_ID=$(echo "$role_credentials" | jq -r .Credentials.AccessKeyId)
    AWS_SECRET_ACCESS_KEY=$(echo "$role_credentials" | jq -r .Credentials.SecretAccessKey)
    AWS_SESSION_TOKEN=$(echo "$role_credentials" | jq -r .Credentials.SessionToken)
    echo "s3_account_session done..."
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}

# Run Prowler against Accounts in AWS Organization
echo "AWS Accounts in Organization"
echo "$ACCOUNTS_IN_ORGS"
PARALLEL_ACCOUNTS="1"
for accountId in $ACCOUNTS_IN_ORGS; do
    # shellcheck disable=SC2015
    test "$(jobs | wc -l)" -ge $PARALLEL_ACCOUNTS && wait || true
    {
        START_TIME=$SECONDS
        # Unset AWS Profile Variables
        unset_aws
        # Run Prowler
        echo -e "Assessing AWS Account: $accountId, using Role: $ROLE on $(date)"
        # remove -g cislevel for a full report and add other formats if needed
        ./prowler/prowler -R "$ROLE" -A "$accountId" -g cislevel1 -M $FORMAT -z
        echo "Report stored locally at: prowler/output/ directory"
        TOTAL_SEC=$((SECONDS - START_TIME))
        echo -e "Completed AWS Account: $accountId, using Role: $ROLE on $(date)"
        printf "Completed AWS Account: $accountId in %02dh:%02dm:%02ds" $((TOTAL_SEC / 3600)) $((TOTAL_SEC % 3600 / 60)) $((TOTAL_SEC % 60))
        echo ""
    } &
done

# Wait for All Prowler Processes to finish
wait
echo "Prowler Assessments Completed against All Accounts in the AWS Organization. Starting S3 copy operations..."

# Upload Prowler Report to S3
s3_account_session
aws s3 cp prowler/output/ "$S3/reports/" --recursive --include "*.html" --acl bucket-owner-full-control
echo "Assessment reports successfully copied to S3 bucket"

# Final Wait for All Prowler Processes to finish
wait
echo "Prowler Assessments Completed"

# Unset AWS Profile Variables
unset_aws
