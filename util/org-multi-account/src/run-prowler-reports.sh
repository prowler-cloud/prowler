#!/bin/bash -e
#
# Run Prowler against All AWS Accounts in an AWS Organization

# Change Directory (rest of the script, assumes your in the ec2-user home directory)
cd /home/ec2-user

# Download Prowler
rm -rf prowler
git clone https://github.com/toniblyx/prowler.git

# Source .awsvariables (to read in Environment Variables from CloudFormation Data)
# shellcheck disable=SC1091
source .awsvariables

# Get Values from Environment Variables Created on EC2 Instance from CloudFormation Data
echo "S3:             $S3"
echo "S3ACCOUNT:      $S3ACCOUNT"
echo "ROLE:           $ROLE"

# Create Folder to Store Prowler Reports
mkdir -p prowler-reports

# CleanUp Last Ran Prowler Reports
rm -rf prowler-reports/*.html

# Function to unset AWS Profile Variables
unset_aws() {
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}
unset_aws

# Find THIS Account AWS Number
THISACCOUNT=$(aws sts get-caller-identity --output text --query Account)
PARTITION=$(aws sts get-caller-identity --output text --query Arn | cut -d: -f2)
echo "THISACCOUNT:    $THISACCOUNT"
echo "PARTITION:      $PARTITION"

# Function to Assume Role to THIS Account & Create Session
this_account_session() {
    unset_aws
    role_credentials=$(aws sts assume-role --role-arn arn:"$PARTITION":iam::"$THISACCOUNT":role/"$ROLE" --role-session-name ProwlerRun --output json)
    AWS_ACCESS_KEY_ID=$(echo "$role_credentials" | jq -r .Credentials.AccessKeyId)
    AWS_SECRET_ACCESS_KEY=$(echo "$role_credentials" | jq -r .Credentials.SecretAccessKey)
    AWS_SESSION_TOKEN=$(echo "$role_credentials" | jq -r .Credentials.SessionToken)
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
    export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
}

# Run Prowler against Accounts in AWS Organization
echo "AWS Accounts in Organization"
echo "$ACCOUNTS_IN_ORGS"
for accountId in $ACCOUNTS_IN_ORGS; do
    # Unset AWS Profile Variables
    unset_aws
    # Run Prowler
    Report="prowler-reports/$(date +'%Y-%m-%d-%H%M%P')-$accountId-report.html"
    echo -e "Analyzing AWS Account: $accountId, using Role: $ROLE"
    ./prowler/prowler -R "$ROLE" -A "$accountId" -c check29 | ansi2html -la >"$Report"
    echo "Report stored locally at: $Report"
    # Upload Prowler Report to S3
    s3_account_session
    aws s3 cp "$Report" "$S3/reports/"
    echo ""
done
