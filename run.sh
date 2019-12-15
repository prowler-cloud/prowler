#!/bin/bash

echo "Assuming role for ${ACCOUNT_ID}"
creds=$(aws sts assume-role --role-arn ${ROLE_ARN} --external-id ${EXTERNAL_ID} --role-session-name prowler | jq '.Credentials')
export AWS_ACCESS_KEY_ID=$(echo $creds | jq ".AccessKeyId" | sed 's/\"//g')
export AWS_SECRET_ACCESS_KEY=$(echo $creds | jq ".SecretAccessKey" | sed 's/\"//g')
export AWS_SESSION_TOKEN=$(echo $creds | jq ".SessionToken" | sed 's/\"//g')

echo "Running prowler on ${ACCOUNT_ID}"
./prowler ${CHECKS} -M json > output.json

echo "Results:"
cat output.json

unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY
unset AWS_SESSION_TOKEN

echo "Uploading result to s3://${BUCKET}/prowler/${ACCOUNT_ID}/output.json"
aws s3api put-object --bucket ${BUCKET} --key prowler/$ACCOUNT_ID/output.json --body output.json