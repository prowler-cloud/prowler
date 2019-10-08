#!/bin/bash

mkdir ~/.aws
cat << AWS_CREDS > ~/.aws/credentials
[${ACCOUNT_ID}]
credential_source = EcsContainer
role_arn = ${ROLE_ARN}
external_id = ${EXTERNAL_ID}

AWS_CREDS

echo "Running prowler on ${ACCOUNT_ID}"
./prowler -p "${ACCOUNT_ID}" "${CHECKS}" -M json > output.json

echo "Results:"
cat output.json

echo "Uploading result to s3://${BUCKET}/prowler/${ACCOUNT_ID}/output.json"
aws s3api put-object --bucket "${BUCKET}" --key prowler/"${ACCOUNT_ID}"/output.json --body output.json