#!/usr/bin/env sh

# This value is random. The only requirement is that it is not empty.
export AWS_SECURITY_TOKEN=LSIAXXXXXXXXXXXXXXXXX

# Set the endpoint URL pointing to LocalStack
export AWS_ENDPOINT_URL=http://localhost.localstack.cloud:4566
export AWS_ENDPOINT_URL_S3=http://localhost.localstack.cloud:4566

# Assume the role and get temporary credentials
TEMP_CREDENTIALS=$(aws sts assume-role --role-arn "arn:aws:iam::000000000000:role/demo" --role-session-name "sessionName")

# Extract AccessKeyId and SecretAccessKey from JSON
AWS_ACCESS_KEY_ID=$(echo "$TEMP_CREDENTIALS" | jq -r '.Credentials.AccessKeyId')
AWS_SECRET_ACCESS_KEY=$(echo "$TEMP_CREDENTIALS" | jq -r '.Credentials.SecretAccessKey')
AWS_SECURITY_TOKEN=$(echo "$TEMP_CREDENTIALS" | jq -r '.Credentials.SessionToken')

# Write to .env file
cat <<EOF > .env
export AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
export AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
export AWS_SECURITY_TOKEN=$AWS_SECURITY_TOKEN
export AWS_DEFAULT_REGION=us-east-1
export AWS_ENDPOINT_URL=http://localhost.localstack.cloud:4566
export AWS_ENDPOINT_URL_S3=http://localhost.localstack.cloud:4566
export AWS_ROLE_ARN=arn:aws:iam::000000000000:role/demo
export PROWLER_LOCAL_DEBUG=1
EOF

echo ".env file generated successfully"
