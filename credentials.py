import boto3
import sys
import json
import os

sts = boto3.client('sts')
aws_lambda = boto3.client('lambda', region_name='us-west-2')

aws_account_id = sys.argv[1]

if aws_account_id is None:
    raise ValueError('Must provide an AWS account ID')

account_details_response = aws_lambda.invoke(
    FunctionName='customers-api',
    Payload=json.dumps({"path": "/invoke/getTenantDetails", "body": {"awsAccountId": sys.argv[1]}, "headers": {"Content-Type": "application/json"}}).encode('utf-8')
)

account_details = json.loads(json.loads(account_details_response['Payload'].read())['body'])

print('Got account details, assuming role')

temporary_creds = sts.assume_role(RoleArn=account_details['cross_account_role_arn'], ExternalId=account_details['external_id'], RoleSessionName='prowler')['Credentials']

os.environ['AWS_ACCESS_KEY_ID2'] = temporary_creds['AccessKeyId']
os.environ['AWS_SECRET_ACCESS_KEY2'] = temporary_creds['SecretAccessKey']
