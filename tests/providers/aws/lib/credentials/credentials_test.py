import re

import boto3
import botocore
from mock import patch
from moto import mock_iam, mock_sts

from prowler.providers.aws.lib.arn.arn import parse_iam_credentials_arn
from prowler.providers.aws.lib.credentials.credentials import validate_aws_credentials

AWS_ACCOUNT_NUMBER = "123456789012"


# Mocking GetCallerIdentity for China and GovCloud
make_api_call = botocore.client.BaseClient._make_api_call


def mock_get_caller_identity_china(self, operation_name, kwarg):
    if operation_name == "GetCallerIdentity":
        return {
            "UserId": "XXXXXXXXXXXXXXXXXXXXX",
            "Account": AWS_ACCOUNT_NUMBER,
            "Arn": f"arn:aws-cn:iam::{AWS_ACCOUNT_NUMBER}:user/test-user",
        }

    return make_api_call(self, operation_name, kwarg)


def mock_get_caller_identity_gov_cloud(self, operation_name, kwarg):
    if operation_name == "GetCallerIdentity":
        return {
            "UserId": "XXXXXXXXXXXXXXXXXXXXX",
            "Account": AWS_ACCOUNT_NUMBER,
            "Arn": f"arn:aws-us-gov:iam::{AWS_ACCOUNT_NUMBER}:user/test-user",
        }

    return make_api_call(self, operation_name, kwarg)


class Test_AWS_Credentials:
    @mock_sts
    @mock_iam
    def test_validate_credentials_commercial_partition_with_regions(self):
        # AWS Region for AWS COMMERCIAL
        aws_region = "eu-west-1"
        aws_partition = "aws"
        # Create a mock IAM user
        iam_client = boto3.client("iam", region_name=aws_region)
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]

        # Create AWS session to validate
        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=aws_region,
        )

        get_caller_identity = validate_aws_credentials(session, [aws_region])

        assert get_caller_identity["region"] == aws_region

        caller_identity_arn = parse_iam_credentials_arn(get_caller_identity["Arn"])

        assert caller_identity_arn.partition == aws_partition
        assert caller_identity_arn.region is None
        assert caller_identity_arn.resource == "test-user"
        assert caller_identity_arn.resource_type == "user"
        assert re.match("[0-9a-zA-Z]{20}", get_caller_identity["UserId"])
        assert get_caller_identity["Account"] == AWS_ACCOUNT_NUMBER

    @mock_sts
    @mock_iam
    def test_validate_credentials_commercial_partition_with_regions_none_and_profile_region_so_profile_region(
        self,
    ):
        # AWS Region for AWS COMMERCIAL
        aws_region = "eu-west-1"
        aws_partition = "aws"
        # Create a mock IAM user
        iam_client = boto3.client("iam", region_name=aws_region)
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]

        # Create AWS session to validate
        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=aws_region,
        )

        get_caller_identity = validate_aws_credentials(session, None)

        assert get_caller_identity["region"] == aws_region

        caller_identity_arn = parse_iam_credentials_arn(get_caller_identity["Arn"])

        assert caller_identity_arn.partition == aws_partition
        assert caller_identity_arn.region is None
        assert caller_identity_arn.resource == "test-user"
        assert caller_identity_arn.resource_type == "user"
        assert re.match("[0-9a-zA-Z]{20}", get_caller_identity["UserId"])
        assert get_caller_identity["Account"] == AWS_ACCOUNT_NUMBER

    @mock_sts
    @mock_iam
    def test_validate_credentials_commercial_partition_with_0_regions_and_profile_region_so_profile_region(
        self,
    ):
        # AWS Region for AWS COMMERCIAL
        aws_region = "eu-west-1"
        aws_partition = "aws"
        # Create a mock IAM user
        iam_client = boto3.client("iam", region_name=aws_region)
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]

        # Create AWS session to validate
        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=aws_region,
        )

        get_caller_identity = validate_aws_credentials(session, [])

        assert get_caller_identity["region"] == aws_region

        caller_identity_arn = parse_iam_credentials_arn(get_caller_identity["Arn"])

        assert caller_identity_arn.partition == aws_partition
        assert caller_identity_arn.region is None
        assert caller_identity_arn.resource == "test-user"
        assert caller_identity_arn.resource_type == "user"
        assert re.match("[0-9a-zA-Z]{20}", get_caller_identity["UserId"])
        assert get_caller_identity["Account"] == AWS_ACCOUNT_NUMBER

    @mock_sts
    @mock_iam
    def test_validate_credentials_commercial_partition_without_regions_and_profile_region_so_us_east_1(
        self,
    ):
        # AWS Region for AWS COMMERCIAL
        aws_region = "eu-west-1"
        aws_partition = "aws"
        # Create a mock IAM user
        iam_client = boto3.client("iam", region_name=aws_region)
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]

        # Create AWS session to validate
        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=None,
        )

        get_caller_identity = validate_aws_credentials(session, [])

        assert get_caller_identity["region"] == "us-east-1"

        caller_identity_arn = parse_iam_credentials_arn(get_caller_identity["Arn"])

        assert caller_identity_arn.partition == aws_partition
        assert caller_identity_arn.region is None
        assert caller_identity_arn.resource == "test-user"
        assert caller_identity_arn.resource_type == "user"
        assert re.match("[0-9a-zA-Z]{20}", get_caller_identity["UserId"])
        assert get_caller_identity["Account"] == AWS_ACCOUNT_NUMBER

    @mock_sts
    @mock_iam
    def test_validate_credentials_china_partition_without_regions_and_profile_region_so_us_east_1(
        self,
    ):
        # AWS Region for AWS COMMERCIAL
        aws_region = "eu-west-1"
        aws_partition = "aws"
        # Create a mock IAM user
        iam_client = boto3.client("iam", region_name=aws_region)
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]

        # Create AWS session to validate
        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=None,
        )

        get_caller_identity = validate_aws_credentials(session, [])

        assert get_caller_identity["region"] == "us-east-1"

        caller_identity_arn = parse_iam_credentials_arn(get_caller_identity["Arn"])

        assert caller_identity_arn.partition == aws_partition
        assert caller_identity_arn.region is None
        assert caller_identity_arn.resource == "test-user"
        assert caller_identity_arn.resource_type == "user"
        assert re.match("[0-9a-zA-Z]{20}", get_caller_identity["UserId"])
        assert get_caller_identity["Account"] == AWS_ACCOUNT_NUMBER

    @mock_sts
    @mock_iam
    @patch(
        "botocore.client.BaseClient._make_api_call", new=mock_get_caller_identity_china
    )
    def test_validate_credentials_china_partition(self):
        # AWS Region for AWS CHINA
        aws_region = "cn-north-1"
        aws_partition = "aws-cn"
        # Create a mock IAM user
        iam_client = boto3.client("iam", region_name=aws_region)
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]

        # Create AWS session to validate
        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=aws_region,
        )

        get_caller_identity = validate_aws_credentials(session, [aws_region])

        # To use GovCloud or China it is either required:
        # - Set the AWS profile region with a valid partition region
        # - Use the -f/--region with a valid partition region
        assert get_caller_identity["region"] == aws_region

        caller_identity_arn = parse_iam_credentials_arn(get_caller_identity["Arn"])

        assert caller_identity_arn.partition == aws_partition
        assert caller_identity_arn.region is None
        assert caller_identity_arn.resource == "test-user"
        assert caller_identity_arn.resource_type == "user"
        assert re.match("[0-9a-zA-Z]{20}", get_caller_identity["UserId"])
        assert get_caller_identity["Account"] == AWS_ACCOUNT_NUMBER

    @mock_sts
    @mock_iam
    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_get_caller_identity_gov_cloud,
    )
    def test_validate_credentials_gov_cloud_partition(self):
        # AWS Region for US GOV CLOUD
        aws_region = "us-gov-east-1"
        aws_partition = "aws-us-gov"
        # Create a mock IAM user
        iam_client = boto3.client("iam", region_name=aws_region)
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]

        # Create AWS session to validate
        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=aws_region,
        )

        get_caller_identity = validate_aws_credentials(session, [aws_region])

        # To use GovCloud or China it is either required:
        # - Set the AWS profile region with a valid partition region
        # - Use the -f/--region with a valid partition region
        assert get_caller_identity["region"] == aws_region

        caller_identity_arn = parse_iam_credentials_arn(get_caller_identity["Arn"])

        assert caller_identity_arn.partition == aws_partition
        assert caller_identity_arn.region is None
        assert caller_identity_arn.resource == "test-user"
        assert caller_identity_arn.resource_type == "user"
        assert re.match("[0-9a-zA-Z]{20}", get_caller_identity["UserId"])
        assert get_caller_identity["Account"] == AWS_ACCOUNT_NUMBER
