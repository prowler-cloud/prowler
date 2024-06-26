import io
from json import dumps

import botocore
import yaml
from boto3 import client, resource
from mock import patch
from moto import mock_aws

from prowler.config.config import enconding_format_utf_8
from prowler.providers.aws.lib.mutelist.mutelist import (
    get_mutelist_file_from_dynamodb,
    get_mutelist_file_from_lambda,
    get_mutelist_file_from_s3,
)
from tests.providers.aws.services.awslambda.awslambda_service_test import (
    create_zip_file,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "Invoke":
        return {
            "Payload": io.BytesIO(
                dumps(
                    {
                        "Mutelist": {
                            "Accounts": {
                                "*": {
                                    "Checks": {
                                        "*": {
                                            "Regions": ["*"],
                                            "Resources": ["*"],
                                            "Tags": ["key:value"],
                                        },
                                    }
                                },
                            }
                        }
                    }
                ).encode(enconding_format_utf_8)
            )
        }

    return make_api_call(self, operation_name, kwarg)


class TestMutelistAWS:
    @mock_aws
    def test_get_mutelist_file_from_s3(self):
        aws_provider = set_mocked_aws_provider()
        # Create bucket and upload mutelist yaml
        s3_resource = resource("s3", region_name=AWS_REGION_US_EAST_1)
        s3_resource.create_bucket(Bucket="test-mutelist")
        s3_resource.Object("test-mutelist", "mutelist.yaml").put(
            Body=open(
                "tests/lib/mutelist/fixtures/aws_mutelist.yaml",
                "rb",
            )
        )

        with open("tests/lib/mutelist/fixtures/aws_mutelist.yaml") as f:
            fixture_mutelist = yaml.safe_load(f)["Mutelist"]

        assert (
            get_mutelist_file_from_s3(
                "s3://test-mutelist/mutelist.yaml",
                aws_provider.session.current_session,
            )
            == fixture_mutelist
        )

    @mock_aws
    def test_get_mutelist_file_from_s3_not_present(self):
        aws_provider = set_mocked_aws_provider()

        assert (
            get_mutelist_file_from_s3(
                "s3://test-mutelist/mutelist.yaml",
                aws_provider.session.current_session,
            )
            == {}
        )

    @mock_aws
    def test_get_mutelist_file_from_dynamodb(self):
        aws_provider = set_mocked_aws_provider()
        # Create table and put item
        dynamodb_resource = resource("dynamodb", region_name=AWS_REGION_US_EAST_1)
        table_name = "test-mutelist"
        table_arn = f"arn:aws:dynamodb:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:table/{table_name}"
        params = {
            "TableName": table_name,
            "KeySchema": [
                {"AttributeName": "Accounts", "KeyType": "HASH"},
                {"AttributeName": "Checks", "KeyType": "RANGE"},
            ],
            "AttributeDefinitions": [
                {"AttributeName": "Accounts", "AttributeType": "S"},
                {"AttributeName": "Checks", "AttributeType": "S"},
            ],
            "ProvisionedThroughput": {
                "ReadCapacityUnits": 10,
                "WriteCapacityUnits": 10,
            },
        }
        table = dynamodb_resource.create_table(**params)
        dynamo_db_mutelist = {
            "Accounts": "*",
            "Checks": "iam_user_hardware_mfa_enabled",
            "Regions": [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            "Resources": ["keyword"],
            "Exceptions": {},
        }
        mutelist = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "iam_user_hardware_mfa_enabled": {
                            "Regions": [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
                            "Resources": ["keyword"],
                            "Exceptions": {},
                        },
                    }
                },
            }
        }
        table.put_item(Item=dynamo_db_mutelist)

        assert (
            get_mutelist_file_from_dynamodb(
                table_arn,
                aws_provider.session.current_session,
                aws_provider.identity.account,
            )
            == mutelist
        )

    @mock_aws
    def test_get_mutelist_file_from_dynamodb_with_tags(self):
        aws_provider = set_mocked_aws_provider()
        # Create table and put item
        dynamodb_resource = resource("dynamodb", region_name=AWS_REGION_US_EAST_1)
        table_name = "test-mutelist"
        table_arn = f"arn:aws:dynamodb:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:table/{table_name}"
        params = {
            "TableName": table_name,
            "KeySchema": [
                {"AttributeName": "Accounts", "KeyType": "HASH"},
                {"AttributeName": "Checks", "KeyType": "RANGE"},
            ],
            "AttributeDefinitions": [
                {"AttributeName": "Accounts", "AttributeType": "S"},
                {"AttributeName": "Checks", "AttributeType": "S"},
            ],
            "ProvisionedThroughput": {
                "ReadCapacityUnits": 10,
                "WriteCapacityUnits": 10,
            },
        }
        table = dynamodb_resource.create_table(**params)
        dynamo_db_mutelist = {
            "Accounts": "*",
            "Checks": "*",
            "Regions": ["*"],
            "Resources": ["*"],
            "Tags": ["environment=dev"],
        }
        mutelist = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "*": {
                            "Regions": ["*"],
                            "Resources": ["*"],
                            "Tags": ["environment=dev"],
                        },
                    }
                },
            }
        }
        table.put_item(Item=dynamo_db_mutelist)

        assert (
            get_mutelist_file_from_dynamodb(
                table_arn,
                aws_provider.session.current_session,
                aws_provider.identity.account,
            )
            == mutelist
        )

    @mock_aws
    def test_get_mutelist_file_from_dynamodb_not_present(self):
        aws_provider = set_mocked_aws_provider()
        table_name = "non-existent"
        table_arn = f"arn:aws:dynamodb:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:table/{table_name}"
        assert (
            get_mutelist_file_from_dynamodb(
                table_arn,
                aws_provider.session.current_session,
                aws_provider.identity.account,
            )
            == {}
        )

    @mock_aws(config={"lambda": {"use_docker": False}})
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_get_mutelist_file_from_lambda(self):
        aws_provider = set_mocked_aws_provider()
        lambda_name = "mutelist"
        lambda_role = "lambda_role"
        lambda_client = client("lambda", region_name=AWS_REGION_US_EAST_1)
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        lambda_role_assume_policy = {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "test",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"},
                "Action": "sts:AssumeRole",
            },
        }
        lambda_role_arn = iam_client.create_role(
            RoleName=lambda_role,
            AssumeRolePolicyDocument=dumps(lambda_role_assume_policy),
        )["Role"]["Arn"]
        lambda_code = """def handler(event, context):
  checks = {}
  checks["*"] = { "Regions": [ "*" ], "Resources": [ "" ], Optional("Tags"): [ "key:value" ] }

  al = { "Mutelist": { "Accounts": { "*": { "Checks": checks } } } }
  return al"""

        lambda_function = lambda_client.create_function(
            FunctionName=lambda_name,
            Runtime="3.9",
            Role=lambda_role_arn,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": create_zip_file(code=lambda_code).read()},
            Description="test lambda function",
        )
        lambda_function_arn = lambda_function["FunctionArn"]
        mutelist = {
            "Accounts": {
                "*": {
                    "Checks": {
                        "*": {
                            "Regions": ["*"],
                            "Resources": ["*"],
                            "Tags": ["key:value"],
                        },
                    }
                },
            }
        }

        assert (
            get_mutelist_file_from_lambda(
                lambda_function_arn, aws_provider.session.current_session
            )
            == mutelist
        )

    @mock_aws
    def test_get_mutelist_file_from_lambda_invalid_arn(self):
        aws_provider = set_mocked_aws_provider()
        lambda_function_arn = "invalid_arn"

        assert (
            get_mutelist_file_from_lambda(
                lambda_function_arn, aws_provider.session.current_session
            )
            == {}
        )
