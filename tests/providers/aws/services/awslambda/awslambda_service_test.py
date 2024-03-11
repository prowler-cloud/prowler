import io
import os
import tempfile
import zipfile
from re import search
from unittest.mock import patch

import mock
from boto3 import client, resource
from moto import mock_aws

from prowler.providers.aws.services.awslambda.awslambda_service import AuthType, Lambda
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)

LAMBDA_FUNCTION_CODE = """def lambda_handler(event, context):
print("custom log event")
return event
            """


def create_zip_file(code: str = "") -> io.BytesIO:
    zip_output = io.BytesIO()
    zip_file = zipfile.ZipFile(zip_output, "w", zipfile.ZIP_DEFLATED)
    if not code:
        zip_file.writestr(
            "lambda_function.py",
            LAMBDA_FUNCTION_CODE,
        )
    else:
        zip_file.writestr("lambda_function.py", code)
    zip_file.close()
    zip_output.seek(0)
    return zip_output


def mock_request_get(_):
    """Mock requests.get() to get the Lambda Code in Zip Format"""
    mock_resp = mock.MagicMock
    mock_resp.status_code = 200
    mock_resp.content = create_zip_file().read()
    return mock_resp


# Mock generate_regional_clients()
def mock_generate_regional_clients(provider, service):
    regional_client_eu_west_1 = provider.session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client_us_east_1 = provider.session.current_session.client(
        service, region_name=AWS_REGION_US_EAST_1
    )
    regional_client_eu_west_1.region = AWS_REGION_EU_WEST_1
    regional_client_us_east_1.region = AWS_REGION_US_EAST_1
    return {
        AWS_REGION_EU_WEST_1: regional_client_eu_west_1,
        AWS_REGION_US_EAST_1: regional_client_us_east_1,
    }


@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_Lambda_Service:
    # Test Lambda Client
    def test__get_client__(self):
        awslambda = Lambda(set_mocked_aws_audit_info([AWS_REGION_US_EAST_1]))
        assert (
            awslambda.regional_clients[AWS_REGION_EU_WEST_1].__class__.__name__
            == "Lambda"
        )

    # Test Lambda Session
    def test__get_session__(self):
        awslambda = Lambda(set_mocked_aws_audit_info([AWS_REGION_US_EAST_1]))
        assert awslambda.session.__class__.__name__ == "Session"

    # Test Lambda Service
    def test__get_service__(self):
        awslambda = Lambda(set_mocked_aws_audit_info([AWS_REGION_US_EAST_1]))
        assert awslambda.service == "lambda"

    @mock_aws
    def test__list_functions__(self):
        # Create IAM Lambda Role
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        iam_role = iam_client.create_role(
            RoleName="test-lambda-role",
            AssumeRolePolicyDocument="test-policy",
            Path="/",
        )["Role"]["Arn"]
        # Create S3 Bucket
        s3_client = resource("s3", region_name=AWS_REGION_EU_WEST_1)
        s3_client.create_bucket(
            Bucket="test-bucket",
            CreateBucketConfiguration={"LocationConstraint": AWS_REGION_EU_WEST_1},
        )
        # Create Test Lambda 1
        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        lambda_name_1 = "test-lambda-1"
        resp = lambda_client.create_function(
            FunctionName=lambda_name_1,
            Runtime="python3.7",
            Role=iam_role,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": create_zip_file().read()},
            Description="test lambda function",
            Timeout=3,
            MemorySize=128,
            PackageType="ZIP",
            Publish=True,
            VpcConfig={
                "SecurityGroupIds": ["sg-123abc"],
                "SubnetIds": ["subnet-123abc"],
            },
            Environment={"Variables": {"db-password": "test-password"}},
            Tags={"test": "test"},
        )
        lambda_arn_1 = resp["FunctionArn"]
        # Update Lambda Policy
        lambda_policy = {
            "Version": "2012-10-17",
            "Id": "default",
            "Statement": [
                {
                    "Action": "lambda:GetFunction",
                    "Principal": "*",
                    "Effect": "Allow",
                    "Resource": f"arn:aws:lambda:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:function:{lambda_name_1}",
                    "Sid": "test",
                }
            ],
        }
        _ = lambda_client.add_permission(
            FunctionName=lambda_name_1,
            StatementId="test",
            Action="lambda:GetFunction",
            Principal="*",
        )
        # Create Function URL Config
        _ = lambda_client.create_function_url_config(
            FunctionName=lambda_name_1,
            AuthType=AuthType.AWS_IAM.value,
            Cors={
                "AllowCredentials": True,
                "AllowHeaders": [
                    "string",
                ],
                "AllowMethods": [
                    "string",
                ],
                "AllowOrigins": [
                    "*",
                ],
                "ExposeHeaders": [
                    "string",
                ],
                "MaxAge": 123,
            },
        )

        # Create Test Lambda 2 (with the same attributes but different region)
        lambda_client_2 = client("lambda", region_name=AWS_REGION_US_EAST_1)
        lambda_name_2 = "test-lambda-2"
        resp_2 = lambda_client_2.create_function(
            FunctionName=lambda_name_2,
            Runtime="python3.7",
            Role=iam_role,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": create_zip_file().read()},
            Description="test lambda function",
            Timeout=3,
            MemorySize=128,
            PackageType="ZIP",
            Publish=True,
            VpcConfig={
                "SecurityGroupIds": ["sg-123abc"],
                "SubnetIds": ["subnet-123abc"],
            },
            Environment={"Variables": {"db-password": "test-password"}},
            Tags={"test": "test"},
        )
        lambda_arn_2 = resp_2["FunctionArn"]

        with mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_service.requests.get",
            new=mock_request_get,
        ):
            awslambda = Lambda(
                set_mocked_aws_audit_info(audited_regions=[AWS_REGION_US_EAST_1])
            )
            assert awslambda.functions
            assert len(awslambda.functions) == 2
            # Lambda 1
            assert awslambda.functions[lambda_arn_1].name == lambda_name_1
            assert awslambda.functions[lambda_arn_1].arn == lambda_arn_1
            assert awslambda.functions[lambda_arn_1].runtime == "python3.7"
            assert awslambda.functions[lambda_arn_1].environment == {
                "db-password": "test-password"
            }
            assert awslambda.functions[lambda_arn_1].region == AWS_REGION_EU_WEST_1
            assert awslambda.functions[lambda_arn_1].policy == lambda_policy

            assert awslambda.functions[lambda_arn_1].url_config
            assert (
                awslambda.functions[lambda_arn_1].url_config.auth_type
                == AuthType.AWS_IAM
            )
            assert search(
                "lambda-url.eu-west-1.on.aws",
                awslambda.functions[lambda_arn_1].url_config.url,
            )

            assert awslambda.functions[lambda_arn_1].url_config.cors_config
            assert awslambda.functions[
                lambda_arn_1
            ].url_config.cors_config.allow_origins == ["*"]

            assert awslambda.functions[lambda_arn_1].tags == [{"test": "test"}]

            # Lambda 2
            assert awslambda.functions[lambda_arn_2].name == lambda_name_2
            assert awslambda.functions[lambda_arn_2].arn == lambda_arn_2
            assert awslambda.functions[lambda_arn_2].runtime == "python3.7"
            assert awslambda.functions[lambda_arn_2].environment == {
                "db-password": "test-password"
            }
            assert awslambda.functions[lambda_arn_2].region == AWS_REGION_US_EAST_1
            # Emtpy policy
            assert awslambda.functions[lambda_arn_2].policy == {
                "Id": "default",
                "Statement": [],
                "Version": "2012-10-17",
            }

            # Lambda Code
            with tempfile.TemporaryDirectory() as tmp_dir_name:
                for function, function_code in awslambda.__get_function_code__():
                    if function.arn == lambda_arn_1 or function.arn == lambda_arn_2:
                        assert search(
                            f"s3://awslambda-{function.region}-tasks.s3-{function.region}.amazonaws.com",
                            function_code.location,
                        )
                        assert function_code
                        function_code.code_zip.extractall(tmp_dir_name)
                        files_in_zip = next(os.walk(tmp_dir_name))[2]
                        assert len(files_in_zip) == 1
                        assert files_in_zip[0] == "lambda_function.py"
                        with open(
                            f"{tmp_dir_name}/{files_in_zip[0]}", "r"
                        ) as lambda_code_file:
                            assert lambda_code_file.read() == LAMBDA_FUNCTION_CODE
