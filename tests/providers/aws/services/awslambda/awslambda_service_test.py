import io
import os
import tempfile
import zipfile
from re import search
from unittest.mock import patch

import mock
import pytest
from boto3 import client, resource
from botocore.client import ClientError
from moto import mock_aws

from prowler.providers.aws.services.awslambda.awslambda_service import (
    AuthType,
    Function,
    Lambda,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
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
    def test_get_client(self):
        awslambda = Lambda(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))
        assert (
            awslambda.regional_clients[AWS_REGION_EU_WEST_1].__class__.__name__
            == "Lambda"
        )

    # Test Lambda Session
    def test__get_session__(self):
        awslambda = Lambda(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))
        assert awslambda.session.__class__.__name__ == "Session"

    # Test Lambda Service
    def test__get_service__(self):
        awslambda = Lambda(set_mocked_aws_provider([AWS_REGION_US_EAST_1]))
        assert awslambda.service == "lambda"

    def test_function_limit_selects_latest_functions_for_analysis(self):
        awslambda = Lambda.__new__(Lambda)
        awslambda.functions = {
            "old": Function(
                name="old",
                arn="old",
                security_groups=[],
                last_modified="2024-01-01T00:00:00.000+0000",
                region=AWS_REGION_EU_WEST_1,
            ),
            "new": Function(
                name="new",
                arn="new",
                security_groups=[],
                last_modified="2024-01-02T00:00:00.000+0000",
                region=AWS_REGION_EU_WEST_1,
            ),
        }
        awslambda.function_limit = 1

        awslambda._select_functions_for_analysis()

        assert list(awslambda.functions) == ["new"]

    def test_function_limit_selects_global_latest_across_regions(self):
        class FakePaginator:
            def __init__(self, functions):
                self.functions = functions

            def paginate(self, **kwargs):
                assert "PageSize" not in kwargs
                return [{"Functions": self.functions}]

        class FakeLambdaClient:
            def __init__(self, region, functions):
                self.region = region
                self.functions = functions

            def get_paginator(self, name):
                assert name == "list_functions"
                return FakePaginator(self.functions)

        awslambda = Lambda.__new__(Lambda)
        awslambda.functions = {}
        awslambda.security_groups_in_use = set()
        awslambda.regions_with_functions = set()
        awslambda.function_limit = 1
        awslambda.audit_resources = []
        old_client = FakeLambdaClient(
            AWS_REGION_EU_WEST_1,
            [
                {
                    "FunctionName": "old",
                    "FunctionArn": "arn:aws:lambda:eu-west-1:123456789012:function:old",
                    "LastModified": "2024-01-01T00:00:00.000+0000",
                }
            ],
        )
        new_client = FakeLambdaClient(
            AWS_REGION_US_EAST_1,
            [
                {
                    "FunctionName": "new",
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:new",
                    "LastModified": "2024-01-02T00:00:00.000+0000",
                }
            ],
        )

        awslambda._list_functions(old_client)
        awslambda._list_functions(new_client)
        awslambda._select_functions_for_analysis()

        assert [function.name for function in awslambda.functions.values()] == ["new"]

    def test_function_limit_keeps_complete_auxiliary_indexes(self):
        class FakePaginator:
            def __init__(self, functions):
                self.functions = functions

            def paginate(self, **kwargs):
                assert "PageSize" not in kwargs
                return [{"Functions": self.functions}]

        class FakeLambdaClient:
            region = AWS_REGION_US_EAST_1

            def get_paginator(self, name):
                assert name == "list_functions"
                return FakePaginator(
                    [
                        {
                            "FunctionName": "old",
                            "FunctionArn": (
                                f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:"
                                f"{AWS_ACCOUNT_NUMBER}:function:old"
                            ),
                            "LastModified": "2024-01-01T00:00:00.000+0000",
                            "VpcConfig": {"SecurityGroupIds": ["sg-old"]},
                        },
                        {
                            "FunctionName": "new",
                            "FunctionArn": (
                                f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:"
                                f"{AWS_ACCOUNT_NUMBER}:function:new"
                            ),
                            "LastModified": "2024-01-02T00:00:00.000+0000",
                            "VpcConfig": {"SecurityGroupIds": ["sg-new"]},
                        },
                    ]
                )

        awslambda = Lambda.__new__(Lambda)
        awslambda.functions = {}
        awslambda.security_groups_in_use = set()
        awslambda.regions_with_functions = set()
        awslambda.function_limit = 1
        awslambda.audit_resources = []

        awslambda._list_functions(FakeLambdaClient())
        awslambda._select_functions_for_analysis()

        assert [function.name for function in awslambda.functions.values()] == ["new"]
        assert awslambda.security_groups_in_use == {"sg-old", "sg-new"}
        assert awslambda.regions_with_functions == {AWS_REGION_US_EAST_1}

    def test_list_event_source_mappings_uses_selected_functions_as_api_scope(self):
        class FakePaginator:
            def __init__(self):
                self.paginate_calls = []

            def paginate(self, **kwargs):
                self.paginate_calls.append(kwargs)
                function_name = kwargs["FunctionName"]
                return [
                    {
                        "EventSourceMappings": [
                            {
                                "UUID": f"{function_name}-mapping",
                                "FunctionArn": (
                                    f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:"
                                    f"{AWS_ACCOUNT_NUMBER}:function:{function_name}:1"
                                ),
                                "EventSourceArn": "arn:aws:sqs:queue",
                                "State": "Enabled",
                                "BatchSize": 10,
                            }
                        ]
                    }
                ]

        class FakeLambdaClient:
            region = AWS_REGION_US_EAST_1

            def __init__(self):
                self.paginator = FakePaginator()

            def get_paginator(self, name):
                assert name == "list_event_source_mappings"
                return self.paginator

        selected_arn = (
            f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:"
            f"{AWS_ACCOUNT_NUMBER}:function:selected"
        )
        other_region_arn = (
            f"arn:aws:lambda:{AWS_REGION_EU_WEST_1}:"
            f"{AWS_ACCOUNT_NUMBER}:function:other-region"
        )
        awslambda = Lambda.__new__(Lambda)
        awslambda.function_limit = 1
        awslambda.functions = {
            selected_arn: Function(
                name="selected",
                arn=selected_arn,
                security_groups=[],
                region=AWS_REGION_US_EAST_1,
            ),
            other_region_arn: Function(
                name="other-region",
                arn=other_region_arn,
                security_groups=[],
                region=AWS_REGION_EU_WEST_1,
            ),
        }
        regional_client = FakeLambdaClient()

        awslambda._list_event_source_mappings(regional_client)

        assert regional_client.paginator.paginate_calls == [
            {"FunctionName": "selected"}
        ]
        assert len(awslambda.functions[selected_arn].event_source_mappings) == 1
        assert (
            awslambda.functions[selected_arn].event_source_mappings[0].uuid
            == "selected-mapping"
        )
        assert not awslambda.functions[other_region_arn].event_source_mappings

    def test_list_event_source_mappings_keeps_unlimited_regional_api_scope(self):
        class FakePaginator:
            def __init__(self):
                self.paginate_calls = []

            def paginate(self, **kwargs):
                self.paginate_calls.append(kwargs)
                return [
                    {
                        "EventSourceMappings": [
                            {
                                "UUID": "selected-mapping",
                                "FunctionArn": selected_arn,
                                "EventSourceArn": "arn:aws:sqs:queue",
                                "State": "Enabled",
                            }
                        ]
                    }
                ]

        class FakeLambdaClient:
            region = AWS_REGION_US_EAST_1

            def __init__(self):
                self.paginator = FakePaginator()

            def get_paginator(self, name):
                assert name == "list_event_source_mappings"
                return self.paginator

        selected_arn = (
            f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:"
            f"{AWS_ACCOUNT_NUMBER}:function:selected"
        )
        awslambda = Lambda.__new__(Lambda)
        awslambda.function_limit = None
        awslambda.functions = {
            selected_arn: Function(
                name="selected",
                arn=selected_arn,
                security_groups=[],
                region=AWS_REGION_US_EAST_1,
            )
        }
        regional_client = FakeLambdaClient()

        awslambda._list_event_source_mappings(regional_client)

        assert regional_client.paginator.paginate_calls == [{}]
        assert len(awslambda.functions[selected_arn].event_source_mappings) == 1

    def test_list_event_source_mappings_continues_after_invalid_parameter_value(self):
        class FakePaginator:
            def paginate(self, **kwargs):
                function_name = kwargs["FunctionName"]
                if function_name == "deleted":
                    raise ClientError(
                        {
                            "Error": {
                                "Code": "InvalidParameterValueException",
                                "Message": "Function no longer exists",
                            }
                        },
                        "ListEventSourceMappings",
                    )
                return [
                    {
                        "EventSourceMappings": [
                            {
                                "UUID": f"{function_name}-mapping",
                                "FunctionArn": (
                                    f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:"
                                    f"{AWS_ACCOUNT_NUMBER}:function:{function_name}"
                                ),
                                "EventSourceArn": "arn:aws:sqs:queue",
                                "State": "Enabled",
                            }
                        ]
                    }
                ]

        class FakeLambdaClient:
            region = AWS_REGION_US_EAST_1

            def get_paginator(self, name):
                assert name == "list_event_source_mappings"
                return FakePaginator()

        deleted_arn = (
            f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:"
            f"{AWS_ACCOUNT_NUMBER}:function:deleted"
        )
        remaining_arn = (
            f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:"
            f"{AWS_ACCOUNT_NUMBER}:function:remaining"
        )
        awslambda = Lambda.__new__(Lambda)
        awslambda.function_limit = 2
        awslambda.functions = {
            deleted_arn: Function(
                name="deleted",
                arn=deleted_arn,
                security_groups=[],
                region=AWS_REGION_US_EAST_1,
            ),
            remaining_arn: Function(
                name="remaining",
                arn=remaining_arn,
                security_groups=[],
                region=AWS_REGION_US_EAST_1,
            ),
        }

        awslambda._list_event_source_mappings(FakeLambdaClient())

        assert not awslambda.functions[deleted_arn].event_source_mappings
        assert len(awslambda.functions[remaining_arn].event_source_mappings) == 1
        assert (
            awslambda.functions[remaining_arn].event_source_mappings[0].uuid
            == "remaining-mapping"
        )

    def test_list_event_source_mappings_raises_non_transient_client_error(self):
        class FakePaginator:
            def paginate(self, **kwargs):
                raise ClientError(
                    {
                        "Error": {
                            "Code": "AccessDeniedException",
                            "Message": "Access denied",
                        }
                    },
                    "ListEventSourceMappings",
                )

        class FakeLambdaClient:
            region = AWS_REGION_US_EAST_1

            def get_paginator(self, name):
                assert name == "list_event_source_mappings"
                return FakePaginator()

        function_arn = (
            f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:"
            f"{AWS_ACCOUNT_NUMBER}:function:selected"
        )
        awslambda = Lambda.__new__(Lambda)
        awslambda.function_limit = 1
        awslambda.functions = {
            function_arn: Function(
                name="selected",
                arn=function_arn,
                security_groups=[],
                region=AWS_REGION_US_EAST_1,
            )
        }

        with pytest.raises(ClientError) as error:
            awslambda._list_event_source_mappings(FakeLambdaClient())

        assert error.value.response["Error"]["Code"] == "AccessDeniedException"

    @mock_aws
    def test_list_functions(self):
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
                set_mocked_aws_provider(audited_regions=[AWS_REGION_US_EAST_1])
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
            assert awslambda.functions[lambda_arn_1].vpc_id == "vpc-123abc"
            assert awslambda.functions[lambda_arn_1].subnet_ids == {"subnet-123abc"}

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
            assert awslambda.functions[lambda_arn_2].policy == {}

            # Lambda Code
            with tempfile.TemporaryDirectory() as tmp_dir_name:
                for function, function_code in awslambda._get_function_code():
                    if function.arn == lambda_arn_1 or function.arn == lambda_arn_2:
                        assert search(
                            f"https://awslambda-{function.region}-tasks.s3.{function.region}.amazonaws.com",
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

    @mock_aws
    def test_function_limit_exposes_only_selected_functions(self):
        lambda_client = client("lambda", region_name=AWS_REGION_US_EAST_1)
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        iam_role = iam_client.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument="{}",
        )["Role"]["Arn"]
        for name in ("function-1", "function-2"):
            lambda_client.create_function(
                FunctionName=name,
                Runtime="python3.7",
                Role=iam_role,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": create_zip_file().read()},
                PackageType="ZIP",
            )
        awslambda = Lambda(
            set_mocked_aws_provider(
                audited_regions=[AWS_REGION_US_EAST_1],
                audit_config={"max_lambda_functions": 1},
            )
        )

        assert len(awslambda.functions) == 1

    @mock_aws
    def test_get_function_code_fetches_only_selected_functions(self):
        lambda_client = client("lambda", region_name=AWS_REGION_US_EAST_1)
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        iam_role = iam_client.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument="{}",
        )["Role"]["Arn"]
        for name in ("function-1", "function-2"):
            lambda_client.create_function(
                FunctionName=name,
                Runtime="python3.7",
                Role=iam_role,
                Handler="lambda_function.lambda_handler",
                Code={"ZipFile": create_zip_file().read()},
                PackageType="ZIP",
            )
        awslambda = Lambda(
            set_mocked_aws_provider(
                audited_regions=[AWS_REGION_US_EAST_1],
                audit_config={"max_lambda_functions": 1},
            )
        )
        fetched = []

        def fetch_function_code(function_name, _function_region):
            fetched.append(function_name)
            return mock.MagicMock()

        awslambda._fetch_function_code = fetch_function_code

        assert len(list(awslambda._get_function_code())) == 1
        assert len(fetched) == 1
