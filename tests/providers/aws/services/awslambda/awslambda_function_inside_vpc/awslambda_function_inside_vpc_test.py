from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider


class Test_awslambda_function_inside_vpc:
    def test_no_functions(self):
        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        aws_provider = set_mocked_aws_provider(AWS_REGION_EU_WEST_1)

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_inside_vpc.awslambda_function_inside_vpc.awslambda_client",
            new=Lambda(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_inside_vpc.awslambda_function_inside_vpc import (
                awslambda_function_inside_vpc,
            )

            check = awslambda_function_inside_vpc()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_function_inside_vpc(self):
        # Create IAM Role for Lambda Function
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_name = "test-role"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(assume_role_policy_document),
        )["Role"]["Arn"]

        # Create Lambda Function inside VPC
        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        function_name = "test_function"
        function_arn = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.8",
            Role=role_arn,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": b"file not used"},
            VpcConfig={
                "SubnetIds": ["subnet-12345678"],
                "SecurityGroupIds": ["sg-12345678"],
            },
        )["FunctionArn"]

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_inside_vpc.awslambda_function_inside_vpc.awslambda_client",
            new=Lambda(aws_provider),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_function_inside_vpc.awslambda_function_inside_vpc import (
                awslambda_function_inside_vpc,
            )

            check = awslambda_function_inside_vpc()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Lambda function test_function is inside of VPC vpc-123abc"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].resource_tags == [{}]

    @mock_aws
    def test_function_outside_vpc(self):
        # Create IAM Role for Lambda Function
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        role_name = "test-role"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "lambda.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(assume_role_policy_document),
        )["Role"]["Arn"]

        # Create Lambda Function outside VPC
        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        function_name = "test_function"
        function_arn = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="python3.8",
            Role=role_arn,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": b"file not used"},
        )["FunctionArn"]

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_inside_vpc.awslambda_function_inside_vpc.awslambda_client",
            new=Lambda(aws_provider),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_function_inside_vpc.awslambda_function_inside_vpc import (
                awslambda_function_inside_vpc,
            )

            check = awslambda_function_inside_vpc()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Lambda function test_function is not inside a VPC"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].resource_tags == [{}]
