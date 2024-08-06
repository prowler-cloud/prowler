from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.awslambda.awslambda_service import Function
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)


class Test_awslambda_function_not_publicly_accessible:
    @mock_aws
    def test_no_functions(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible.awslambda_client",
            new=Lambda(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (
                awslambda_function_not_publicly_accessible,
            )

            check = awslambda_function_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_function_public(self):
        # Create the mock IAM role
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

        function_name = "test-lambda"

        # Create the lambda function using boto3 client
        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        function_arn = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="nodejs4.3",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": b"fileb://file-path/to/your-deployment-package.zip"},
            Description="Test Lambda function",
            Timeout=3,
            MemorySize=128,
            Publish=True,
            Tags={"tag1": "value1", "tag2": "value2"},
        )["FunctionArn"]

        # Attach the policy to the lambda function with a wildcard principal
        lambda_client.add_permission(
            FunctionName=function_name,
            StatementId="public-access",
            Action="lambda:InvokeFunction",
            Principal="*",
            SourceArn=function_arn,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible.awslambda_client",
            new=Lambda(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (
                awslambda_function_not_publicly_accessible,
            )

            check = awslambda_function_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} has a policy resource-based policy with public access."
            )
            assert result[0].resource_tags == [{"tag1": "value1", "tag2": "value2"}]

    @mock_aws
    def test_function_not_public(self):
        # Create the mock IAM role
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

        function_name = "test-lambda"

        # Create the lambda function using boto3 client
        lambda_client = client("lambda", region_name=AWS_REGION_EU_WEST_1)
        function_arn = lambda_client.create_function(
            FunctionName=function_name,
            Runtime="nodejs4.3",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": b"fileb://file-path/to/your-deployment-package.zip"},
            Description="Test Lambda function",
            Timeout=3,
            MemorySize=128,
            Publish=True,
            Tags={"tag1": "value1", "tag2": "value2"},
        )["FunctionArn"]

        # Attach the policy to the lambda function with a specific AWS account number as principal
        lambda_client.add_permission(
            FunctionName=function_name,
            StatementId="public-access",
            Action="lambda:InvokeFunction",
            Principal=AWS_ACCOUNT_NUMBER,
            SourceArn=function_arn,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.awslambda.awslambda_service import Lambda

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible.awslambda_client",
            new=Lambda(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (
                awslambda_function_not_publicly_accessible,
            )

            check = awslambda_function_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} has a policy resource-based policy not public."
            )
            assert result[0].resource_tags == [{"tag1": "value1", "tag2": "value2"}]

    def test_function_public_with_canonical(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"
        lambda_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "public-access",
                    "Principal": {"CanonicalUser": ["*"]},
                    "Effect": "Allow",
                    "Action": [
                        "lambda:InvokeFunction",
                    ],
                    "Resource": [function_arn],
                }
            ],
        }

        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION_EU_WEST_1,
                runtime=function_runtime,
                policy=lambda_policy,
            )
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible.awslambda_client",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (
                awslambda_function_not_publicly_accessible,
            )

            check = awslambda_function_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} has a policy resource-based policy with public access."
            )
            assert result[0].resource_tags == []
