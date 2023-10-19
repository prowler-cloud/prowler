from unittest import mock

from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.services.awslambda.awslambda_service import Function

AWS_REGION = "us-east-1"


class Test_awslambda_function_not_publicly_accessible:
    def test_no_functions(self):
        lambda_client = mock.MagicMock
        lambda_client.functions = {}

        with mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (
                awslambda_function_not_publicly_accessible,
            )

            check = awslambda_function_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 0

    def test_function_public(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = (
            f"arn:aws:lambda:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:function/{function_name}"
        )
        lambda_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "public-access",
                    "Principal": {"AWS": ["*", DEFAULT_ACCOUNT_ID]},
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
                region=AWS_REGION,
                runtime=function_runtime,
                policy=lambda_policy,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (
                awslambda_function_not_publicly_accessible,
            )

            check = awslambda_function_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} has a policy resource-based policy with public access."
            )
            assert result[0].resource_tags == []

    def test_function_not_public(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = (
            f"arn:aws:lambda:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:function/{function_name}"
        )
        lambda_policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "public-access",
                    "Principal": {"AWS": [DEFAULT_ACCOUNT_ID]},
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
                region=AWS_REGION,
                runtime=function_runtime,
                policy=lambda_policy,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (
                awslambda_function_not_publicly_accessible,
            )

            check = awslambda_function_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} has a policy resource-based policy not public."
            )
            assert result[0].resource_tags == []

    def test_function_public_with_canonical(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = (
            f"arn:aws:lambda:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:function/{function_name}"
        )
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
                region=AWS_REGION,
                runtime=function_runtime,
                policy=lambda_policy,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_not_publicly_accessible.awslambda_function_not_publicly_accessible import (
                awslambda_function_not_publicly_accessible,
            )

            check = awslambda_function_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} has a policy resource-based policy with public access."
            )
            assert result[0].resource_tags == []
