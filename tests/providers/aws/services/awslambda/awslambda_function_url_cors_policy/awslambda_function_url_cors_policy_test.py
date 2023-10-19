from unittest import mock

from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.services.awslambda.awslambda_service import (
    AuthType,
    Function,
    URLConfig,
    URLConfigCORS,
)

AWS_REGION = "us-east-1"


class Test_awslambda_function_url_cors_policy:
    def test_no_functions(self):
        lambda_client = mock.MagicMock
        lambda_client.functions = {}

        with mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_url_cors_policy.awslambda_function_url_cors_policy import (
                awslambda_function_url_cors_policy,
            )

            check = awslambda_function_url_cors_policy()
            result = check.execute()

            assert len(result) == 0

    def test_function_cors_asterisk(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = (
            f"arn:aws:lambda:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:function/{function_name}"
        )
        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION,
                runtime=function_runtime,
                url_config=URLConfig(
                    auth_type=AuthType.NONE,
                    url="",
                    cors_config=URLConfigCORS(allow_origins=["*"]),
                ),
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_url_cors_policy.awslambda_function_url_cors_policy import (
                awslambda_function_url_cors_policy,
            )

            check = awslambda_function_url_cors_policy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} URL has a wide CORS configuration."
            )
            assert result[0].resource_tags == []

    def test_function_cors_not_wide(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "python3.9"
        function_arn = (
            f"arn:aws:lambda:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:function/{function_name}"
        )
        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION,
                runtime=function_runtime,
                url_config=URLConfig(
                    auth_type=AuthType.AWS_IAM,
                    url="",
                    cors_config=URLConfigCORS(allow_origins=["https://example.com"]),
                ),
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_url_cors_policy.awslambda_function_url_cors_policy import (
                awslambda_function_url_cors_policy,
            )

            check = awslambda_function_url_cors_policy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} does not have a wide CORS configuration."
            )
            assert result[0].resource_tags == []

    def test_function_cors_wide_with_two_origins(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "python3.9"
        function_arn = (
            f"arn:aws:lambda:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:function/{function_name}"
        )
        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION,
                runtime=function_runtime,
                url_config=URLConfig(
                    auth_type=AuthType.AWS_IAM,
                    url="",
                    cors_config=URLConfigCORS(
                        allow_origins=["https://example.com", "*"]
                    ),
                ),
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_url_cors_policy.awslambda_function_url_cors_policy import (
                awslambda_function_url_cors_policy,
            )

            check = awslambda_function_url_cors_policy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} URL has a wide CORS configuration."
            )
            assert result[0].resource_tags == []
