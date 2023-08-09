from unittest import mock

from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.services.awslambda.awslambda_service import Function

AWS_REGION = "us-east-1"


class Test_awslambda_function_no_secrets_in_variables:
    def test_no_functions(self):
        lambda_client = mock.MagicMock
        lambda_client.functions = {}

        with mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables import (
                awslambda_function_no_secrets_in_variables,
            )

            check = awslambda_function_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 0

    def test_function_no_variables(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = (
            f"arn:aws:lambda:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:function/{function_name}"
        )

        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                arn=function_arn,
                region=AWS_REGION,
                runtime=function_runtime,
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables import (
                awslambda_function_no_secrets_in_variables,
            )

            check = awslambda_function_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Lambda function {function_name} variables."
            )
            assert result[0].resource_tags == []

    def test_function_secrets_in_variables(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = (
            f"arn:aws:lambda:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:function/{function_name}"
        )

        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                arn=function_arn,
                region=AWS_REGION,
                runtime=function_runtime,
                environment={"db_password": "test-password"},
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables import (
                awslambda_function_no_secrets_in_variables,
            )

            check = awslambda_function_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in Lambda function {function_name} variables -> Secret Keyword in variable db_password."
            )
            assert result[0].resource_tags == []

    def test_function_no_secrets_in_variables(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = (
            f"arn:aws:lambda:{AWS_REGION}:{DEFAULT_ACCOUNT_ID}:function/{function_name}"
        )

        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                arn=function_arn,
                region=AWS_REGION,
                runtime=function_runtime,
                environment={"db_username": "test-user"},
            )
        }

        with mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_service.Lambda",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_variables.awslambda_function_no_secrets_in_variables import (
                awslambda_function_no_secrets_in_variables,
            )

            check = awslambda_function_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Lambda function {function_name} variables."
            )
            assert result[0].resource_tags == []
