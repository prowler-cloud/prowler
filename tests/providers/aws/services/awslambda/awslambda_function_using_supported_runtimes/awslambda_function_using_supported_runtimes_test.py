from unittest import mock

from prowler.providers.aws.services.awslambda.awslambda_service import Function
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_awslambda_function_using_supported_runtimes:
    def test_no_functions(self):
        lambda_client = mock.MagicMock
        lambda_client.functions = {}

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_using_supported_runtimes.awslambda_function_using_supported_runtimes.awslambda_client",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_using_supported_runtimes.awslambda_function_using_supported_runtimes import (
                awslambda_function_using_supported_runtimes,
            )

            check = awslambda_function_using_supported_runtimes()
            result = check.execute()

            assert len(result) == 0

    def test_function_obsolete_runtime(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"
        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION_US_EAST_1,
                runtime=function_runtime,
            )
        }

        # Mock config
        lambda_client.audit_config = {
            "obsolete_lambda_runtimes": [
                "python3.6",
                "python2.7",
                "nodejs4.3",
                "nodejs4.3-edge",
                "nodejs6.10",
                "nodejs",
                "nodejs8.10",
                "nodejs10.x",
                "dotnetcore1.0",
                "dotnetcore2.0",
                "dotnetcore2.1",
                "ruby2.5",
            ]
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_using_supported_runtimes.awslambda_function_using_supported_runtimes.awslambda_client",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_using_supported_runtimes.awslambda_function_using_supported_runtimes import (
                awslambda_function_using_supported_runtimes,
            )

            check = awslambda_function_using_supported_runtimes()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} is using {function_runtime} which is obsolete."
            )
            assert result[0].resource_tags == []

    def test_function_supported_runtime(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "python3.9"
        function_arn = f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"
        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION_US_EAST_1,
                runtime=function_runtime,
            )
        }

        # Mock config
        lambda_client.audit_config = {
            "obsolete_lambda_runtimes": [
                "python3.6",
                "python2.7",
                "nodejs4.3",
                "nodejs4.3-edge",
                "nodejs6.10",
                "nodejs",
                "nodejs8.10",
                "nodejs10.x",
                "dotnetcore1.0",
                "dotnetcore2.0",
                "dotnetcore2.1",
                "ruby2.5",
            ]
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_using_supported_runtimes.awslambda_function_using_supported_runtimes.awslambda_client",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_using_supported_runtimes.awslambda_function_using_supported_runtimes import (
                awslambda_function_using_supported_runtimes,
            )

            check = awslambda_function_using_supported_runtimes()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Lambda function {function_name} is using {function_runtime} which is supported."
            )
            assert result[0].resource_tags == []

    def test_function_no_runtime(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_arn = f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:function/{function_name}"
        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION_US_EAST_1,
            )
        }

        # Mock config
        lambda_client.audit_config = {
            "obsolete_lambda_runtimes": [
                "python3.6",
                "python2.7",
                "nodejs4.3",
                "nodejs4.3-edge",
                "nodejs6.10",
                "nodejs",
                "nodejs8.10",
                "nodejs10.x",
                "dotnetcore1.0",
                "dotnetcore2.0",
                "dotnetcore2.1",
                "ruby2.5",
            ]
        }

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=set_mocked_aws_provider(),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_using_supported_runtimes.awslambda_function_using_supported_runtimes.awslambda_client",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_using_supported_runtimes.awslambda_function_using_supported_runtimes import (
                awslambda_function_using_supported_runtimes,
            )

            check = awslambda_function_using_supported_runtimes()
            result = check.execute()

            assert len(result) == 0
