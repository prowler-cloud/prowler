import zipfile
from unittest import mock

from awslambda_service_test import create_zip_file
from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.services.awslambda.awslambda_service import (
    Function,
    LambdaCode,
)
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_awslambda_function_no_secrets_in_code:
    def test_no_functions(self):
        lambda_client = mock.MagicMock
        lambda_client.functions = {}

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            set_mocked_aws_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_code.awslambda_function_no_secrets_in_code.awslambda_client",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_code.awslambda_function_no_secrets_in_code import (
                awslambda_function_no_secrets_in_code,
            )

            check = awslambda_function_no_secrets_in_code()
            result = check.execute()

            assert len(result) == 0

    def test_function_code_with_secrets(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{DEFAULT_ACCOUNT_ID}:function/{function_name}"
        code_with_secrets = """
        def lambda_handler(event, context):
                db_password = "test-password"
                print("custom log event")
                return event
        """
        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION_US_EAST_1,
                runtime=function_runtime,
                code=LambdaCode(
                    location="",
                    code_zip=zipfile.ZipFile(create_zip_file(code_with_secrets)),
                ),
            )
        }

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            set_mocked_aws_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_code.awslambda_function_no_secrets_in_code.awslambda_client",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_code.awslambda_function_no_secrets_in_code import (
                awslambda_function_no_secrets_in_code,
            )

            check = awslambda_function_no_secrets_in_code()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in Lambda function {function_name} code -> lambda_function.py: Secret Keyword on line 3."
            )
            assert result[0].resource_tags == []

    def test_function_code_without_secrets(self):
        lambda_client = mock.MagicMock
        function_name = "test-lambda"
        function_runtime = "nodejs4.3"
        function_arn = f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{DEFAULT_ACCOUNT_ID}:function/{function_name}"
        code_with_secrets = """
        def lambda_handler(event, context):
                print("custom log event")
                return event
        """
        lambda_client.functions = {
            "function_name": Function(
                name=function_name,
                security_groups=[],
                arn=function_arn,
                region=AWS_REGION_US_EAST_1,
                runtime=function_runtime,
                code=LambdaCode(
                    location="",
                    code_zip=zipfile.ZipFile(create_zip_file(code_with_secrets)),
                ),
            )
        }

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            set_mocked_aws_audit_info(),
        ), mock.patch(
            "prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_code.awslambda_function_no_secrets_in_code.awslambda_client",
            new=lambda_client,
        ):
            # Test Check
            from prowler.providers.aws.services.awslambda.awslambda_function_no_secrets_in_code.awslambda_function_no_secrets_in_code import (
                awslambda_function_no_secrets_in_code,
            )

            check = awslambda_function_no_secrets_in_code()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == function_name
            assert result[0].resource_arn == function_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Lambda function {function_name} code."
            )
            assert result[0].resource_tags == []
