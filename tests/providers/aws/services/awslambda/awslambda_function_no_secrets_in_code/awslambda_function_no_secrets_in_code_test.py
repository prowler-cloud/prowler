import zipfile
from unittest import mock

from prowler.providers.aws.services.awslambda.awslambda_service import (
    Function,
    LambdaCode,
)
from tests.providers.aws.services.awslambda.awslambda_service_test import (
    create_zip_file,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

LAMBDA_FUNCTION_NAME = "test-lambda"
LAMBDA_FUNCTION_RUNTIME = "nodejs4.3"
LAMBDA_FUNCTION_ARN = f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:function/{LAMBDA_FUNCTION_NAME}"
LAMBDA_FUNCTION_CODE_WITH_SECRETS = """
def lambda_handler(event, context):
        db_password = "test-password"
        print("custom log event")
        return event
"""
LAMBDA_FUNCTION_CODE_WITHOUT_SECRETS = """
def lambda_handler(event, context):
        print("custom log event")
        return event
"""
LAMBDA_FUNCTION_CODE_WITH_METADATA_API = """
def lambda_handler(event, context):
        metadata_api = "169.254.169.254"
        print("custom log event")
        return event
"""


def create_lambda_function() -> Function:
    return Function(
        name=LAMBDA_FUNCTION_NAME,
        security_groups=[],
        arn=LAMBDA_FUNCTION_ARN,
        region=AWS_REGION_US_EAST_1,
        runtime=LAMBDA_FUNCTION_RUNTIME,
    )


def get_lambda_code_with_secrets(code):
    return LambdaCode(
        location="",
        code_zip=zipfile.ZipFile(create_zip_file(code)),
    )


def mock_get_function_codewith_secrets():
    yield create_lambda_function(), get_lambda_code_with_secrets(
        LAMBDA_FUNCTION_CODE_WITH_SECRETS
    )


def mock_get_function_codewithout_secrets():
    yield create_lambda_function(), get_lambda_code_with_secrets(
        LAMBDA_FUNCTION_CODE_WITHOUT_SECRETS
    )


def mock_get_function_codewith_metadata_api():
    yield create_lambda_function(), get_lambda_code_with_secrets(
        LAMBDA_FUNCTION_CODE_WITH_METADATA_API
    )


class Test_awslambda_function_no_secrets_in_code:
    def test_no_functions(self):
        lambda_client = mock.MagicMock
        lambda_client.functions = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
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
        lambda_client.functions = {LAMBDA_FUNCTION_ARN: create_lambda_function()}
        lambda_client._get_function_code = mock_get_function_codewith_secrets
        lambda_client.audit_config = {"secrets_ignore_patterns": []}
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
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
            assert result[0].resource_id == LAMBDA_FUNCTION_NAME
            assert result[0].resource_arn == LAMBDA_FUNCTION_ARN
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in Lambda function {LAMBDA_FUNCTION_NAME} code -> lambda_function.py: Secret Keyword on line 3."
            )
            assert result[0].resource_tags == []

    def test_function_code_without_secrets(self):
        lambda_client = mock.MagicMock
        lambda_client.functions = {LAMBDA_FUNCTION_ARN: create_lambda_function()}

        lambda_client._get_function_code = mock_get_function_codewithout_secrets
        lambda_client.audit_config = {"secrets_ignore_patterns": []}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
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
            assert result[0].resource_id == LAMBDA_FUNCTION_NAME
            assert result[0].resource_arn == LAMBDA_FUNCTION_ARN
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Lambda function {LAMBDA_FUNCTION_NAME} code."
            )
            assert result[0].resource_tags == []

    def test_function_code_with_metadata_api(self):
        lambda_client = mock.MagicMock
        lambda_client.functions = {LAMBDA_FUNCTION_ARN: create_lambda_function()}

        lambda_client._get_function_code = mock_get_function_codewith_metadata_api
        lambda_client.audit_config = {"secrets_ignore_patterns": []}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider(),
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
            assert result[0].resource_id == LAMBDA_FUNCTION_NAME
            assert result[0].resource_arn == LAMBDA_FUNCTION_ARN
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Lambda function {LAMBDA_FUNCTION_NAME} code."
            )
            assert result[0].resource_tags == []
