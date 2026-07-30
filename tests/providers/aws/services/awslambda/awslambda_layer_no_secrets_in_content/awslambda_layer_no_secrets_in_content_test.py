import os
import zipfile
from unittest import mock

from prowler.providers.aws.services.awslambda.awslambda_service import (
    LambdaCode,
    Layer,
)
from tests.providers.aws.services.awslambda.awslambda_service_test import (
    create_zip_file,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

LAMBDA_LAYER_NAME = "test-layer"
LAMBDA_LAYER_ARN = (
    f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:layer:"
    f"{LAMBDA_LAYER_NAME}:1"
)
LAMBDA_LAYER_CONTENT_WITH_SECRETS = """
db_password = "Tr0ub4dor3xKq9vLmZ"
"""
LAMBDA_LAYER_CONTENT_WITHOUT_SECRETS = """
def helper():
    return True
"""


def create_lambda_layer() -> Layer:
    return Layer(arn=LAMBDA_LAYER_ARN)


def get_lambda_layer_code(content):
    return LambdaCode(
        location="",
        code_zip=zipfile.ZipFile(create_zip_file(content)),
    )


def get_lambda_layer_code_from_files(files: dict) -> LambdaCode:
    # The check only calls code_zip.extractall(dir); mock it to drop the
    # given files into the temporary directory the check creates, so no
    # real archive needs to be built.
    code_zip = mock.MagicMock()

    def _extractall(path):
        for name, content in files.items():
            os.makedirs(os.path.dirname(f"{path}/{name}"), exist_ok=True)
            with open(f"{path}/{name}", "w") as fd:
                fd.write(content)

    code_zip.extractall.side_effect = _extractall
    return LambdaCode(location="", code_zip=code_zip)


def mock_get_layers_code_with_nested_vendor_secret():
    yield create_lambda_layer(), get_lambda_layer_code_from_files(
        {
            "python/lib.py": LAMBDA_LAYER_CONTENT_WITHOUT_SECRETS,
            "python/vendor/package.js": 'const dbPassword = "test-vendor-password";',
        }
    )


def mock_get_layers_code_with_secrets():
    yield create_lambda_layer(), get_lambda_layer_code(
        LAMBDA_LAYER_CONTENT_WITH_SECRETS
    )


def mock_get_layers_code_without_secrets():
    yield create_lambda_layer(), get_lambda_layer_code(
        LAMBDA_LAYER_CONTENT_WITHOUT_SECRETS
    )


class Test_awslambda_layer_no_secrets_in_content:
    def test_no_layers(self):
        lambda_client = mock.MagicMock
        lambda_client.layers = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_content.awslambda_layer_no_secrets_in_content.awslambda_client",
                new=lambda_client,
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_content.awslambda_layer_no_secrets_in_content import (
                awslambda_layer_no_secrets_in_content,
            )

            check = awslambda_layer_no_secrets_in_content()
            result = check.execute()

            assert len(result) == 0

    def test_layer_content_with_secrets(self):
        lambda_client = mock.MagicMock
        lambda_client.layers = {LAMBDA_LAYER_ARN: create_lambda_layer()}
        lambda_client._get_layers_code = mock_get_layers_code_with_secrets
        lambda_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_content.awslambda_layer_no_secrets_in_content.awslambda_client",
                new=lambda_client,
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_content.awslambda_layer_no_secrets_in_content import (
                awslambda_layer_no_secrets_in_content,
            )

            check = awslambda_layer_no_secrets_in_content()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == LAMBDA_LAYER_NAME
            assert result[0].resource_arn == LAMBDA_LAYER_ARN
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in Lambda layer {LAMBDA_LAYER_NAME} (version 1) content -> lambda_function.py: Generic Password on line 2."
            )
            assert result[0].resource_tags == []

    def test_layer_content_without_secrets(self):
        lambda_client = mock.MagicMock
        lambda_client.layers = {LAMBDA_LAYER_ARN: create_lambda_layer()}
        lambda_client._get_layers_code = mock_get_layers_code_without_secrets
        lambda_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_content.awslambda_layer_no_secrets_in_content.awslambda_client",
                new=lambda_client,
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_content.awslambda_layer_no_secrets_in_content import (
                awslambda_layer_no_secrets_in_content,
            )

            check = awslambda_layer_no_secrets_in_content()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == LAMBDA_LAYER_NAME
            assert result[0].resource_arn == LAMBDA_LAYER_ARN
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Lambda layer {LAMBDA_LAYER_NAME} (version 1) content."
            )
            assert result[0].resource_tags == []

    def test_layer_content_nested_vendor_secret_not_ignored(self):
        lambda_client = mock.MagicMock
        lambda_client.layers = {LAMBDA_LAYER_ARN: create_lambda_layer()}
        lambda_client._get_layers_code = mock_get_layers_code_with_nested_vendor_secret
        lambda_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_content.awslambda_layer_no_secrets_in_content.awslambda_client",
                new=lambda_client,
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_content.awslambda_layer_no_secrets_in_content import (
                awslambda_layer_no_secrets_in_content,
            )

            check = awslambda_layer_no_secrets_in_content()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "python/vendor/package.js" in result[0].status_extended

    def test_layer_content_nested_vendor_secret_ignored_by_file_pattern(self):
        lambda_client = mock.MagicMock
        lambda_client.layers = {LAMBDA_LAYER_ARN: create_lambda_layer()}
        lambda_client._get_layers_code = mock_get_layers_code_with_nested_vendor_secret
        lambda_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_ignore_files": ["python/vendor/*.js"],
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_content.awslambda_layer_no_secrets_in_content.awslambda_client",
                new=lambda_client,
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_content.awslambda_layer_no_secrets_in_content import (
                awslambda_layer_no_secrets_in_content,
            )

            check = awslambda_layer_no_secrets_in_content()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_scan_failure_reports_manual_not_pass(self):
        from prowler.lib.utils.utils import SecretsScanError

        lambda_client = mock.MagicMock
        lambda_client.layers = {LAMBDA_LAYER_ARN: create_lambda_layer()}
        lambda_client._get_layers_code = mock_get_layers_code_with_secrets
        lambda_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_content.awslambda_layer_no_secrets_in_content.awslambda_client",
                new=lambda_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_content.awslambda_layer_no_secrets_in_content.detect_secrets_scan_batch",
                side_effect=SecretsScanError("Kingfisher exited with code 1"),
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_content.awslambda_layer_no_secrets_in_content import (
                awslambda_layer_no_secrets_in_content,
            )

            check = awslambda_layer_no_secrets_in_content()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Could not scan" in result[0].status_extended
