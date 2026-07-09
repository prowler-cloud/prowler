import io
import zipfile
from unittest import mock

from prowler.providers.aws.services.awslambda.awslambda_service import (
    LambdaCode,
    Layer,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

LAMBDA_LAYER_NAME = "shared-layer"
LAMBDA_LAYER_ARN = (
    f"arn:aws:lambda:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:"
    f"layer:{LAMBDA_LAYER_NAME}:1"
)


def get_layer_code_from_files(files: dict) -> LambdaCode:
    zip_output = io.BytesIO()
    with zipfile.ZipFile(zip_output, "w", zipfile.ZIP_DEFLATED) as code_zip:
        for name, content in files.items():
            code_zip.writestr(name, content)
    zip_output.seek(0)
    return LambdaCode(location="", code_zip=zipfile.ZipFile(zip_output))


def create_layer() -> Layer:
    return Layer(arn=LAMBDA_LAYER_ARN)


def mock_get_layer_code_with_secret():
    yield create_layer(), get_layer_code_from_files(
        {
            "python/lib/config.py": 'db_password = "Tr0ub4dor3xKq9vLmZ"',
        }
    )


def mock_get_layer_code_without_secret():
    yield create_layer(), get_layer_code_from_files(
        {
            "python/lib/config.py": 'setting = "not-sensitive"',
        }
    )


def mock_get_layer_code_with_ignored_secret():
    yield create_layer(), get_layer_code_from_files(
        {
            "python/lib/vendor.js": 'const password = "test-vendor-password";',
        }
    )


def mock_get_layer_code_with_unsafe_secret():
    yield create_layer(), get_layer_code_from_files(
        {
            "../config.py": 'db_password = "Tr0ub4dor3xKq9vLmZ"',
            "python/lib/config.py": 'setting = "not-sensitive"',
        }
    )


def mock_get_layer_code_without_payload():
    yield create_layer(), None


class Test_awslambda_layer_no_secrets_in_code:
    def test_no_layers(self):
        lambda_client = mock.MagicMock
        lambda_client.layers = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_code.awslambda_layer_no_secrets_in_code.awslambda_client",
                new=lambda_client,
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_code.awslambda_layer_no_secrets_in_code import (
                awslambda_layer_no_secrets_in_code,
            )

            check = awslambda_layer_no_secrets_in_code()
            result = check.execute()

            assert len(result) == 0

    def test_layer_code_with_secret(self):
        lambda_client = mock.MagicMock
        lambda_client.layers = {LAMBDA_LAYER_ARN: create_layer()}
        lambda_client._get_layer_code = mock_get_layer_code_with_secret
        lambda_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_code.awslambda_layer_no_secrets_in_code.awslambda_client",
                new=lambda_client,
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_code.awslambda_layer_no_secrets_in_code import (
                awslambda_layer_no_secrets_in_code,
            )

            check = awslambda_layer_no_secrets_in_code()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == LAMBDA_LAYER_NAME
            assert result[0].resource_arn == LAMBDA_LAYER_ARN
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in Lambda layer {LAMBDA_LAYER_NAME} code -> python/lib/config.py: Generic Password on line 1."
            )
            assert result[0].resource_tags == []

    def test_layer_code_without_secret(self):
        lambda_client = mock.MagicMock
        lambda_client.layers = {LAMBDA_LAYER_ARN: create_layer()}
        lambda_client._get_layer_code = mock_get_layer_code_without_secret
        lambda_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_code.awslambda_layer_no_secrets_in_code.awslambda_client",
                new=lambda_client,
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_code.awslambda_layer_no_secrets_in_code import (
                awslambda_layer_no_secrets_in_code,
            )

            check = awslambda_layer_no_secrets_in_code()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == LAMBDA_LAYER_NAME
            assert result[0].resource_arn == LAMBDA_LAYER_ARN
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Lambda layer {LAMBDA_LAYER_NAME} code."
            )
            assert result[0].resource_tags == []

    def test_layer_code_secret_ignored_by_file_pattern(self):
        lambda_client = mock.MagicMock
        lambda_client.layers = {LAMBDA_LAYER_ARN: create_layer()}
        lambda_client._get_layer_code = mock_get_layer_code_with_ignored_secret
        lambda_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_ignore_files": ["python/lib/vendor.js"],
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_code.awslambda_layer_no_secrets_in_code.awslambda_client",
                new=lambda_client,
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_code.awslambda_layer_no_secrets_in_code import (
                awslambda_layer_no_secrets_in_code,
            )

            check = awslambda_layer_no_secrets_in_code()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_layer_code_unsafe_zip_path_is_not_extracted(self):
        lambda_client = mock.MagicMock
        lambda_client.layers = {LAMBDA_LAYER_ARN: create_layer()}
        lambda_client._get_layer_code = mock_get_layer_code_with_unsafe_secret
        lambda_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_code.awslambda_layer_no_secrets_in_code.awslambda_client",
                new=lambda_client,
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_code.awslambda_layer_no_secrets_in_code import (
                awslambda_layer_no_secrets_in_code,
            )

            check = awslambda_layer_no_secrets_in_code()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_layer_code_without_payload_reports_manual(self):
        lambda_client = mock.MagicMock
        lambda_client.layers = {LAMBDA_LAYER_ARN: create_layer()}
        lambda_client._get_layer_code = mock_get_layer_code_without_payload
        lambda_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_code.awslambda_layer_no_secrets_in_code.awslambda_client",
                new=lambda_client,
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_code.awslambda_layer_no_secrets_in_code import (
                awslambda_layer_no_secrets_in_code,
            )

            check = awslambda_layer_no_secrets_in_code()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Could not retrieve" in result[0].status_extended

    def test_scan_failure_reports_manual_not_pass(self):
        from prowler.lib.utils.utils import SecretsScanError

        lambda_client = mock.MagicMock
        lambda_client.layers = {LAMBDA_LAYER_ARN: create_layer()}
        lambda_client._get_layer_code = mock_get_layer_code_with_secret
        lambda_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_code.awslambda_layer_no_secrets_in_code.awslambda_client",
                new=lambda_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_code.awslambda_layer_no_secrets_in_code.detect_secrets_scan_batch",
                side_effect=SecretsScanError("Kingfisher exited with code 1"),
            ),
        ):
            from prowler.providers.aws.services.awslambda.awslambda_layer_no_secrets_in_code.awslambda_layer_no_secrets_in_code import (
                awslambda_layer_no_secrets_in_code,
            )

            check = awslambda_layer_no_secrets_in_code()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Could not scan" in result[0].status_extended
