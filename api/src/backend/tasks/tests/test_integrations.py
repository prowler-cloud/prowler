from unittest.mock import MagicMock, patch

import pytest
from tasks.jobs.integrations import (
    get_s3_client_from_integration,
    upload_s3_integration,
)

from api.models import Integration
from api.utils import prowler_integration_connection_test
from prowler.providers.common.models import Connection


@pytest.mark.django_db
class TestS3IntegrationUploads:
    @patch("tasks.jobs.integrations.S3")
    def test_get_s3_client_from_integration_success(self, mock_s3_class):
        mock_integration = MagicMock()
        mock_integration.credentials = {
            "aws_access_key_id": "AKIA...",
            "aws_secret_access_key": "SECRET",
        }
        mock_integration.configuration = {
            "bucket_name": "test-bucket",
            "output_directory": "test-prefix",
        }

        mock_s3 = MagicMock()
        mock_connection = MagicMock()
        mock_connection.is_connected = True
        mock_s3.test_connection.return_value = mock_connection
        mock_s3_class.return_value = mock_s3

        connected, s3 = get_s3_client_from_integration(mock_integration)

        assert connected is True
        assert s3 == mock_s3
        mock_s3_class.assert_called_once_with(
            **mock_integration.credentials,
            bucket_name="test-bucket",
            output_directory="test-prefix",
        )
        mock_s3.test_connection.assert_called_once_with(
            **mock_integration.credentials,
            bucket_name="test-bucket",
        )

    @patch("tasks.jobs.integrations.S3")
    def test_get_s3_client_from_integration_failure(self, mock_s3_class):
        mock_integration = MagicMock()
        mock_integration.credentials = {}
        mock_integration.configuration = {
            "bucket_name": "test-bucket",
            "output_directory": "test-prefix",
        }

        from prowler.providers.common.models import Connection

        mock_connection = Connection()
        mock_connection.is_connected = False
        mock_connection.error = Exception("test error")

        mock_s3 = MagicMock()
        mock_s3.test_connection.return_value = mock_connection
        mock_s3_class.return_value = mock_s3

        connected, connection = get_s3_client_from_integration(mock_integration)

        assert connected is False
        assert isinstance(connection, Connection)
        assert str(connection.error) == "test error"

    @patch("tasks.jobs.integrations.GenericCompliance")
    @patch("tasks.jobs.integrations.ASFF")
    @patch("tasks.jobs.integrations.OCSF")
    @patch("tasks.jobs.integrations.HTML")
    @patch("tasks.jobs.integrations.CSV")
    @patch("tasks.jobs.integrations.glob")
    @patch("tasks.jobs.integrations.get_s3_client_from_integration")
    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    def test_upload_s3_integration_uploads_serialized_outputs(
        self,
        mock_integration_model,
        mock_rls,
        mock_get_s3,
        mock_glob,
        mock_csv,
        mock_html,
        mock_ocsf,
        mock_asff,
        mock_compliance,
    ):
        tenant_id = "tenant-id"
        provider_id = "provider-id"

        integration = MagicMock()
        integration.id = "i-1"
        integration.configuration = {
            "bucket_name": "bucket",
            "output_directory": "prefix",
        }
        mock_integration_model.objects.filter.return_value = [integration]

        mock_s3 = MagicMock()
        mock_get_s3.return_value = (True, mock_s3)

        # Mock the output classes to return mock instances
        mock_csv_instance = MagicMock()
        mock_html_instance = MagicMock()
        mock_ocsf_instance = MagicMock()
        mock_asff_instance = MagicMock()
        mock_compliance_instance = MagicMock()

        mock_csv.return_value = mock_csv_instance
        mock_html.return_value = mock_html_instance
        mock_ocsf.return_value = mock_ocsf_instance
        mock_asff.return_value = mock_asff_instance
        mock_compliance.return_value = mock_compliance_instance

        # Mock glob to return test files
        output_directory = "/tmp/prowler_output/scan123"
        mock_glob.side_effect = [
            ["/tmp/prowler_output/scan123.csv"],
            ["/tmp/prowler_output/scan123.html"],
            ["/tmp/prowler_output/scan123.ocsf.json"],
            ["/tmp/prowler_output/scan123.asff.json"],
            ["/tmp/prowler_output/compliance/compliance.csv"],
        ]

        with patch("os.path.exists", return_value=True):
            with patch("os.getenv", return_value="/tmp/prowler_api_output"):
                result = upload_s3_integration(tenant_id, provider_id, output_directory)

        assert result is True
        mock_s3.send_to_bucket.assert_called_once()

    @patch("tasks.jobs.integrations.get_s3_client_from_integration")
    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.logger")
    def test_upload_s3_integration_fails_connection_logs_error(
        self, mock_logger, mock_integration_model, mock_rls, mock_get_s3
    ):
        tenant_id = "tenant-id"
        provider_id = "provider-id"

        integration = MagicMock()
        integration.id = "i-1"
        integration.connected = True
        mock_s3_client = MagicMock()
        mock_s3_client.error = "Connection failed"

        mock_integration_model.objects.filter.return_value = [integration]
        mock_get_s3.return_value = (False, mock_s3_client)

        output_directory = "/tmp/prowler_output/scan123"
        result = upload_s3_integration(tenant_id, provider_id, output_directory)

        assert result is False
        integration.save.assert_called_once()
        assert integration.connected is False
        mock_logger.error.assert_any_call(
            "S3 upload failed for integration i-1: Connection failed"
        )

    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.logger")
    def test_upload_s3_integration_logs_if_no_integrations(
        self, mock_logger, mock_integration_model, mock_rls
    ):
        mock_integration_model.objects.filter.return_value = []
        output_directory = "/tmp/prowler_output/scan123"
        result = upload_s3_integration("tenant", "provider", output_directory)

        assert result is False
        mock_logger.error.assert_called_once_with(
            "No S3 integrations found for provider provider"
        )

    @patch(
        "tasks.jobs.integrations.get_s3_client_from_integration",
        side_effect=Exception("failed"),
    )
    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.logger")
    def test_upload_s3_integration_logs_connection_exception_and_continues(
        self, mock_logger, mock_integration_model, mock_rls, mock_get_s3
    ):
        tenant_id = "tenant-id"
        provider_id = "provider-id"

        integration = MagicMock()
        integration.id = "i-1"
        integration.configuration = {
            "bucket_name": "bucket",
            "output_directory": "prefix",
        }
        mock_integration_model.objects.filter.return_value = [integration]

        output_directory = "/tmp/prowler_output/scan123"
        result = upload_s3_integration(tenant_id, provider_id, output_directory)

        assert result is False
        mock_logger.error.assert_any_call(
            "S3 connection failed for integration i-1: failed"
        )

    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration.objects.filter")
    def test_upload_s3_integration_filters_enabled_only(
        self, mock_integration_filter, mock_rls
    ):
        """Test that upload_s3_integration only processes enabled integrations."""
        tenant_id = "tenant-id"
        provider_id = "provider-id"
        output_directory = "/tmp/prowler_output/scan123"

        # Mock that no enabled integrations are found
        mock_integration_filter.return_value = []
        mock_rls.return_value.__enter__.return_value = None

        result = upload_s3_integration(tenant_id, provider_id, output_directory)

        assert result is False
        # Verify the filter includes the correct parameters including enabled=True
        mock_integration_filter.assert_called_once_with(
            integrationproviderrelationship__provider_id=provider_id,
            integration_type=Integration.IntegrationChoices.AMAZON_S3,
            enabled=True,
        )

    def test_s3_integration_validates_and_normalizes_output_directory(self):
        """Test that S3 integration validation normalizes output_directory paths."""
        from api.models import Integration
        from api.v1.serializers import BaseWriteIntegrationSerializer

        integration_type = Integration.IntegrationChoices.AMAZON_S3
        providers = []
        configuration = {
            "bucket_name": "test-bucket",
            "output_directory": "///////test",  # This should be normalized
        }
        credentials = {
            "aws_access_key_id": "AKIATEST",
            "aws_secret_access_key": "secret123",
        }

        # Should not raise an exception and should normalize the path
        BaseWriteIntegrationSerializer.validate_integration_data(
            integration_type, providers, configuration, credentials
        )

        # Verify that the path was normalized
        assert configuration["output_directory"] == "test"

    def test_s3_integration_rejects_invalid_output_directory_characters(self):
        """Test that S3 integration validation rejects invalid characters."""
        from rest_framework.exceptions import ValidationError

        from api.models import Integration
        from api.v1.serializers import BaseWriteIntegrationSerializer

        integration_type = Integration.IntegrationChoices.AMAZON_S3
        providers = []
        configuration = {
            "bucket_name": "test-bucket",
            "output_directory": "test<invalid",  # Contains invalid character
        }
        credentials = {
            "aws_access_key_id": "AKIATEST",
            "aws_secret_access_key": "secret123",
        }

        with pytest.raises(ValidationError) as exc_info:
            BaseWriteIntegrationSerializer.validate_integration_data(
                integration_type, providers, configuration, credentials
            )

        # Should contain validation error about invalid characters
        assert "Output directory contains invalid characters" in str(exc_info.value)

    def test_s3_integration_rejects_empty_output_directory(self):
        """Test that S3 integration validation rejects empty directories."""
        from rest_framework.exceptions import ValidationError

        from api.models import Integration
        from api.v1.serializers import BaseWriteIntegrationSerializer

        integration_type = Integration.IntegrationChoices.AMAZON_S3
        providers = []
        configuration = {
            "bucket_name": "test-bucket",
            "output_directory": "/////",  # This becomes empty after normalization
        }
        credentials = {
            "aws_access_key_id": "AKIATEST",
            "aws_secret_access_key": "secret123",
        }

        with pytest.raises(ValidationError) as exc_info:
            BaseWriteIntegrationSerializer.validate_integration_data(
                integration_type, providers, configuration, credentials
            )

        # Should contain validation error about empty directory
        assert "Output directory cannot be empty" in str(exc_info.value)

    def test_s3_integration_normalizes_complex_paths(self):
        """Test that S3 integration validation handles complex path normalization."""
        from api.models import Integration
        from api.v1.serializers import BaseWriteIntegrationSerializer

        integration_type = Integration.IntegrationChoices.AMAZON_S3
        providers = []
        configuration = {
            "bucket_name": "test-bucket",
            "output_directory": "//test//folder///subfolder//",
        }
        credentials = {
            "aws_access_key_id": "AKIATEST",
            "aws_secret_access_key": "secret123",
        }

        BaseWriteIntegrationSerializer.validate_integration_data(
            integration_type, providers, configuration, credentials
        )

        # Verify complex path normalization
        assert configuration["output_directory"] == "test/folder/subfolder"

    @patch("tasks.jobs.integrations.S3")
    def test_s3_client_uses_output_directory_in_object_paths(self, mock_s3_class):
        """Test that S3 client uses output_directory correctly when generating object paths."""
        mock_integration = MagicMock()
        mock_integration.credentials = {
            "aws_access_key_id": "AKIA...",
            "aws_secret_access_key": "SECRET",
        }
        mock_integration.configuration = {
            "bucket_name": "test-bucket",
            "output_directory": "my-custom-prefix/scan-results",
        }

        mock_s3_instance = MagicMock()
        mock_connection = MagicMock()
        mock_connection.is_connected = True
        mock_s3_instance.test_connection.return_value = mock_connection
        mock_s3_class.return_value = mock_s3_instance

        connected, s3 = get_s3_client_from_integration(mock_integration)

        assert connected is True
        # Verify S3 was initialized with the correct output_directory
        mock_s3_class.assert_called_once_with(
            **mock_integration.credentials,
            bucket_name="test-bucket",
            output_directory="my-custom-prefix/scan-results",
        )


@pytest.mark.django_db
class TestProwlerIntegrationConnectionTest:
    @patch("api.utils.S3")
    def test_s3_integration_connection_success(self, mock_s3_class):
        """Test successful S3 integration connection."""
        integration = MagicMock()
        integration.integration_type = Integration.IntegrationChoices.AMAZON_S3
        integration.credentials = {
            "aws_access_key_id": "AKIA...",
            "aws_secret_access_key": "SECRET",
        }
        integration.configuration = {"bucket_name": "test-bucket"}

        mock_connection = Connection(is_connected=True)
        mock_s3_class.test_connection.return_value = mock_connection

        result = prowler_integration_connection_test(integration)

        assert result.is_connected is True
        mock_s3_class.test_connection.assert_called_once_with(
            **integration.credentials,
            bucket_name="test-bucket",
            raise_on_exception=False,
        )

    @patch("api.utils.S3")
    def test_aws_provider_exception_handling(self, mock_s3_class):
        """Test S3 connection exception is properly caught and returned."""
        integration = MagicMock()
        integration.integration_type = Integration.IntegrationChoices.AMAZON_S3
        integration.credentials = {
            "aws_access_key_id": "invalid",
            "aws_secret_access_key": "credentials",
        }
        integration.configuration = {"bucket_name": "test-bucket"}

        test_exception = Exception("Invalid credentials")
        mock_connection = Connection(is_connected=False, error=test_exception)
        mock_s3_class.test_connection.return_value = mock_connection

        result = prowler_integration_connection_test(integration)

        assert result.is_connected is False
        assert result.error == test_exception
        mock_s3_class.test_connection.assert_called_once_with(
            aws_access_key_id="invalid",
            aws_secret_access_key="credentials",
            bucket_name="test-bucket",
            raise_on_exception=False,
        )

    @patch("api.utils.AwsProvider")
    @patch("api.utils.S3")
    def test_s3_integration_connection_failure(self, mock_s3_class, mock_aws_provider):
        """Test S3 integration connection failure."""
        integration = MagicMock()
        integration.integration_type = Integration.IntegrationChoices.AMAZON_S3
        integration.credentials = {
            "aws_access_key_id": "AKIA...",
            "aws_secret_access_key": "SECRET",
        }
        integration.configuration = {"bucket_name": "test-bucket"}

        mock_session = MagicMock()
        mock_aws_provider.return_value.session.current_session = mock_session

        mock_connection = Connection(
            is_connected=False, error=Exception("Bucket not found")
        )
        mock_s3_class.test_connection.return_value = mock_connection

        result = prowler_integration_connection_test(integration)

        assert result.is_connected is False
        assert str(result.error) == "Bucket not found"

    @patch("api.utils.AwsProvider")
    @patch("api.utils.S3")
    def test_aws_security_hub_integration_connection(
        self, mock_s3_class, mock_aws_provider
    ):
        """Test AWS Security Hub integration only validates AWS session."""
        integration = MagicMock()
        integration.integration_type = Integration.IntegrationChoices.AWS_SECURITY_HUB
        integration.credentials = {
            "aws_access_key_id": "AKIA...",
            "aws_secret_access_key": "SECRET",
        }
        integration.configuration = {"region": "us-east-1"}

        mock_session = MagicMock()
        mock_aws_provider.return_value.session.current_session = mock_session

        # For AWS Security Hub, the function should return early after AWS session validation
        result = prowler_integration_connection_test(integration)

        # The function should not reach S3 test_connection for AWS_SECURITY_HUB
        mock_s3_class.test_connection.assert_not_called()
        # Since no exception was raised during AWS session creation, return None (success)
        assert result is None

    def test_unsupported_integration_type(self):
        """Test unsupported integration type raises ValueError."""
        integration = MagicMock()
        integration.integration_type = "UNSUPPORTED_TYPE"
        integration.credentials = {}
        integration.configuration = {}

        with pytest.raises(
            ValueError, match="Integration type UNSUPPORTED_TYPE not supported"
        ):
            prowler_integration_connection_test(integration)
