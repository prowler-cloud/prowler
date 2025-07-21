from unittest.mock import MagicMock, patch

import pytest
from tasks.jobs.integrations import (
    check_integrations,
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

    @patch("tasks.jobs.integrations.get_s3_client_from_integration")
    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.globals")
    def test_upload_s3_integration_uploads_serialized_outputs(
        self, mock_globals, mock_integration_model, mock_rls, mock_get_s3
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

        # Mock the CSV output class
        mock_csv_class = MagicMock()
        mock_output = MagicMock()
        mock_csv_class.return_value = mock_output
        mock_globals.get.return_value = mock_csv_class

        serialized_outputs = {
            "regular": [
                {"class_name": "Csv", "file_path": "/tmp/output.csv"},
            ],
            "compliance": [
                {"class_name": "GenericCompliance", "file_path": "/tmp/compliance.csv"},
            ],
        }

        with patch("os.path.exists", return_value=True):
            result = upload_s3_integration(tenant_id, provider_id, serialized_outputs)

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
        mock_connection = Connection()
        mock_connection.is_connected = False
        mock_connection.error = Exception("Connection failed")

        mock_integration_model.objects.filter.return_value = [integration]
        mock_get_s3.return_value = (False, mock_connection)

        serialized_outputs = {"regular": [], "compliance": []}
        result = upload_s3_integration(tenant_id, provider_id, serialized_outputs)

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
        serialized_outputs = {"regular": [], "compliance": []}
        result = upload_s3_integration("tenant", "provider", serialized_outputs)

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

        serialized_outputs = {"regular": [], "compliance": []}
        result = upload_s3_integration(tenant_id, provider_id, serialized_outputs)

        assert result is False
        mock_logger.error.assert_any_call(
            "S3 connection failed for integration i-1: failed"
        )


@pytest.mark.django_db
class TestCheckIntegrations:
    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    def test_check_integrations_no_integrations(self, mock_integration_model, mock_rls):
        mock_integration_model.objects.filter.return_value.exists.return_value = False

        result = check_integrations("tenant-id", "provider-id")

        assert result == {"integrations_processed": 0}

    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    def test_check_integrations_with_integrations(
        self, mock_integration_model, mock_rls
    ):
        mock_integration_model.objects.filter.return_value.exists.return_value = True

        result = check_integrations("tenant-id", "provider-id")

        assert result["integrations_processed"] == 0
        assert result["tasks"] == []

    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.logger")
    def test_check_integrations_exception(
        self, mock_logger, mock_integration_model, mock_rls
    ):
        mock_rls.side_effect = Exception("Database error")

        result = check_integrations("tenant-id", "provider-id")

        assert result["integrations_processed"] == 0
        assert "error" in result
        assert result["error"] == "Database error"
        mock_logger.error.assert_called_once()


@pytest.mark.django_db
class TestProwlerIntegrationConnectionTest:
    @patch("api.utils.AwsProvider")
    @patch("api.utils.S3")
    def test_s3_integration_connection_success(self, mock_s3_class, mock_aws_provider):
        """Test successful S3 integration connection."""
        integration = MagicMock()
        integration.integration_type = Integration.IntegrationChoices.AMAZON_S3
        integration.credentials = {
            "aws_access_key_id": "AKIA...",
            "aws_secret_access_key": "SECRET",
        }
        integration.configuration = {"bucket_name": "test-bucket"}

        mock_session = MagicMock()
        mock_aws_provider.return_value.session.current_session = mock_session

        mock_connection = Connection(is_connected=True)
        mock_s3_class.test_connection.return_value = mock_connection

        result = prowler_integration_connection_test(integration)

        assert result.is_connected is True
        mock_aws_provider.assert_called_once_with(**integration.credentials)
        mock_s3_class.test_connection.assert_called_once_with(
            **integration.credentials,
            bucket_name="test-bucket",
            raise_on_exception=False,
        )

    @patch("api.utils.AwsProvider")
    def test_aws_provider_exception_handling(self, mock_aws_provider):
        """Test AWS provider exception is properly caught and returned."""
        integration = MagicMock()
        integration.integration_type = Integration.IntegrationChoices.AMAZON_S3
        integration.credentials = {"invalid": "credentials"}
        integration.configuration = {"bucket_name": "test-bucket"}

        test_exception = Exception("Invalid credentials")
        mock_aws_provider.side_effect = test_exception

        result = prowler_integration_connection_test(integration)

        assert result.is_connected is False
        assert result.error == test_exception

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
