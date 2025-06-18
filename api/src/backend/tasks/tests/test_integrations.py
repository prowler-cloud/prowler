from unittest.mock import MagicMock, patch

import pytest
from tasks.jobs.integrations import (
    get_s3_client_from_integration,
    upload_s3_integration,
)

from prowler.providers.common.models import Connection


@pytest.mark.django_db
class TestS3IntegrationUploads:

    @patch("tasks.jobs.integrations.AwsProvider")
    @patch("tasks.jobs.integrations.S3")
    def test_get_s3_client_from_integration_success(
        self, mock_s3_class, mock_aws_provider
    ):
        mock_integration = MagicMock()
        mock_integration.credentials = {
            "aws_access_key_id": "AKIA...",
            "aws_secret_access_key": "SECRET",
        }
        mock_integration.configuration = {
            "bucket_name": "test-bucket",
            "output_directory": "test-prefix",
        }

        mock_session = MagicMock()
        mock_aws_provider.return_value.session.current_session = mock_session

        mock_s3 = MagicMock()
        mock_connection = MagicMock()
        mock_connection.is_connected = True
        mock_s3.test_connection.return_value = mock_connection
        mock_s3_class.return_value = mock_s3

        connected, s3 = get_s3_client_from_integration(mock_integration)

        assert connected is True
        assert s3 == mock_s3

    @patch("tasks.jobs.integrations.AwsProvider")
    @patch("tasks.jobs.integrations.S3")
    def test_get_s3_client_from_integration_failure(
        self, mock_s3_class, mock_aws_provider
    ):
        mock_integration = MagicMock()
        mock_integration.credentials = {}
        mock_integration.configuration = {
            "bucket_name": "test-bucket",
            "output_directory": "test-prefix",
        }

        mock_session = MagicMock()
        mock_aws_provider.return_value.session.current_session = mock_session

        from prowler.providers.common.models import Connection

        mock_connection = Connection()
        mock_connection.is_connected = False
        mock_connection.error = "test error"

        mock_s3 = MagicMock()
        mock_s3.test_connection.return_value = mock_connection
        mock_s3_class.return_value = mock_s3

        connected, connection = get_s3_client_from_integration(mock_integration)

        assert connected is False
        assert isinstance(connection, Connection)
        assert connection.error == "test error"

    @patch("tasks.jobs.integrations.get_s3_client_from_integration")
    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    def test_upload_s3_integration_uploads_all_files(
        self, mock_integration_model, mock_rls, mock_get_s3, tmp_path
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

        output_dir = tmp_path / "upload"
        output_dir.mkdir()
        (output_dir / "out1.csv").write_text("result")
        compliance_dir = output_dir / "compliance"
        compliance_dir.mkdir()
        (compliance_dir / "c1.csv").write_text("comp")

        upload_s3_integration(tenant_id, provider_id, str(output_dir))

        assert mock_s3.upload_file.call_count == 2
        calls = [call.kwargs["key"] for call in mock_s3.upload_file.mock_calls]
        assert "prefix/out1.csv" in calls
        assert "prefix/compliance/c1.csv" in calls

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
        integration.configuration = {
            "bucket_name": "bucket",
            "output_directory": "prefix",
        }
        mock_integration_model.objects.filter.return_value = [integration]

        mock_connection = Connection()
        mock_connection.is_connected = False
        mock_connection.error = "Connection failed"

        mock_get_s3.return_value = (False, mock_connection)

        upload_s3_integration(tenant_id, provider_id, "/fake/path")
        mock_logger.error.assert_any_call(
            "S3 upload failed for integration i-1: Connection failed"
        )

    @patch("tasks.jobs.integrations.get_s3_client_from_integration")
    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.logger")
    def test_upload_s3_integration_logs_if_no_integrations(
        self, mock_logger, mock_integration_model, mock_rls, mock_get_s3
    ):
        mock_integration_model.objects.filter.return_value = []
        upload_s3_integration("tenant", "provider", "/some/path")
        mock_logger.error.assert_called_once_with(
            "No S3 integrations found for provider provider"
        )
