from unittest.mock import MagicMock, patch

import pytest
from tasks.jobs.integrations import (
    get_s3_client_from_integration,
    get_security_hub_client_from_integration,
    upload_s3_integration,
    upload_security_hub_integration,
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

    @patch("api.utils.SecurityHub")
    @patch("api.utils.initialize_prowler_provider")
    def test_aws_security_hub_integration_connection_success(
        self, mock_initialize_provider, mock_security_hub_class
    ):
        """Test successful AWS Security Hub integration connection."""
        integration = MagicMock()
        integration.integration_type = Integration.IntegrationChoices.AWS_SECURITY_HUB
        integration.credentials = {
            "aws_access_key_id": "AKIA...",
            "aws_secret_access_key": "SECRET",
        }
        integration.configuration = {"send_only_fails": True}

        # Mock integration provider relationship
        mock_provider = MagicMock()
        mock_provider.provider = "aws"
        mock_relationship = MagicMock()
        mock_relationship.provider = mock_provider
        integration.integrationproviderrelationship_set.first.return_value = (
            mock_relationship
        )

        # Mock prowler provider
        mock_prowler_provider = MagicMock()
        mock_prowler_provider.identity.account = "123456789012"
        mock_prowler_provider.identity.partition = "aws"
        mock_prowler_provider.session.current_session = MagicMock()
        mock_initialize_provider.return_value = mock_prowler_provider

        # Mock successful SecurityHub connection
        mock_connection = Connection(is_connected=True)
        mock_security_hub_class.test_connection.return_value = mock_connection

        result = prowler_integration_connection_test(integration)

        assert result.is_connected is True
        mock_security_hub_class.test_connection.assert_called_once_with(
            aws_account_id="123456789012",
            aws_partition="aws",
            session=mock_prowler_provider.session.current_session,
            raise_on_exception=False,
        )

    @patch("api.utils.SecurityHub")
    @patch("api.utils.initialize_prowler_provider")
    def test_aws_security_hub_integration_connection_failure(
        self, mock_initialize_provider, mock_security_hub_class
    ):
        """Test AWS Security Hub integration connection failure."""
        integration = MagicMock()
        integration.integration_type = Integration.IntegrationChoices.AWS_SECURITY_HUB
        integration.credentials = {
            "aws_access_key_id": "INVALID",
            "aws_secret_access_key": "CREDENTIALS",
        }
        integration.configuration = {"send_only_fails": False}

        # Mock integration provider relationship
        mock_provider = MagicMock()
        mock_provider.provider = "aws"
        mock_relationship = MagicMock()
        mock_relationship.provider = mock_provider
        integration.integrationproviderrelationship_set.first.return_value = (
            mock_relationship
        )

        # Mock prowler provider
        mock_prowler_provider = MagicMock()
        mock_prowler_provider.identity.account = "123456789012"
        mock_prowler_provider.identity.partition = "aws"
        mock_prowler_provider.session.current_session = MagicMock()
        mock_initialize_provider.return_value = mock_prowler_provider

        # Mock failed SecurityHub connection
        test_exception = Exception("SecurityHub not enabled")
        mock_connection = Connection(is_connected=False, error=test_exception)
        mock_security_hub_class.test_connection.return_value = mock_connection

        result = prowler_integration_connection_test(integration)

        assert result.is_connected is False
        assert result.error == test_exception

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


@pytest.mark.django_db
class TestSecurityHubIntegrationUploads:
    @patch("tasks.jobs.integrations.SecurityHub.test_connection")
    @patch("tasks.jobs.integrations.initialize_prowler_provider")
    def test_get_security_hub_client_from_integration_success(
        self, mock_initialize_provider, mock_test_connection
    ):
        """Test successful SecurityHub client creation."""
        # Mock integration
        mock_integration = MagicMock()
        mock_integration.configuration = {"send_only_fails": True}

        # Mock provider
        mock_provider = MagicMock()

        # Mock prowler provider
        mock_prowler_provider = MagicMock()
        mock_prowler_provider.identity.account = "123456789012"
        mock_prowler_provider.identity.partition = "aws"
        mock_prowler_provider.identity.audited_regions = ["us-east-1", "us-west-2"]
        mock_prowler_provider.session.current_session = MagicMock()
        mock_prowler_provider.get_available_aws_service_regions.return_value = [
            "us-east-1",
            "us-west-2",
        ]
        mock_initialize_provider.return_value = mock_prowler_provider

        # Mock successful connection
        mock_connection = MagicMock()
        mock_connection.is_connected = True
        mock_test_connection.return_value = mock_connection

        # Mock findings
        mock_findings = [{"finding": "test"}]

        with patch("tasks.jobs.integrations.SecurityHub") as mock_security_hub_class:
            mock_security_hub = MagicMock()
            mock_security_hub_class.return_value = mock_security_hub

            connected, security_hub = get_security_hub_client_from_integration(
                mock_integration, mock_provider, mock_findings
            )

        assert connected is True
        assert security_hub == mock_security_hub

        # Verify SecurityHub was initialized with correct parameters
        mock_security_hub_class.assert_called_once_with(
            aws_account_id="123456789012",
            aws_partition="aws",
            aws_session=mock_prowler_provider.session.current_session,
            findings=mock_findings,
            send_only_fails=True,
            aws_security_hub_available_regions=["us-east-1", "us-west-2"],
        )

    @patch("tasks.jobs.integrations.SecurityHub.test_connection")
    @patch("tasks.jobs.integrations.initialize_prowler_provider")
    def test_get_security_hub_client_from_integration_failure(
        self, mock_initialize_provider, mock_test_connection
    ):
        """Test SecurityHub client creation failure."""
        # Mock integration
        mock_integration = MagicMock()
        mock_integration.configuration = {"send_only_fails": False}

        # Mock provider
        mock_provider = MagicMock()

        # Mock prowler provider
        mock_prowler_provider = MagicMock()
        mock_prowler_provider.identity.account = "123456789012"
        mock_prowler_provider.identity.partition = "aws"
        mock_prowler_provider.session.current_session = MagicMock()
        mock_initialize_provider.return_value = mock_prowler_provider

        # Mock failed connection
        mock_connection = MagicMock()
        mock_connection.is_connected = False
        mock_connection.error = "Connection failed"
        mock_test_connection.return_value = mock_connection

        # Mock findings
        mock_findings = [{"finding": "test"}]

        connected, connection = get_security_hub_client_from_integration(
            mock_integration, mock_provider, mock_findings
        )

        assert connected is False
        assert connection == mock_connection

        # Verify test_connection was called with correct parameters
        mock_test_connection.assert_called_once_with(
            aws_account_id="123456789012",
            aws_partition="aws",
            session=mock_prowler_provider.session.current_session,
            raise_on_exception=False,
        )

    @patch("tasks.jobs.integrations.SecurityHub.test_connection")
    @patch("tasks.jobs.integrations.initialize_prowler_provider")
    def test_get_security_hub_client_from_integration_no_audited_regions(
        self, mock_initialize_provider, mock_test_connection
    ):
        """Test SecurityHub client creation when no audited regions are specified."""
        # Mock integration
        mock_integration = MagicMock()
        mock_integration.configuration = {"send_only_fails": False}

        # Mock provider
        mock_provider = MagicMock()

        # Mock prowler provider with no audited regions
        mock_prowler_provider = MagicMock()
        mock_prowler_provider.identity.account = "123456789012"
        mock_prowler_provider.identity.partition = "aws"
        mock_prowler_provider.identity.audited_regions = None
        mock_prowler_provider.session.current_session = MagicMock()
        mock_prowler_provider.get_available_aws_service_regions.return_value = [
            "us-east-1",
            "us-west-2",
            "eu-west-1",
        ]
        mock_initialize_provider.return_value = mock_prowler_provider

        # Mock successful connection
        mock_connection = MagicMock()
        mock_connection.is_connected = True
        mock_test_connection.return_value = mock_connection

        # Mock findings
        mock_findings = [{"finding": "test"}]

        with patch("tasks.jobs.integrations.SecurityHub") as mock_security_hub_class:
            mock_security_hub = MagicMock()
            mock_security_hub_class.return_value = mock_security_hub

            connected, security_hub = get_security_hub_client_from_integration(
                mock_integration, mock_provider, mock_findings
            )

        assert connected is True

        # Verify SecurityHub was initialized with available regions
        mock_security_hub_class.assert_called_once_with(
            aws_account_id="123456789012",
            aws_partition="aws",
            aws_session=mock_prowler_provider.session.current_session,
            findings=mock_findings,
            send_only_fails=False,
            aws_security_hub_available_regions=["us-east-1", "us-west-2", "eu-west-1"],
        )

    @patch("tasks.jobs.integrations.ASFF")
    @patch("tasks.jobs.integrations.FindingOutput")
    @patch("tasks.jobs.integrations.batched")
    @patch("tasks.jobs.integrations.get_security_hub_client_from_integration")
    @patch("tasks.jobs.integrations.initialize_prowler_provider")
    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.Provider")
    @patch("tasks.jobs.integrations.Finding")
    def test_upload_security_hub_integration_success(
        self,
        mock_finding_model,
        mock_provider_model,
        mock_integration_model,
        mock_rls,
        mock_initialize_provider,
        mock_get_security_hub,
        mock_batched,
        mock_finding_output,
        mock_asff,
    ):
        """Test successful SecurityHub integration upload."""
        tenant_id = "tenant-id"
        provider_id = "provider-id"
        scan_id = "scan-123"

        # Mock integration
        integration = MagicMock()
        integration.id = "integration-1"
        integration.configuration = {
            "send_only_fails": True,
            "skip_archive_previous": False,
        }
        mock_integration_model.objects.filter.return_value = [integration]

        # Mock provider
        provider = MagicMock()
        mock_provider_model.objects.get.return_value = provider

        # Mock prowler provider
        mock_prowler_provider = MagicMock()
        mock_initialize_provider.return_value = mock_prowler_provider

        # Mock findings
        mock_findings = [MagicMock(), MagicMock()]
        mock_finding_model.all_objects.filter.return_value.order_by.return_value.iterator.return_value = iter(
            mock_findings
        )

        # Mock batched to return findings in one batch
        mock_batched.return_value = [(mock_findings, None)]

        # Mock transformed findings
        transformed_findings = [MagicMock(), MagicMock()]
        mock_finding_output.transform_api_finding.side_effect = transformed_findings

        # Mock ASFF transformer
        mock_asff_instance = MagicMock()
        finding1 = MagicMock()
        finding1.Compliance.Status = "FAILED"
        finding2 = MagicMock()
        finding2.Compliance.Status = "FAILED"
        mock_asff_instance.data = [finding1, finding2]
        mock_asff_instance._data = MagicMock()
        mock_asff.return_value = mock_asff_instance

        # Mock SecurityHub client
        mock_security_hub = MagicMock()
        mock_security_hub.batch_send_to_security_hub.return_value = 2
        mock_security_hub.archive_previous_findings.return_value = 5
        mock_get_security_hub.return_value = (True, mock_security_hub)

        result = upload_security_hub_integration(tenant_id, provider_id, scan_id)

        assert result is True

        # Verify findings were transformed and sent
        assert mock_finding_output.transform_api_finding.call_count == 2
        mock_asff.assert_called_once()
        mock_asff_instance.transform.assert_called_once_with(transformed_findings)
        mock_security_hub.batch_send_to_security_hub.assert_called_once()
        mock_security_hub.archive_previous_findings.assert_called_once()

    @patch("tasks.jobs.integrations.get_security_hub_client_from_integration")
    @patch("tasks.jobs.integrations.initialize_prowler_provider")
    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.Provider")
    @patch("tasks.jobs.integrations.Finding")
    def test_upload_security_hub_integration_no_integrations(
        self,
        mock_finding_model,
        mock_provider_model,
        mock_integration_model,
        mock_rls,
        mock_initialize_provider,
        mock_get_security_hub,
    ):
        """Test SecurityHub upload when no integrations are found."""
        tenant_id = "tenant-id"
        provider_id = "provider-id"
        scan_id = "scan-123"

        # Mock no integrations found
        mock_integration_model.objects.filter.return_value = []

        result = upload_security_hub_integration(tenant_id, provider_id, scan_id)

        assert result is False

    @patch("tasks.jobs.integrations.batched")
    @patch("tasks.jobs.integrations.get_security_hub_client_from_integration")
    @patch("tasks.jobs.integrations.initialize_prowler_provider")
    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.Provider")
    @patch("tasks.jobs.integrations.Finding")
    def test_upload_security_hub_integration_no_findings(
        self,
        mock_finding_model,
        mock_provider_model,
        mock_integration_model,
        mock_rls,
        mock_initialize_provider,
        mock_get_security_hub,
        mock_batched,
    ):
        """Test SecurityHub upload when no findings are found."""
        tenant_id = "tenant-id"
        provider_id = "provider-id"
        scan_id = "scan-123"

        # Mock integration
        integration = MagicMock()
        integration.id = "integration-1"
        mock_integration_model.objects.filter.return_value = [integration]

        # Mock provider
        provider = MagicMock()
        mock_provider_model.objects.get.return_value = provider

        # Mock prowler provider
        mock_prowler_provider = MagicMock()
        mock_initialize_provider.return_value = mock_prowler_provider

        # Mock no findings
        mock_finding_model.all_objects.filter.return_value.order_by.return_value.iterator.return_value = iter(
            []
        )
        mock_batched.return_value = []

        result = upload_security_hub_integration(tenant_id, provider_id, scan_id)

        assert result is True  # No findings is considered success

    @patch("tasks.jobs.integrations.get_security_hub_client_from_integration")
    @patch("tasks.jobs.integrations.initialize_prowler_provider")
    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.Provider")
    @patch("tasks.jobs.integrations.Finding")
    def test_upload_security_hub_integration_connection_failure(
        self,
        mock_finding_model,
        mock_provider_model,
        mock_integration_model,
        mock_rls,
        mock_initialize_provider,
        mock_get_security_hub,
    ):
        """Test SecurityHub upload when connection fails."""
        tenant_id = "tenant-id"
        provider_id = "provider-id"
        scan_id = "scan-123"

        # Mock integration
        integration = MagicMock()
        integration.id = "integration-1"
        integration.connected = True
        mock_integration_model.objects.filter.return_value = [integration]

        # Mock provider
        provider = MagicMock()
        mock_provider_model.objects.get.return_value = provider

        # Mock prowler provider
        mock_prowler_provider = MagicMock()
        mock_initialize_provider.return_value = mock_prowler_provider

        # Mock findings exist
        mock_findings = [MagicMock()]
        mock_finding_model.all_objects.filter.return_value.order_by.return_value.iterator.return_value = iter(
            mock_findings
        )

        # Mock failed connection
        mock_connection = MagicMock()
        mock_connection.error = "Connection failed"
        mock_get_security_hub.return_value = (False, mock_connection)

        with patch("tasks.jobs.integrations.batched") as mock_batched:
            with patch("tasks.jobs.integrations.FindingOutput") as mock_finding_output:
                with patch("tasks.jobs.integrations.ASFF") as mock_asff:
                    # Mock batched and transformation
                    mock_batched.return_value = [(mock_findings, None)]
                    transformed_findings = [MagicMock()]
                    mock_finding_output.transform_api_finding.return_value = (
                        transformed_findings[0]
                    )

                    mock_asff_instance = MagicMock()
                    finding1 = MagicMock()
                    finding1.Compliance.Status = "FAILED"
                    mock_asff_instance.data = [finding1]
                    mock_asff_instance._data = MagicMock()
                    mock_asff.return_value = mock_asff_instance

                    result = upload_security_hub_integration(
                        tenant_id, provider_id, scan_id
                    )

        assert result is False
        # Integration should be marked as disconnected
        integration.save.assert_called_once()
        assert integration.connected is False

    @patch("tasks.jobs.integrations.ASFF")
    @patch("tasks.jobs.integrations.FindingOutput")
    @patch("tasks.jobs.integrations.batched")
    @patch("tasks.jobs.integrations.get_security_hub_client_from_integration")
    @patch("tasks.jobs.integrations.initialize_prowler_provider")
    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.Provider")
    @patch("tasks.jobs.integrations.Finding")
    def test_upload_security_hub_integration_skip_archive(
        self,
        mock_finding_model,
        mock_provider_model,
        mock_integration_model,
        mock_rls,
        mock_initialize_provider,
        mock_get_security_hub,
        mock_batched,
        mock_finding_output,
        mock_asff,
    ):
        """Test SecurityHub upload with skip_archive_previous enabled."""
        tenant_id = "tenant-id"
        provider_id = "provider-id"
        scan_id = "scan-123"

        # Mock integration with skip_archive_previous enabled
        integration = MagicMock()
        integration.id = "integration-1"
        integration.configuration = {
            "send_only_fails": False,
            "skip_archive_previous": True,
        }
        mock_integration_model.objects.filter.return_value = [integration]

        # Mock provider
        provider = MagicMock()
        mock_provider_model.objects.get.return_value = provider

        # Mock prowler provider
        mock_prowler_provider = MagicMock()
        mock_initialize_provider.return_value = mock_prowler_provider

        # Mock findings
        mock_findings = [MagicMock()]
        mock_finding_model.all_objects.filter.return_value.order_by.return_value.iterator.return_value = iter(
            mock_findings
        )

        # Mock batched and transformation
        mock_batched.return_value = [(mock_findings, None)]
        transformed_findings = [MagicMock()]
        mock_finding_output.transform_api_finding.return_value = transformed_findings[0]

        # Mock ASFF transformer
        mock_asff_instance = MagicMock()
        finding1 = MagicMock()
        finding1.Compliance.Status = "FAILED"
        mock_asff_instance.data = [finding1]
        mock_asff_instance._data = MagicMock()
        mock_asff.return_value = mock_asff_instance

        # Mock SecurityHub client
        mock_security_hub = MagicMock()
        mock_security_hub.batch_send_to_security_hub.return_value = 1
        mock_get_security_hub.return_value = (True, mock_security_hub)

        result = upload_security_hub_integration(tenant_id, provider_id, scan_id)

        assert result is True

        # Verify archiving was skipped
        mock_security_hub.archive_previous_findings.assert_not_called()
        mock_security_hub.batch_send_to_security_hub.assert_called_once()

    @patch("tasks.jobs.integrations.ASFF")
    @patch("tasks.jobs.integrations.FindingOutput")
    @patch("tasks.jobs.integrations.batched")
    @patch("tasks.jobs.integrations.get_security_hub_client_from_integration")
    @patch("tasks.jobs.integrations.initialize_prowler_provider")
    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.Provider")
    @patch("tasks.jobs.integrations.Finding")
    def test_upload_security_hub_integration_archive_failure(
        self,
        mock_finding_model,
        mock_provider_model,
        mock_integration_model,
        mock_rls,
        mock_initialize_provider,
        mock_get_security_hub,
        mock_batched,
        mock_finding_output,
        mock_asff,
    ):
        """Test SecurityHub upload when archiving fails but sending succeeds."""
        tenant_id = "tenant-id"
        provider_id = "provider-id"
        scan_id = "scan-123"

        # Mock integration
        integration = MagicMock()
        integration.id = "integration-1"
        integration.configuration = {
            "send_only_fails": False,
            "skip_archive_previous": False,
        }
        mock_integration_model.objects.filter.return_value = [integration]

        # Mock provider
        provider = MagicMock()
        mock_provider_model.objects.get.return_value = provider

        # Mock prowler provider
        mock_prowler_provider = MagicMock()
        mock_initialize_provider.return_value = mock_prowler_provider

        # Mock findings
        mock_findings = [MagicMock()]
        mock_finding_model.all_objects.filter.return_value.order_by.return_value.iterator.return_value = iter(
            mock_findings
        )

        # Mock batched and transformation
        mock_batched.return_value = [(mock_findings, None)]
        transformed_findings = [MagicMock()]
        mock_finding_output.transform_api_finding.return_value = transformed_findings[0]

        # Mock ASFF transformer
        mock_asff_instance = MagicMock()
        finding1 = MagicMock()
        finding1.Compliance.Status = "FAILED"
        mock_asff_instance.data = [finding1]
        mock_asff_instance._data = MagicMock()
        mock_asff.return_value = mock_asff_instance

        # Mock SecurityHub client - sending succeeds, archiving fails
        mock_security_hub = MagicMock()
        mock_security_hub.batch_send_to_security_hub.return_value = 1
        mock_security_hub.archive_previous_findings.side_effect = Exception(
            "Archive failed"
        )
        mock_get_security_hub.return_value = (True, mock_security_hub)

        result = upload_security_hub_integration(tenant_id, provider_id, scan_id)

        assert result is True  # Should still succeed even if archiving fails

        # Verify both methods were called
        mock_security_hub.batch_send_to_security_hub.assert_called_once()
        mock_security_hub.archive_previous_findings.assert_called_once()

    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.Provider")
    @patch("tasks.jobs.integrations.Finding")
    def test_upload_security_hub_integration_general_exception(
        self,
        mock_finding_model,
        mock_provider_model,
        mock_integration_model,
        mock_rls,
    ):
        """Test SecurityHub upload handles general exceptions."""
        tenant_id = "tenant-id"
        provider_id = "provider-id"
        scan_id = "scan-123"

        # Mock exception during integration retrieval
        mock_integration_model.objects.filter.side_effect = Exception("Database error")

        result = upload_security_hub_integration(tenant_id, provider_id, scan_id)

        assert result is False

    @patch("tasks.jobs.integrations.ASFF")
    @patch("tasks.jobs.integrations.FindingOutput")
    @patch("tasks.jobs.integrations.batched")
    @patch("tasks.jobs.integrations.get_security_hub_client_from_integration")
    @patch("tasks.jobs.integrations.initialize_prowler_provider")
    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.Provider")
    @patch("tasks.jobs.integrations.Finding")
    def test_upload_security_hub_integration_send_only_fails_filters_findings(
        self,
        mock_finding_model,
        mock_provider_model,
        mock_integration_model,
        mock_rls,
        mock_initialize_provider,
        mock_get_security_hub,
        mock_batched,
        mock_finding_output,
        mock_asff,
    ):
        """Test that send_only_fails=True filters findings to only include FAILED status."""
        tenant_id = "tenant-id"
        provider_id = "provider-id"
        scan_id = "scan-123"

        # Mock integration with send_only_fails=True
        integration = MagicMock()
        integration.id = "integration-1"
        integration.configuration = {
            "send_only_fails": True,
            "skip_archive_previous": False,
        }
        mock_integration_model.objects.filter.return_value = [integration]

        # Mock provider
        provider = MagicMock()
        mock_provider_model.objects.get.return_value = provider

        # Mock prowler provider
        mock_prowler_provider = MagicMock()
        mock_initialize_provider.return_value = mock_prowler_provider

        # Mock findings
        mock_findings = [MagicMock(), MagicMock()]
        mock_finding_model.all_objects.filter.return_value.order_by.return_value.iterator.return_value = iter(
            mock_findings
        )

        # Mock batched to return findings in one batch
        mock_batched.return_value = [(mock_findings, None)]

        # Mock transformed findings
        transformed_findings = [MagicMock(), MagicMock()]
        mock_finding_output.transform_api_finding.side_effect = transformed_findings

        # Mock ASFF transformer with mixed findings (FAILED and PASSED)
        mock_asff_instance = MagicMock()
        failed_finding = MagicMock()
        failed_finding.Compliance.Status = "FAILED"
        passed_finding = MagicMock()
        passed_finding.Compliance.Status = "PASSED"
        mock_asff_instance.data = [failed_finding, passed_finding]
        mock_asff_instance._data = MagicMock()
        mock_asff.return_value = mock_asff_instance

        # Mock SecurityHub client
        mock_security_hub = MagicMock()
        mock_security_hub.batch_send_to_security_hub.return_value = (
            1  # Only 1 finding sent (FAILED)
        )
        mock_security_hub.archive_previous_findings.return_value = 2
        mock_get_security_hub.return_value = (True, mock_security_hub)

        result = upload_security_hub_integration(tenant_id, provider_id, scan_id)

        assert result is True

        # Verify SecurityHub client was created with only FAILED findings
        # The filtered_asff_findings should only contain the FAILED finding
        mock_get_security_hub.assert_called_once()
        call_args = mock_get_security_hub.call_args[0]
        filtered_findings = call_args[2]  # Third argument is the findings list

        # Should only contain FAILED findings
        assert len(filtered_findings) == 1
        assert filtered_findings[0].Compliance.Status == "FAILED"

        mock_security_hub.batch_send_to_security_hub.assert_called_once()
        mock_security_hub.archive_previous_findings.assert_called_once()

    @patch("tasks.jobs.integrations.ASFF")
    @patch("tasks.jobs.integrations.FindingOutput")
    @patch("tasks.jobs.integrations.batched")
    @patch("tasks.jobs.integrations.get_security_hub_client_from_integration")
    @patch("tasks.jobs.integrations.initialize_prowler_provider")
    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.Provider")
    @patch("tasks.jobs.integrations.Finding")
    def test_upload_security_hub_integration_send_only_fails_false_sends_all(
        self,
        mock_finding_model,
        mock_provider_model,
        mock_integration_model,
        mock_rls,
        mock_initialize_provider,
        mock_get_security_hub,
        mock_batched,
        mock_finding_output,
        mock_asff,
    ):
        """Test that send_only_fails=False sends all findings."""
        tenant_id = "tenant-id"
        provider_id = "provider-id"
        scan_id = "scan-123"

        # Mock integration with send_only_fails=False
        integration = MagicMock()
        integration.id = "integration-1"
        integration.configuration = {
            "send_only_fails": False,
            "skip_archive_previous": False,
        }
        mock_integration_model.objects.filter.return_value = [integration]

        # Mock provider
        provider = MagicMock()
        mock_provider_model.objects.get.return_value = provider

        # Mock prowler provider
        mock_prowler_provider = MagicMock()
        mock_initialize_provider.return_value = mock_prowler_provider

        # Mock findings
        mock_findings = [MagicMock(), MagicMock()]
        mock_finding_model.all_objects.filter.return_value.order_by.return_value.iterator.return_value = iter(
            mock_findings
        )

        # Mock batched to return findings in one batch
        mock_batched.return_value = [(mock_findings, None)]

        # Mock transformed findings
        transformed_findings = [MagicMock(), MagicMock()]
        mock_finding_output.transform_api_finding.side_effect = transformed_findings

        # Mock ASFF transformer with mixed findings (FAILED and PASSED)
        mock_asff_instance = MagicMock()
        mock_asff_instance.data = [
            {"Compliance": {"Status": "FAILED"}, "asff": "failed_finding"},
            {"Compliance": {"Status": "PASSED"}, "asff": "passed_finding"},
        ]
        mock_asff_instance._data = MagicMock()
        mock_asff.return_value = mock_asff_instance

        # Mock SecurityHub client
        mock_security_hub = MagicMock()
        mock_security_hub.batch_send_to_security_hub.return_value = (
            2  # Both findings sent
        )
        mock_security_hub.archive_previous_findings.return_value = 2
        mock_get_security_hub.return_value = (True, mock_security_hub)

        result = upload_security_hub_integration(tenant_id, provider_id, scan_id)

        assert result is True

        # Verify SecurityHub client was created with all findings
        mock_get_security_hub.assert_called_once()
        call_args = mock_get_security_hub.call_args[0]
        filtered_findings = call_args[2]  # Third argument is the findings list

        # Should contain all findings
        assert len(filtered_findings) == 2

        mock_security_hub.batch_send_to_security_hub.assert_called_once()
        mock_security_hub.archive_previous_findings.assert_called_once()
