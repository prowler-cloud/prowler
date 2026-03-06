from unittest.mock import MagicMock, patch

import pytest
from django.db import OperationalError
from tasks.jobs.integrations import (
    get_s3_client_from_integration,
    get_security_hub_client_from_integration,
    send_findings_to_jira,
    upload_s3_integration,
    upload_security_hub_integration,
)

from api.db_router import READ_REPLICA_ALIAS, MainRouter
from api.models import Integration
from api.utils import prowler_integration_connection_test
from prowler.providers.aws.lib.security_hub.security_hub import SecurityHubConnection
from prowler.providers.common.models import Connection


@pytest.mark.django_db
class TestS3IntegrationUploads:
    @patch("tasks.jobs.integrations.S3")
    def test_get_s3_client_from_integration_success(self, mock_s3_class):
        mock_integration = MagicMock()
        mock_integration.credentials = {
            "aws_access_key_id": "test_key_id",
            "aws_secret_access_key": "test_secret_key",
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
            "S3 upload failed, connection failed for integration i-1: Connection failed"
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
        mock_logger.info.assert_any_call(
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
            "aws_access_key_id": "test_key_id",
            "aws_secret_access_key": "test_secret_key",
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
            "aws_access_key_id": "test_key_id",
            "aws_secret_access_key": "test_secret_key",
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
            "aws_access_key_id": "invalid_key",
            "aws_secret_access_key": "invalid_secret",
        }
        integration.configuration = {"bucket_name": "test-bucket"}

        test_exception = Exception("Invalid credentials")
        mock_connection = Connection(is_connected=False, error=test_exception)
        mock_s3_class.test_connection.return_value = mock_connection

        result = prowler_integration_connection_test(integration)

        assert result.is_connected is False
        assert result.error == test_exception
        mock_s3_class.test_connection.assert_called_once_with(
            aws_access_key_id="invalid_key",
            aws_secret_access_key="invalid_secret",
            bucket_name="test-bucket",
            raise_on_exception=False,
        )

    @patch("api.utils.S3")
    def test_s3_integration_connection_failure(self, mock_s3_class):
        """Test S3 integration connection failure."""
        integration = MagicMock()
        integration.integration_type = Integration.IntegrationChoices.AMAZON_S3
        integration.credentials = {
            "aws_access_key_id": "test_key_id",
            "aws_secret_access_key": "test_secret_key",
        }
        integration.configuration = {"bucket_name": "test-bucket"}

        mock_connection = Connection(
            is_connected=False, error=Exception("Bucket not found")
        )
        mock_s3_class.test_connection.return_value = mock_connection

        result = prowler_integration_connection_test(integration)

        assert result.is_connected is False
        assert str(result.error) == "Bucket not found"

    @patch("api.utils.SecurityHub")
    def test_aws_security_hub_integration_connection_success(
        self, mock_security_hub_class
    ):
        """Test successful AWS Security Hub integration connection."""
        integration = MagicMock()
        integration.integration_type = Integration.IntegrationChoices.AWS_SECURITY_HUB
        integration.credentials = {
            "aws_access_key_id": "test_key_id",
            "aws_secret_access_key": "test_secret_key",
        }
        integration.configuration = {"send_only_fails": True}

        # Mock integration provider relationship
        mock_provider = MagicMock()
        mock_provider.uid = "123456789012"
        mock_relationship = MagicMock()
        mock_relationship.provider = mock_provider
        integration.integrationproviderrelationship_set.first.return_value = (
            mock_relationship
        )

        # Mock successful SecurityHub connection with regions
        mock_connection = SecurityHubConnection(
            is_connected=True,
            error=None,
            enabled_regions={"us-east-1", "us-west-2", "eu-west-1"},
            disabled_regions={"us-east-2", "eu-west-2"},
        )
        mock_security_hub_class.test_connection.return_value = mock_connection

        result = prowler_integration_connection_test(integration)

        assert result.is_connected is True
        mock_security_hub_class.test_connection.assert_called_once_with(
            aws_account_id="123456789012",
            raise_on_exception=False,
            aws_access_key_id="test_key_id",
            aws_secret_access_key="test_secret_key",
        )
        # Verify regions were saved
        assert integration.configuration["regions"]["us-east-1"] is True
        assert integration.configuration["regions"]["us-west-2"] is True
        assert integration.configuration["regions"]["eu-west-1"] is True
        assert integration.configuration["regions"]["us-east-2"] is False
        assert integration.configuration["regions"]["eu-west-2"] is False
        integration.save.assert_called_once()

    @patch("api.utils.SecurityHub")
    def test_aws_security_hub_integration_connection_failure(
        self, mock_security_hub_class
    ):
        """Test AWS Security Hub integration connection failure resets regions."""
        integration = MagicMock()
        integration.integration_type = Integration.IntegrationChoices.AWS_SECURITY_HUB
        integration.credentials = {
            "aws_access_key_id": "invalid_key",
            "aws_secret_access_key": "invalid_secret",
        }
        integration.configuration = {
            "send_only_fails": False,
            "regions": {"us-east-1": True, "us-west-2": False},  # Existing regions
        }

        # Mock integration provider relationship
        mock_provider = MagicMock()
        mock_provider.uid = "123456789012"
        mock_relationship = MagicMock()
        mock_relationship.provider = mock_provider
        integration.integrationproviderrelationship_set.first.return_value = (
            mock_relationship
        )

        # Mock failed SecurityHub connection
        test_exception = Exception("SecurityHub not enabled")
        mock_connection = SecurityHubConnection(
            is_connected=False,
            error=test_exception,
            enabled_regions=set(),
            disabled_regions=set(),
        )
        mock_security_hub_class.test_connection.return_value = mock_connection

        result = prowler_integration_connection_test(integration)

        assert result.is_connected is False
        assert result.error == test_exception
        # Verify regions were reset to empty dict when connection failed
        assert integration.configuration["regions"] == {}
        integration.save.assert_called_once()

    @patch("api.utils.SecurityHub")
    def test_aws_security_hub_integration_with_provider_credentials(
        self, mock_security_hub_class
    ):
        """Test AWS Security Hub integration using provider credentials."""
        integration = MagicMock()
        integration.integration_type = Integration.IntegrationChoices.AWS_SECURITY_HUB
        integration.credentials = None  # No custom credentials
        integration.configuration = {"send_only_fails": True}

        # Mock integration provider relationship
        mock_provider = MagicMock()
        mock_provider.uid = "123456789012"
        mock_provider.secret.secret = {
            "aws_access_key_id": "test_key_id",
            "aws_secret_access_key": "test_secret_key",
        }
        mock_relationship = MagicMock()
        mock_relationship.provider = mock_provider
        integration.integrationproviderrelationship_set.first.return_value = (
            mock_relationship
        )

        # Mock successful SecurityHub connection with regions
        mock_connection = SecurityHubConnection(
            is_connected=True,
            error=None,
            enabled_regions={"us-east-1", "eu-central-1"},
            disabled_regions={"ap-south-1"},
        )
        mock_security_hub_class.test_connection.return_value = mock_connection

        result = prowler_integration_connection_test(integration)

        assert result.is_connected
        # Should use provider credentials
        mock_security_hub_class.test_connection.assert_called_once_with(
            aws_account_id="123456789012",
            raise_on_exception=False,
            aws_access_key_id="test_key_id",
            aws_secret_access_key="test_secret_key",
        )
        # Verify regions were saved
        assert integration.configuration["regions"]["us-east-1"]
        assert integration.configuration["regions"]["eu-central-1"]
        assert not integration.configuration["regions"]["ap-south-1"]
        integration.save.assert_called_once()

    @patch("api.utils.SecurityHub")
    def test_aws_security_hub_connection_failure_with_multiple_regions_clears_all(
        self, mock_security_hub_class
    ):
        """Test that SecurityHub connection failure clears all existing regions data."""
        integration = MagicMock()
        integration.integration_type = Integration.IntegrationChoices.AWS_SECURITY_HUB
        integration.credentials = {
            "aws_access_key_id": "test_key",
            "aws_secret_access_key": "test_secret",
        }
        # Start with complex regions configuration
        integration.configuration = {
            "send_only_fails": True,
            "regions": {
                "us-east-1": True,
                "us-east-2": False,
                "us-west-1": True,
                "us-west-2": True,
                "eu-west-1": False,
                "eu-west-2": True,
                "eu-central-1": True,
                "ap-northeast-1": False,
                "ap-southeast-1": True,
                "ap-southeast-2": False,
            },
        }

        # Mock integration provider relationship
        mock_provider = MagicMock()
        mock_provider.uid = "987654321098"
        mock_relationship = MagicMock()
        mock_relationship.provider = mock_provider
        integration.integrationproviderrelationship_set.first.return_value = (
            mock_relationship
        )

        # Mock failed SecurityHub connection
        mock_connection = SecurityHubConnection(
            is_connected=False,
            error=Exception("Invalid credentials or permissions"),
            enabled_regions=set(),
            disabled_regions=set(),
        )
        mock_security_hub_class.test_connection.return_value = mock_connection

        result = prowler_integration_connection_test(integration)

        assert result.is_connected is False
        assert str(result.error) == "Invalid credentials or permissions"

        # Verify all regions were completely cleared
        assert integration.configuration["regions"] == {}
        assert len(integration.configuration["regions"]) == 0

        # Verify save was called to persist the cleared regions
        integration.save.assert_called_once()

        # Verify the test_connection was called with correct parameters
        mock_security_hub_class.test_connection.assert_called_once_with(
            aws_account_id="987654321098",
            raise_on_exception=False,
            aws_access_key_id="test_key",
            aws_secret_access_key="test_secret",
        )

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
    @patch("tasks.jobs.integrations.AwsProvider")
    @patch("tasks.jobs.integrations.SecurityHub.test_connection")
    @patch("tasks.jobs.integrations.initialize_prowler_provider")
    def test_get_security_hub_client_from_integration_success(
        self, mock_initialize_provider, mock_test_connection, mock_aws_provider
    ):
        """Test successful SecurityHub client creation."""
        # Mock integration
        mock_integration = MagicMock()
        mock_integration.configuration = {"send_only_fails": True}
        mock_integration.credentials = {}  # Empty credentials, use provider

        # Mock tenant_id
        tenant_id = "550e8400-e29b-41d4-a716-446655440000"  # Valid UUID

        # Mock provider relationship
        mock_provider = MagicMock()
        mock_provider.uid = "123456789012"
        mock_provider.secret.secret = {
            "aws_access_key_id": "test_key_id",
            "aws_secret_access_key": "test_secret_key",
        }
        mock_relationship = MagicMock()
        mock_relationship.provider = mock_provider
        mock_integration.integrationproviderrelationship_set.first.return_value = (
            mock_relationship
        )

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

        # Mock successful connection with SecurityHub-specific attributes
        mock_connection = MagicMock()
        mock_connection.is_connected = True
        mock_connection.partition = "aws"
        mock_connection.enabled_regions = {"us-east-1": True, "us-west-2": True}
        mock_test_connection.return_value = mock_connection

        # Mock AwsProvider.get_available_aws_service_regions
        mock_aws_provider.get_available_aws_service_regions.return_value = [
            "us-east-1",
            "us-west-2",
        ]

        # Mock findings
        mock_findings = [{"finding": "test"}]

        with patch("tasks.jobs.integrations.SecurityHub") as mock_security_hub_class:
            mock_security_hub = MagicMock()
            mock_security_hub._enabled_regions = {"us-east-1": True, "us-west-2": True}
            mock_security_hub_class.return_value = mock_security_hub
            # Configure the test_connection to return our mock_connection
            mock_security_hub_class.test_connection = mock_test_connection

            connected, security_hub = get_security_hub_client_from_integration(
                mock_integration, tenant_id, mock_findings
            )

        assert connected is True
        assert security_hub == mock_security_hub

        # Verify SecurityHub was called once to create the client
        assert mock_security_hub_class.call_count == 1

        # Verify the call has the correct parameters
        actual_call = mock_security_hub_class.call_args_list[0]
        assert actual_call.kwargs["aws_account_id"] == "123456789012"
        assert actual_call.kwargs["findings"] == mock_findings
        assert actual_call.kwargs["send_only_fails"]
        # Check that available_regions list was passed correctly
        assert actual_call.kwargs["aws_security_hub_available_regions"] == [
            "us-east-1",
            "us-west-2",
        ]

    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.SecurityHub.test_connection")
    @patch("tasks.jobs.integrations.initialize_prowler_provider")
    def test_get_security_hub_client_from_integration_failure(
        self, mock_initialize_provider, mock_test_connection, mock_rls
    ):
        """Test SecurityHub client creation failure resets regions."""
        # Mock integration
        mock_integration = MagicMock()
        mock_integration.configuration = {
            "send_only_fails": False,
            "regions": {"us-east-1": True, "us-west-2": False},  # Existing regions
        }
        mock_integration.credentials = {}  # Empty credentials, use provider

        # Mock tenant_id
        tenant_id = "550e8400-e29b-41d4-a716-446655440000"  # Valid UUID

        # Mock provider relationship
        mock_provider = MagicMock()
        mock_provider.uid = "123456789012"
        mock_provider.secret.secret = {
            "aws_access_key_id": "test_key_id",
            "aws_secret_access_key": "test_secret_key",
        }
        mock_relationship = MagicMock()
        mock_relationship.provider = mock_provider
        mock_integration.integrationproviderrelationship_set.first.return_value = (
            mock_relationship
        )

        # Mock failed connection
        mock_connection = MagicMock()
        mock_connection.is_connected = False
        mock_connection.error = "Connection failed"
        mock_test_connection.return_value = mock_connection

        # Mock findings
        mock_findings = [{"finding": "test"}]

        # Mock RLS context manager
        mock_rls.return_value.__enter__.return_value = None

        connected, connection = get_security_hub_client_from_integration(
            mock_integration, tenant_id, mock_findings
        )

        assert connected is False
        assert connection == mock_connection

        # Verify test_connection was called with correct parameters
        mock_test_connection.assert_called_once_with(
            aws_account_id="123456789012",
            raise_on_exception=False,
            aws_access_key_id="test_key_id",
            aws_secret_access_key="test_secret_key",
        )

        # Verify regions were reset to empty when connection failed
        assert mock_integration.configuration["regions"] == {}
        mock_integration.save.assert_called_once()
        # Verify RLS transaction was used for the reset
        assert (
            mock_rls.call_count == 2
        )  # Once for getting provider, once for resetting regions

    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.SecurityHub.test_connection")
    def test_get_security_hub_client_from_integration_failure_clears_existing_regions(
        self, mock_test_connection, mock_rls
    ):
        """Test that SecurityHub client creation failure clears existing regions configuration."""
        # Mock integration with pre-existing regions configuration
        mock_integration = MagicMock()
        mock_integration.configuration = {
            "send_only_fails": True,
            "regions": {
                "us-east-1": True,
                "us-west-2": True,
                "eu-west-1": False,
                "ap-south-1": False,
            },  # Pre-existing regions configuration
        }
        mock_integration.credentials = {
            "aws_access_key_id": "test_key_id",
            "aws_secret_access_key": "test_secret_key",
        }

        # Mock tenant_id
        tenant_id = "550e8400-e29b-41d4-a716-446655440000"

        # Mock provider relationship
        mock_provider = MagicMock()
        mock_provider.uid = "123456789012"
        mock_provider.secret.secret = {
            "aws_access_key_id": "provider_key",
            "aws_secret_access_key": "provider_secret",
        }
        mock_relationship = MagicMock()
        mock_relationship.provider = mock_provider
        mock_integration.integrationproviderrelationship_set.first.return_value = (
            mock_relationship
        )

        # Mock failed connection with specific error
        mock_connection = MagicMock()
        mock_connection.is_connected = False
        mock_connection.error = "Access denied: SecurityHub not enabled in region"
        mock_test_connection.return_value = mock_connection

        # Mock findings
        mock_findings = [{"finding": "test1"}, {"finding": "test2"}]

        # Mock RLS context manager
        mock_rls.return_value.__enter__.return_value = None

        # Call the function
        connected, connection = get_security_hub_client_from_integration(
            mock_integration, tenant_id, mock_findings
        )

        # Assertions
        assert connected is False
        assert connection == mock_connection
        assert connection.error == "Access denied: SecurityHub not enabled in region"

        # Verify that regions configuration was completely cleared
        assert mock_integration.configuration["regions"] == {}

        # Verify save was called to persist the change
        mock_integration.save.assert_called_once()

        # Verify RLS transaction was used correctly
        # Should be called twice: once for getting provider info, once for resetting regions
        assert mock_rls.call_count == 2
        mock_rls.assert_any_call(tenant_id, using=READ_REPLICA_ALIAS)
        mock_rls.assert_any_call(tenant_id, using=MainRouter.default_db)

        # Verify test_connection was called with integration credentials (not provider's)
        mock_test_connection.assert_called_once_with(
            aws_account_id="123456789012",
            raise_on_exception=False,
            aws_access_key_id="test_key_id",
            aws_secret_access_key="test_secret_key",
        )

    @patch("tasks.jobs.integrations.AwsProvider")
    @patch("tasks.jobs.integrations.SecurityHub.test_connection")
    @patch("tasks.jobs.integrations.initialize_prowler_provider")
    def test_get_security_hub_client_from_integration_no_audited_regions(
        self, mock_initialize_provider, mock_test_connection, mock_aws_provider
    ):
        """Test SecurityHub client creation when no audited regions are specified."""
        # Mock integration
        mock_integration = MagicMock()
        mock_integration.configuration = {"send_only_fails": False}
        mock_integration.credentials = {}  # Empty credentials, use provider

        # Mock tenant_id
        tenant_id = "550e8400-e29b-41d4-a716-446655440000"  # Valid UUID

        # Mock provider relationship
        mock_provider = MagicMock()
        mock_provider.uid = "123456789012"
        mock_provider.secret.secret = {
            "aws_access_key_id": "test_key_id",
            "aws_secret_access_key": "test_secret_key",
        }
        mock_relationship = MagicMock()
        mock_relationship.provider = mock_provider
        mock_integration.integrationproviderrelationship_set.first.return_value = (
            mock_relationship
        )

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

        # Mock successful connection with SecurityHub-specific attributes
        mock_connection = MagicMock()
        mock_connection.is_connected = True
        mock_connection.partition = "aws"
        mock_connection.enabled_regions = {"us-east-1": True, "us-west-2": True}
        mock_test_connection.return_value = mock_connection

        # Mock AwsProvider.get_available_aws_service_regions
        mock_aws_provider.get_available_aws_service_regions.return_value = [
            "us-east-1",
            "us-west-2",
            "eu-west-1",
        ]

        # Mock findings
        mock_findings = [{"finding": "test"}]

        with patch("tasks.jobs.integrations.SecurityHub") as mock_security_hub_class:
            mock_security_hub = MagicMock()
            mock_security_hub._enabled_regions = {"us-east-1": True, "us-west-2": True}
            mock_security_hub_class.return_value = mock_security_hub
            # Configure the test_connection to return our mock_connection
            mock_security_hub_class.test_connection = mock_test_connection

            connected, security_hub = get_security_hub_client_from_integration(
                mock_integration, tenant_id, mock_findings
            )

        assert connected is True

        # Verify SecurityHub was called once to create the client
        assert mock_security_hub_class.call_count == 1

        # Verify the call has the correct parameters
        actual_call = mock_security_hub_class.call_args_list[0]
        assert actual_call.kwargs["aws_account_id"] == "123456789012"
        assert actual_call.kwargs["findings"] == mock_findings
        assert not actual_call.kwargs["send_only_fails"]
        # Check that available_regions list was passed correctly
        assert actual_call.kwargs["aws_security_hub_available_regions"] == [
            "us-east-1",
            "us-west-2",
        ]

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
            "archive_previous_findings": True,
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

    @patch("tasks.jobs.integrations.time.sleep")
    @patch("tasks.jobs.integrations.batched")
    @patch("tasks.jobs.integrations.get_security_hub_client_from_integration")
    @patch("tasks.jobs.integrations.initialize_prowler_provider")
    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.Provider")
    @patch("tasks.jobs.integrations.Finding")
    def test_upload_security_hub_integration_retries_on_operational_error(
        self,
        mock_finding_model,
        mock_provider_model,
        mock_integration_model,
        mock_rls,
        mock_initialize_provider,
        mock_get_security_hub,
        mock_batched,
        mock_sleep,
    ):
        """Test SecurityHub upload retries on transient OperationalError."""
        tenant_id = "tenant-id"
        provider_id = "provider-id"
        scan_id = "scan-123"

        integration = MagicMock()
        integration.id = "integration-1"
        integration.configuration = {
            "send_only_fails": True,
            "archive_previous_findings": False,
        }
        mock_integration_model.objects.filter.return_value = [integration]

        provider = MagicMock()
        mock_provider_model.objects.get.return_value = provider

        mock_prowler_provider = MagicMock()
        mock_initialize_provider.return_value = mock_prowler_provider

        mock_findings = [MagicMock(), MagicMock()]
        mock_finding_model.all_objects.filter.return_value.order_by.return_value.iterator.return_value = iter(
            mock_findings
        )

        transformed_findings = [MagicMock(), MagicMock()]
        with patch("tasks.jobs.integrations.FindingOutput") as mock_finding_output:
            mock_finding_output.transform_api_finding.side_effect = transformed_findings

            with patch("tasks.jobs.integrations.ASFF") as mock_asff:
                mock_asff_instance = MagicMock()
                finding1 = MagicMock()
                finding1.Compliance.Status = "FAILED"
                finding2 = MagicMock()
                finding2.Compliance.Status = "FAILED"
                mock_asff_instance.data = [finding1, finding2]
                mock_asff_instance._data = MagicMock()
                mock_asff.return_value = mock_asff_instance

                mock_security_hub = MagicMock()
                mock_security_hub.batch_send_to_security_hub.return_value = 2
                mock_get_security_hub.return_value = (True, mock_security_hub)

                mock_rls.return_value.__enter__.return_value = None
                mock_rls.return_value.__exit__.return_value = False

                mock_batched.side_effect = [
                    OperationalError("Conflict with recovery"),
                    [(mock_findings, None)],
                ]

                with patch("tasks.jobs.integrations.REPLICA_MAX_ATTEMPTS", 2):
                    with patch("tasks.jobs.integrations.READ_REPLICA_ALIAS", "replica"):
                        result = upload_security_hub_integration(
                            tenant_id, provider_id, scan_id
                        )

        assert result is True
        mock_sleep.assert_called_once()

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
        """Test SecurityHub upload with archive_previous_findings disabled."""
        tenant_id = "tenant-id"
        provider_id = "provider-id"
        scan_id = "scan-123"

        # Mock integration with archive_previous_findings disabled
        integration = MagicMock()
        integration.id = "integration-1"
        integration.configuration = {
            "send_only_fails": False,
            "archive_previous_findings": False,
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
            "archive_previous_findings": True,
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
            "archive_previous_findings": True,
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

        # Verify SecurityHub client was created with ALL findings (both FAILED and PASSED)
        # The SecurityHub client internally filters based on send_only_fails configuration
        mock_get_security_hub.assert_called_once()
        call_args = mock_get_security_hub.call_args[0]
        all_findings = call_args[2]  # Third argument is the findings list

        # Should contain both FAILED and PASSED findings
        assert len(all_findings) == 2
        assert any(f.Compliance.Status == "FAILED" for f in all_findings)
        assert any(f.Compliance.Status == "PASSED" for f in all_findings)

        # The SecurityHub client should have been configured with send_only_fails=True
        # and will filter internally when sending
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
            "archive_previous_findings": True,
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


@pytest.mark.django_db
class TestJiraIntegration:
    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Finding")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.initialize_prowler_integration")
    def test_send_findings_to_jira_success(
        self,
        mock_initialize_integration,
        mock_integration_model,
        mock_finding_model,
        mock_rls_transaction,
    ):
        """Test successful sending of findings to Jira using send_finding method"""
        tenant_id = "tenant-123"
        integration_id = "integration-456"
        project_key = "PROJ"
        issue_type = "Task"
        finding_ids = ["finding-1", "finding-2"]

        # Mock RLS transaction
        mock_rls_transaction.return_value.__enter__ = MagicMock()
        mock_rls_transaction.return_value.__exit__ = MagicMock()

        # Mock integration
        integration = MagicMock()
        mock_integration_model.objects.get.return_value = integration

        # Mock Jira integration
        mock_jira_integration = MagicMock()
        mock_jira_integration.send_finding.side_effect = [True, True]  # Both succeed
        mock_initialize_integration.return_value = mock_jira_integration

        # Mock findings with resources
        resource1 = MagicMock()
        resource1.uid = "resource-uid-1"
        resource1.name = "resource-name-1"
        resource1.region = "us-east-1"
        resource1.get_tags.return_value = {"env": "prod", "team": "security"}

        resource2 = MagicMock()
        resource2.uid = "resource-uid-2"
        resource2.name = "resource-name-2"
        resource2.region = "eu-west-1"
        resource2.get_tags.return_value = {"env": "dev"}

        finding1 = MagicMock()
        finding1.id = "finding-1"
        finding1.check_id = "check_001"
        finding1.severity = "high"
        finding1.status = "FAIL"
        finding1.status_extended = "Resource is not compliant"
        finding1.resource_regions = ["us-east-1"]
        finding1.compliance = {"cis": ["1.1", "1.2"]}
        finding1.resources.exists.return_value = True
        finding1.resources.first.return_value = resource1
        finding1.scan.provider.provider = "aws"
        finding1.check_metadata = {
            "checktitle": "Check Title 1",
            "risk": "High risk finding",
            "remediation": {
                "recommendation": {
                    "text": "Fix this issue",
                    "url": "https://docs.example.com/fix",
                },
                "code": {
                    "nativeiac": "native code",
                    "terraform": "terraform code",
                    "cli": "aws cli command",
                    "other": "",
                },
            },
        }

        finding2 = MagicMock()
        finding2.id = "finding-2"
        finding2.check_id = "check_002"
        finding2.severity = "medium"
        finding2.status = "PASS"
        finding2.status_extended = None
        finding2.resource_regions = []
        finding2.compliance = {}
        finding2.resources.exists.return_value = True
        finding2.resources.first.return_value = resource2
        finding2.scan.provider.provider = "azure"
        finding2.check_metadata = {
            "checktitle": "Check Title 2",
            "risk": "Medium risk",
            "remediation": {
                "recommendation": {"text": "Consider fixing", "url": ""},
                "code": {},
            },
        }

        mock_finding_model.all_objects.select_related.return_value.prefetch_related.return_value.get.side_effect = [
            finding1,
            finding2,
        ]

        # Call the function
        result = send_findings_to_jira(
            tenant_id, integration_id, project_key, issue_type, finding_ids
        )

        # Assertions
        assert result == {"created_count": 2, "failed_count": 0}

        # Verify Jira integration was initialized
        mock_initialize_integration.assert_called_once_with(integration)

        # Verify send_finding was called twice with correct parameters
        assert mock_jira_integration.send_finding.call_count == 2

        # Verify first call
        first_call = mock_jira_integration.send_finding.call_args_list[0]
        assert first_call.kwargs["check_id"] == "check_001"
        assert first_call.kwargs["check_title"] == "Check Title 1"
        assert first_call.kwargs["severity"] == "high"
        assert first_call.kwargs["status"] == "FAIL"
        assert first_call.kwargs["resource_uid"] == "resource-uid-1"
        assert first_call.kwargs["resource_name"] == "resource-name-1"
        assert first_call.kwargs["region"] == "us-east-1"
        assert first_call.kwargs["provider"] == "aws"
        assert first_call.kwargs["project_key"] == project_key
        assert first_call.kwargs["issue_type"] == issue_type

        # Verify second call
        second_call = mock_jira_integration.send_finding.call_args_list[1]
        assert second_call.kwargs["check_id"] == "check_002"
        assert second_call.kwargs["severity"] == "medium"
        assert second_call.kwargs["status"] == "PASS"

    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Finding")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.initialize_prowler_integration")
    @patch("tasks.jobs.integrations.logger")
    def test_send_findings_to_jira_partial_failure(
        self,
        mock_logger,
        mock_initialize_integration,
        mock_integration_model,
        mock_finding_model,
        mock_rls_transaction,
    ):
        """Test partial failure when sending findings to Jira"""
        tenant_id = "tenant-123"
        integration_id = "integration-456"
        project_key = "PROJ"
        issue_type = "Task"
        finding_ids = ["finding-1", "finding-2", "finding-3"]

        # Mock RLS transaction
        mock_rls_transaction.return_value.__enter__ = MagicMock()
        mock_rls_transaction.return_value.__exit__ = MagicMock()

        # Mock integration
        integration = MagicMock()
        mock_integration_model.objects.get.return_value = integration

        # Mock Jira integration with mixed results
        mock_jira_integration = MagicMock()
        mock_jira_integration.send_finding.side_effect = [
            True,
            False,
            True,
        ]  # Second fails
        mock_initialize_integration.return_value = mock_jira_integration

        # Mock findings (simplified for this test)
        findings = []
        for i in range(3):
            finding = MagicMock()
            finding.id = f"finding-{i + 1}"
            finding.check_id = f"check_{i + 1:03d}"
            finding.severity = "low"
            finding.status = "FAIL"
            finding.status_extended = ""
            finding.resource_regions = []
            finding.compliance = {}

            finding.resources.exists.return_value = False
            finding.resources.first.return_value = None
            finding.scan.provider.provider = "aws"
            finding.check_metadata = {
                "checktitle": f"Check {i + 1}",
                "risk": "Low risk",
                "remediation": {"recommendation": {}, "code": {}},
            }
            findings.append(finding)

        mock_finding_model.all_objects.select_related.return_value.prefetch_related.return_value.get.side_effect = findings

        # Call the function
        result = send_findings_to_jira(
            tenant_id, integration_id, project_key, issue_type, finding_ids
        )

        # Assertions
        assert result == {"created_count": 2, "failed_count": 1}

        # Verify error was logged for the failed finding
        mock_logger.error.assert_called_with("Failed to send finding finding-2 to Jira")

    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Finding")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.initialize_prowler_integration")
    def test_send_findings_to_jira_no_resources(
        self,
        mock_initialize_integration,
        mock_integration_model,
        mock_finding_model,
        mock_rls_transaction,
    ):
        """Test sending findings to Jira when finding has no resources"""
        tenant_id = "tenant-123"
        integration_id = "integration-456"
        project_key = "PROJ"
        issue_type = "Task"
        finding_ids = ["finding-1"]

        # Mock RLS transaction
        mock_rls_transaction.return_value.__enter__ = MagicMock()
        mock_rls_transaction.return_value.__exit__ = MagicMock()

        # Mock integration
        integration = MagicMock()
        mock_integration_model.objects.get.return_value = integration

        # Mock Jira integration
        mock_jira_integration = MagicMock()
        mock_jira_integration.send_finding.return_value = True
        mock_initialize_integration.return_value = mock_jira_integration

        # Mock finding without resources
        finding = MagicMock()
        finding.id = "finding-1"
        finding.check_id = "check_001"
        finding.severity = "critical"
        finding.status = "FAIL"
        finding.status_extended = "Critical issue found"
        finding.resource_regions = None
        finding.compliance = {"pci": ["3.1"]}

        finding.resources.exists.return_value = False
        finding.resources.first.return_value = None
        finding.scan.provider.provider = "gcp"
        finding.check_metadata = {
            "checktitle": "Critical Check",
            "risk": "Very high risk",
            "remediation": {
                "recommendation": {
                    "text": "Immediate action required",
                    "url": "https://example.com/critical",
                },
                "code": {
                    "nativeiac": "",
                    "terraform": "terraform fix",
                    "cli": "",
                    "other": "manual fix",
                },
            },
        }

        mock_finding_model.all_objects.select_related.return_value.prefetch_related.return_value.get.return_value = finding

        # Call the function
        result = send_findings_to_jira(
            tenant_id, integration_id, project_key, issue_type, finding_ids
        )

        # Assertions
        assert result == {"created_count": 1, "failed_count": 0}

        # Verify send_finding was called with empty resource fields
        call_kwargs = mock_jira_integration.send_finding.call_args.kwargs
        assert call_kwargs["resource_uid"] == ""
        assert call_kwargs["resource_name"] == ""
        assert call_kwargs["resource_tags"] == {}
        assert call_kwargs["region"] == ""

    @patch("tasks.jobs.integrations.rls_transaction")
    @patch("tasks.jobs.integrations.Finding")
    @patch("tasks.jobs.integrations.Integration")
    @patch("tasks.jobs.integrations.initialize_prowler_integration")
    def test_send_findings_to_jira_with_empty_check_metadata(
        self,
        mock_initialize_integration,
        mock_integration_model,
        mock_finding_model,
        mock_rls_transaction,
    ):
        """Test sending findings to Jira when check_metadata is empty or missing fields"""
        tenant_id = "tenant-123"
        integration_id = "integration-456"
        project_key = "PROJ"
        issue_type = "Task"
        finding_ids = ["finding-1"]

        # Mock RLS transaction
        mock_rls_transaction.return_value.__enter__ = MagicMock()
        mock_rls_transaction.return_value.__exit__ = MagicMock()

        # Mock integration
        integration = MagicMock()
        mock_integration_model.objects.get.return_value = integration

        # Mock Jira integration
        mock_jira_integration = MagicMock()
        mock_jira_integration.send_finding.return_value = True
        mock_initialize_integration.return_value = mock_jira_integration

        # Mock finding with minimal/empty check_metadata
        finding = MagicMock()
        finding.id = "finding-1"
        finding.check_id = "check_001"
        finding.severity = "low"
        finding.status = "PASS"
        finding.status_extended = None
        finding.resource_regions = []
        finding.compliance = None

        finding.resources.exists.return_value = False
        finding.resources.first.return_value = None
        finding.scan.provider.provider = "kubernetes"
        finding.check_metadata = {}  # Empty metadata

        mock_finding_model.all_objects.select_related.return_value.prefetch_related.return_value.get.return_value = finding

        # Call the function
        result = send_findings_to_jira(
            tenant_id, integration_id, project_key, issue_type, finding_ids
        )

        # Assertions
        assert result == {"created_count": 1, "failed_count": 0}

        # Verify send_finding was called with default/empty values
        call_kwargs = mock_jira_integration.send_finding.call_args.kwargs
        assert call_kwargs["check_title"] == ""
        assert call_kwargs["risk"] == ""
        assert call_kwargs["recommendation_text"] == ""
        assert call_kwargs["recommendation_url"] == ""
        assert call_kwargs["remediation_code_native_iac"] == ""
        assert call_kwargs["remediation_code_terraform"] == ""
        assert call_kwargs["remediation_code_cli"] == ""
        assert call_kwargs["remediation_code_other"] == ""
        assert call_kwargs["compliance"] == {}
