from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock, patch
from uuid import uuid4

import pytest
from api.db_router import READ_REPLICA_ALIAS, MainRouter
from api.db_utils import rls_transaction
from api.models import Integration, JiraIssue
from api.utils import prowler_integration_connection_test
from django.db import OperationalError, connection
from django.test import override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from prowler.lib.outputs.jira.jira import Jira
from prowler.lib.outputs.jira.models import (
    JiraCreationOutcome,
    JiraCreationResult,
    JiraIssueLookupOutcome,
    JiraIssueSearchMatch,
    JiraIssueSearchOutcome,
    JiraIssueSearchResult,
    JiraIssueStatusResult,
)
from prowler.providers.aws.lib.security_hub.security_hub import SecurityHubConnection
from prowler.providers.common.models import Connection
from tasks.jobs.integrations import (
    JIRA_CLAIM_LEASE,
    _claim_existing_attempt,
    _finish_owned_failure,
    _load_jira_delivery_page,
    build_jira_finding_url,
    build_jira_issue_labels,
    get_s3_client_from_integration,
    get_security_hub_client_from_integration,
    get_tenant_name,
    reconcile_due_jira_issues,
    send_findings_to_jira,
    upload_s3_integration,
    upload_security_hub_integration,
)
from tasks.tasks import jira_integration_task, jira_issue_reconciliation_task


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
        from api.models import Integration
        from api.v1.serializers import BaseWriteIntegrationSerializer
        from rest_framework.exceptions import ValidationError

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
        from api.models import Integration
        from api.v1.serializers import BaseWriteIntegrationSerializer
        from rest_framework.exceptions import ValidationError

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
        mock_integration.connected = False
        mock_integration.connection_last_checked_at = None

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

            checked_at_before = datetime.now(tz=UTC)
            connected, security_hub = get_security_hub_client_from_integration(
                mock_integration, tenant_id, mock_findings
            )
            checked_at_after = datetime.now(tz=UTC)

        assert connected is True
        assert security_hub == mock_security_hub
        assert mock_integration.connected is True
        assert mock_integration.connection_last_checked_at.tzinfo is UTC
        assert (
            checked_at_before
            <= mock_integration.connection_last_checked_at
            <= checked_at_after
        )
        mock_integration.save.assert_called_once()

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


class TestJiraFindingReference:
    """Helpers that give Jira issues a stable reference back to the finding."""

    def test_build_jira_issue_labels(self):
        assert build_jira_issue_labels(
            finding_uid="prowler-aws-check-123-eu-west-1-hub/unknown",
            provider="aws",
            severity="critical",
            check_id="iam_root_mfa",
        ) == [
            "prowler",
            "prowler-aws",
            "prowler-critical",
            "prowler-iam_root_mfa",
            "prowler-finding-prowler-aws-check-123-eu-west-1-hub/unknown",
        ]

    def test_build_jira_issue_labels_skips_empty_parts(self):
        assert build_jira_issue_labels(
            finding_uid="", provider="", severity="", check_id=""
        ) == ["prowler"]

    def test_build_jira_issue_labels_sanitizes_metadata(self):
        assert build_jira_issue_labels(
            finding_uid=" uid\x00 with spaces ",
            provider="aws cloud",
            severity="high severity",
            check_id="check id",
        ) == [
            "prowler",
            "prowler-aws_cloud",
            "prowler-high_severity",
            "prowler-check_id",
            "prowler-finding-uid_with_spaces",
        ]

    def test_build_jira_issue_labels_preserves_maximum_length_uid(self):
        finding_uid = "u" * (Jira.LABEL_MAX_LENGTH - len(Jira.FINDING_LABEL_PREFIX) - 1)
        finding_label = build_jira_issue_labels(
            finding_uid=finding_uid,
            provider="gcp",
            severity="low",
            check_id="check",
        )[-1]

        assert finding_label == f"{Jira.FINDING_LABEL_PREFIX}-{finding_uid}"
        assert len(finding_label) == Jira.LABEL_MAX_LENGTH

    def test_build_jira_issue_labels_distinguishes_long_uids(self):
        common_prefix = "u" * 300
        first_uid = f"{common_prefix}-first"
        second_uid = f"{common_prefix}-second"

        first_label = build_jira_issue_labels(
            finding_uid=first_uid,
            provider="gcp",
            severity="low",
            check_id="check",
        )[-1]
        second_label = build_jira_issue_labels(
            finding_uid=second_uid,
            provider="gcp",
            severity="low",
            check_id="check",
        )[-1]

        assert first_label == Jira.build_finding_label(first_uid)
        assert second_label == Jira.build_finding_label(second_uid)
        assert first_label != second_label
        assert len(first_label) == Jira.LABEL_MAX_LENGTH
        assert len(second_label) == Jira.LABEL_MAX_LENGTH

    @override_settings(UI_BASE_URL="")
    def test_build_jira_finding_url_without_base_url(self):
        assert build_jira_finding_url("prowler-aws-check-1") == ""

    @override_settings(UI_BASE_URL="https://cloud.example.com")
    def test_build_jira_finding_url_with_base_url(self):
        assert build_jira_finding_url("prowler-aws-check-1") == (
            "https://cloud.example.com/findings?filter[uid]=prowler-aws-check-1"
        )
        # uid characters that would break the query string are encoded
        assert build_jira_finding_url("a/b c&d") == (
            "https://cloud.example.com/findings?filter[uid]=a%2Fb%20c%26d"
        )
        assert build_jira_finding_url("") == ""

    @pytest.mark.django_db
    def test_get_tenant_name(self, tenants_fixture):
        tenant = tenants_fixture[0]
        assert get_tenant_name(str(tenant.id)) == tenant.name

    @pytest.mark.django_db
    def test_get_tenant_name_unknown_or_invalid(self):
        assert get_tenant_name("00000000-0000-0000-0000-000000000000") == ""
        assert get_tenant_name("not-a-uuid") == ""


@pytest.mark.django_db
class TestSafeJiraDelivery:
    @pytest.fixture
    def jira_mock(self):
        jira = MagicMock(spec=Jira)
        issue_number = 0

        def create_issue(**kwargs):
            nonlocal issue_number
            issue_number += 1
            return JiraCreationResult(
                outcome=JiraCreationOutcome.CONFIRMED_SUCCESS,
                issue_id=str(10000 + issue_number),
                issue_key=f"TEST-{issue_number}",
                issue_url=(f"https://test.atlassian.net/browse/TEST-{issue_number}"),
                delivery_marker=kwargs["delivery_attempt_marker"],
            )

        jira.send_finding.side_effect = create_issue
        jira.search_issues_by_delivery_attempt.return_value = JiraIssueSearchResult(
            outcome=JiraIssueSearchOutcome.SUCCESS
        )
        return jira

    @staticmethod
    def _send(
        integration,
        jira,
        finding_ids,
        *,
        task_id="jira-task-1",
        force_replace=False,
        actor_id=None,
    ):
        with patch(
            "tasks.jobs.integrations.initialize_prowler_integration",
            return_value=jira,
        ):
            return send_findings_to_jira(
                str(integration.tenant_id),
                str(integration.id),
                "TEST",
                "Task",
                [str(finding_id) for finding_id in finding_ids],
                task_id=task_id,
                force_replace=force_replace,
                actor_id=actor_id,
            )

    @staticmethod
    def _row(integration, finding):
        with rls_transaction(str(integration.tenant_id)):
            return JiraIssue.objects.get(
                integration=integration,
                provider_id=finding.scan.provider_id,
                finding_uid=finding.uid,
            )

    @staticmethod
    def _status_results(outcome, *, moved_key=None):
        def build(references):
            results = []
            for reference in references:
                if outcome in {
                    JiraIssueLookupOutcome.MISSING,
                    JiraIssueLookupOutcome.FORBIDDEN,
                    JiraIssueLookupOutcome.UNKNOWN,
                }:
                    results.append(
                        JiraIssueStatusResult(
                            reference=reference,
                            outcome=outcome,
                            error_code=f"jira_{outcome.value}",
                            error_message="Jira could not confirm the linked issue.",
                        )
                    )
                    continue
                issue_key = moved_key or reference.issue_key
                results.append(
                    JiraIssueStatusResult(
                        reference=reference,
                        outcome=outcome,
                        current_issue_id=reference.issue_id,
                        current_issue_key=issue_key,
                        current_issue_url=(
                            f"https://test.atlassian.net/browse/{issue_key}"
                        ),
                        status=(
                            "Done"
                            if outcome == JiraIssueLookupOutcome.DONE
                            else "In Progress"
                        ),
                        status_category=(
                            "done"
                            if outcome == JiraIssueLookupOutcome.DONE
                            else "indeterminate"
                        ),
                    )
                )
            return results

        return build

    def test_first_send_links_typed_result_and_returns_json_safe_summary(
        self, jira_mock, jira_integration_fixture, findings_fixture
    ):
        finding1, finding2 = findings_fixture

        result = self._send(
            jira_integration_fixture, jira_mock, [finding1.id, finding2.id]
        )

        assert result["created_count"] == 2
        assert result["skipped_count"] == 0
        assert result["deferred_count"] == 0
        assert result["uncertain_count"] == 0
        assert result["failed_count"] == 0
        assert result["truncated"] is False
        assert [entry["outcome"] for entry in result["results"]] == [
            "created",
            "created",
        ]
        row = self._row(jira_integration_fixture, finding1)
        assert row.issue_id == "10001"
        assert row.issue_key == "TEST-1"
        assert row.attempt_state == JiraIssue.AttemptStateChoices.IDLE
        assert row.claim_token is None
        assert row.attempt_count == 1
        assert jira_mock.send_finding.call_args_list[0].kwargs[
            "delivery_attempt_marker"
        ] == str(row.delivery_attempt_token)

    def test_open_issue_is_refreshed_and_skipped(
        self, jira_mock, jira_integration_fixture, findings_fixture
    ):
        finding, _ = findings_fixture
        self._send(jira_integration_fixture, jira_mock, [finding.id])
        jira_mock.send_finding.reset_mock()
        jira_mock.get_issues_status.side_effect = self._status_results(
            JiraIssueLookupOutcome.OPEN
        )

        result = self._send(
            jira_integration_fixture, jira_mock, [finding.id], task_id="jira-task-2"
        )

        assert result["skipped_count"] == 1
        jira_mock.send_finding.assert_not_called()
        row = self._row(jira_integration_fixture, finding)
        assert row.issue_status == "In Progress"
        assert row.issue_status_category == "indeterminate"
        assert row.status_synced_at is not None

    def test_moved_issue_updates_key_by_immutable_id_and_skips(
        self, jira_mock, jira_integration_fixture, findings_fixture
    ):
        finding, _ = findings_fixture
        self._send(jira_integration_fixture, jira_mock, [finding.id])
        jira_mock.send_finding.reset_mock()
        jira_mock.get_issues_status.side_effect = self._status_results(
            JiraIssueLookupOutcome.MOVED, moved_key="MOVED-7"
        )

        result = self._send(
            jira_integration_fixture, jira_mock, [finding.id], task_id="jira-task-2"
        )

        assert result["skipped_count"] == 1
        row = self._row(jira_integration_fixture, finding)
        assert row.issue_id == "10001"
        assert row.issue_key == "MOVED-7"
        assert row.issue_url.endswith("/MOVED-7")
        jira_mock.send_finding.assert_not_called()

    @pytest.mark.parametrize(
        ("creation_result", "outcome", "attempt_state"),
        [
            (
                JiraCreationResult(
                    outcome=JiraCreationOutcome.CONFIRMED_REJECTION,
                    error_code="invalid_project",
                    error_message="The Jira project key is invalid.",
                ),
                "failed",
                JiraIssue.AttemptStateChoices.TERMINAL_FAILURE,
            ),
            (
                JiraCreationResult(
                    outcome=JiraCreationOutcome.RETRYABLE_FAILURE,
                    error_code="rate_limited",
                    error_message="Jira rejected the request temporarily.",
                ),
                "failed",
                JiraIssue.AttemptStateChoices.RETRYABLE_FAILURE,
            ),
            (
                JiraCreationResult(
                    outcome=JiraCreationOutcome.UNCERTAIN,
                    error_code="ambiguous_transport_failure",
                    error_message="Jira did not confirm whether it created the issue.",
                ),
                "uncertain",
                JiraIssue.AttemptStateChoices.UNCERTAIN,
            ),
        ],
    )
    def test_creation_outcomes_are_mapped_explicitly(
        self,
        jira_mock,
        jira_integration_fixture,
        findings_fixture,
        creation_result,
        outcome,
        attempt_state,
    ):
        finding, _ = findings_fixture
        jira_mock.send_finding.side_effect = None
        jira_mock.send_finding.return_value = creation_result

        result = self._send(jira_integration_fixture, jira_mock, [finding.id])

        assert result["results"][0]["outcome"] == outcome
        row = self._row(jira_integration_fixture, finding)
        assert row.attempt_state == attempt_state
        assert row.issue_id is None
        assert row.claim_token is None
        if attempt_state == JiraIssue.AttemptStateChoices.UNCERTAIN:
            assert row.next_reconcile_at is not None

    def test_unexpected_send_exception_is_uncertain_and_does_not_leak_details(
        self, jira_mock, jira_integration_fixture, findings_fixture
    ):
        finding, _ = findings_fixture
        jira_mock.send_finding.side_effect = Exception("token=private-value")

        result = self._send(jira_integration_fixture, jira_mock, [finding.id])

        entry = result["results"][0]
        assert entry["outcome"] == "uncertain"
        assert entry["error_code"] == "unexpected_send_exception"
        assert "private-value" not in entry["error_message"]
        assert self._row(jira_integration_fixture, finding).issue_id is None

    def test_uncertain_result_honors_longer_retry_after(
        self, jira_mock, jira_integration_fixture, findings_fixture
    ):
        finding, _ = findings_fixture
        jira_mock.send_finding.side_effect = None
        jira_mock.send_finding.return_value = JiraCreationResult(
            outcome=JiraCreationOutcome.UNCERTAIN,
            retry_after="1200",
            error_code="rate_limited_after_send",
            error_message="Jira did not confirm whether it created the issue.",
        )
        before = timezone.now()

        self._send(jira_integration_fixture, jira_mock, [finding.id])

        row = self._row(jira_integration_fixture, finding)
        assert row.next_reconcile_at >= before + timedelta(seconds=1200)

    def test_done_replacement_keeps_old_link_when_creation_is_uncertain(
        self, jira_mock, jira_integration_fixture, findings_fixture
    ):
        finding, _ = findings_fixture
        self._send(jira_integration_fixture, jira_mock, [finding.id])
        original = self._row(jira_integration_fixture, finding)
        original_marker = original.delivery_attempt_token
        jira_mock.get_issues_status.side_effect = self._status_results(
            JiraIssueLookupOutcome.DONE
        )
        jira_mock.send_finding.side_effect = None
        jira_mock.send_finding.return_value = JiraCreationResult(
            outcome=JiraCreationOutcome.UNCERTAIN,
            error_code="ambiguous_transport_failure",
            error_message="Jira did not confirm whether it created the issue.",
        )

        result = self._send(
            jira_integration_fixture, jira_mock, [finding.id], task_id="jira-task-2"
        )

        assert result["uncertain_count"] == 1
        row = self._row(jira_integration_fixture, finding)
        assert row.issue_id == original.issue_id
        assert row.issue_key == original.issue_key
        assert row.issue_url == original.issue_url
        assert row.attempt_operation == JiraIssue.AttemptOperationChoices.REPLACEMENT
        assert row.delivery_attempt_token != original_marker

    @pytest.mark.parametrize(
        "lookup_outcome",
        [
            JiraIssueLookupOutcome.MISSING,
            JiraIssueLookupOutcome.FORBIDDEN,
            JiraIssueLookupOutcome.UNKNOWN,
        ],
    )
    def test_unconfirmed_issue_requires_force_replace(
        self,
        jira_mock,
        jira_integration_fixture,
        findings_fixture,
        lookup_outcome,
    ):
        finding, _ = findings_fixture
        self._send(jira_integration_fixture, jira_mock, [finding.id])
        original = self._row(jira_integration_fixture, finding)
        original_marker = original.delivery_attempt_token
        jira_mock.get_issues_status.side_effect = self._status_results(lookup_outcome)
        jira_mock.send_finding.reset_mock()

        skipped = self._send(
            jira_integration_fixture, jira_mock, [finding.id], task_id="jira-task-2"
        )
        assert skipped["skipped_count"] == 1
        jira_mock.send_finding.assert_not_called()

        with patch("tasks.jobs.integrations.logger.warning") as warning:
            forced = self._send(
                jira_integration_fixture,
                jira_mock,
                [finding.id],
                task_id="jira-task-3",
                force_replace=True,
                actor_id="operator-1",
            )
        assert forced["created_count"] == 1
        row = self._row(jira_integration_fixture, finding)
        assert row.issue_key == "TEST-2"
        assert row.delivery_attempt_token != original_marker
        warning.assert_called_once()
        _, log_kwargs = warning.call_args
        assert log_kwargs["extra"]["user_id"] == "operator-1"
        assert log_kwargs["extra"]["tenant_id"] == str(
            jira_integration_fixture.tenant_id
        )
        assert log_kwargs["extra"]["metadata"] == {
            "integration_id": str(jira_integration_fixture.id),
            "provider_id": str(finding.scan.provider_id),
            "finding_uid": finding.uid,
            "old_issue_id": original.issue_id,
            "old_issue_key": original.issue_key,
            "old_issue_url": original.issue_url,
        }

    def test_retryable_failure_reuses_delivery_marker(
        self, jira_mock, jira_integration_fixture, findings_fixture
    ):
        finding, _ = findings_fixture
        jira_mock.send_finding.side_effect = None
        jira_mock.send_finding.return_value = JiraCreationResult(
            outcome=JiraCreationOutcome.RETRYABLE_FAILURE,
            error_code="rate_limited",
            error_message="Jira rejected the request temporarily.",
        )
        self._send(jira_integration_fixture, jira_mock, [finding.id])
        marker = self._row(jira_integration_fixture, finding).delivery_attempt_token
        jira_mock.send_finding.return_value = JiraCreationResult(
            outcome=JiraCreationOutcome.CONFIRMED_SUCCESS,
            issue_id="20001",
            issue_key="TEST-RETRY",
            issue_url="https://test.atlassian.net/browse/TEST-RETRY",
        )

        result = self._send(
            jira_integration_fixture, jira_mock, [finding.id], task_id="jira-task-2"
        )

        assert result["created_count"] == 1
        assert jira_mock.send_finding.call_args.kwargs[
            "delivery_attempt_marker"
        ] == str(marker)
        assert (
            self._row(jira_integration_fixture, finding).delivery_attempt_token
            == marker
        )

    def test_fresh_foreign_claim_defers_and_stale_claim_reconciles(
        self, jira_mock, jira_integration_fixture, findings_fixture
    ):
        finding, _ = findings_fixture
        tenant_id = str(jira_integration_fixture.tenant_id)
        with rls_transaction(tenant_id):
            row = JiraIssue.objects.create(
                tenant_id=tenant_id,
                integration=jira_integration_fixture,
                provider_id=finding.scan.provider_id,
                finding_uid=finding.uid,
                finding_id=finding.id,
                attempt_state=JiraIssue.AttemptStateChoices.CREATING,
                claim_token="other-task",
                claim_expires_at=timezone.now() + JIRA_CLAIM_LEASE,
                delivery_attempt_token=uuid4(),
                attempt_operation=JiraIssue.AttemptOperationChoices.INITIAL,
                attempt_project_key="TEST",
                attempt_issue_type="Task",
                attempt_count=1,
                last_attempt_at=timezone.now(),
            )

        deferred = self._send(
            jira_integration_fixture, jira_mock, [finding.id], task_id="new-task"
        )
        assert deferred["deferred_count"] == 1
        jira_mock.send_finding.assert_not_called()
        jira_mock.search_issues_by_delivery_attempt.assert_not_called()

        with rls_transaction(tenant_id):
            JiraIssue.objects.filter(id=row.id).update(
                claim_expires_at=timezone.now() - timedelta(seconds=1)
            )
        jira_mock.search_issues_by_delivery_attempt.return_value = (
            JiraIssueSearchResult(
                outcome=JiraIssueSearchOutcome.SUCCESS,
                matches=(
                    JiraIssueSearchMatch(
                        issue_id="30001",
                        issue_key="TEST-RECOVERED",
                        issue_url=("https://test.atlassian.net/browse/TEST-RECOVERED"),
                    ),
                ),
            )
        )

        recovered = self._send(
            jira_integration_fixture, jira_mock, [finding.id], task_id="new-task"
        )
        assert recovered["created_count"] == 1
        jira_mock.send_finding.assert_not_called()
        assert self._row(jira_integration_fixture, finding).issue_key == (
            "TEST-RECOVERED"
        )

    @pytest.mark.parametrize("match_count", [0, 2])
    def test_uncertain_attempt_reconciles_without_another_post(
        self,
        jira_mock,
        jira_integration_fixture,
        findings_fixture,
        match_count,
    ):
        finding, _ = findings_fixture
        jira_mock.send_finding.side_effect = None
        jira_mock.send_finding.return_value = JiraCreationResult(
            outcome=JiraCreationOutcome.UNCERTAIN,
            error_code="ambiguous_transport_failure",
            error_message="Jira did not confirm whether it created the issue.",
        )
        self._send(jira_integration_fixture, jira_mock, [finding.id])
        marker = self._row(jira_integration_fixture, finding).delivery_attempt_token
        jira_mock.send_finding.reset_mock()
        jira_mock.search_issues_by_delivery_attempt.return_value = (
            JiraIssueSearchResult(
                outcome=JiraIssueSearchOutcome.SUCCESS,
                matches=tuple(
                    JiraIssueSearchMatch(
                        issue_id=str(40000 + index),
                        issue_key=f"TEST-{index}",
                        issue_url=f"https://test.atlassian.net/browse/TEST-{index}",
                    )
                    for index in range(match_count)
                ),
            )
        )

        result = self._send(
            jira_integration_fixture, jira_mock, [finding.id], task_id="jira-task-2"
        )

        assert result["uncertain_count"] == 1
        jira_mock.send_finding.assert_not_called()
        jira_mock.search_issues_by_delivery_attempt.assert_called_once_with(str(marker))
        row = self._row(jira_integration_fixture, finding)
        assert row.delivery_attempt_token == marker
        assert (row.next_reconcile_at is None) is (match_count == 2)

    @pytest.mark.parametrize(
        "lookup_outcome",
        [
            JiraIssueSearchOutcome.RETRYABLE_FAILURE,
            JiraIssueSearchOutcome.UNKNOWN,
        ],
    )
    def test_failed_marker_lookup_remains_uncertain(
        self,
        jira_mock,
        jira_integration_fixture,
        findings_fixture,
        lookup_outcome,
    ):
        finding, _ = findings_fixture
        jira_mock.send_finding.side_effect = None
        jira_mock.send_finding.return_value = JiraCreationResult(
            outcome=JiraCreationOutcome.UNCERTAIN,
            error_code="ambiguous_transport_failure",
            error_message="Jira did not confirm whether it created the issue.",
        )
        self._send(jira_integration_fixture, jira_mock, [finding.id])
        jira_mock.send_finding.reset_mock()
        jira_mock.search_issues_by_delivery_attempt.return_value = (
            JiraIssueSearchResult(
                outcome=lookup_outcome,
                retry_after="120",
                error_code="marker_lookup_failed",
                error_message="Jira marker lookup failed.",
            )
        )

        result = self._send(
            jira_integration_fixture, jira_mock, [finding.id], task_id="jira-task-2"
        )

        assert result["uncertain_count"] == 1
        jira_mock.send_finding.assert_not_called()
        row = self._row(jira_integration_fixture, finding)
        assert row.attempt_state == JiraIssue.AttemptStateChoices.UNCERTAIN
        assert row.next_reconcile_at is not None

    def test_stale_worker_cannot_finish_a_newer_claim(
        self, jira_integration_fixture, findings_fixture
    ):
        finding, _ = findings_fixture
        tenant_id = str(jira_integration_fixture.tenant_id)
        with rls_transaction(tenant_id):
            row = JiraIssue.objects.create(
                tenant_id=tenant_id,
                integration=jira_integration_fixture,
                provider_id=finding.scan.provider_id,
                finding_uid=finding.uid,
                finding_id=finding.id,
                attempt_state=JiraIssue.AttemptStateChoices.CREATING,
                claim_token="stale-worker",
                claim_expires_at=timezone.now() - timedelta(seconds=1),
                delivery_attempt_token=uuid4(),
                attempt_operation=JiraIssue.AttemptOperationChoices.INITIAL,
                attempt_project_key="TEST",
                attempt_issue_type="Task",
                attempt_count=1,
                last_attempt_at=timezone.now(),
            )
        claimed = _claim_existing_attempt(
            tenant_id,
            row,
            str(finding.id),
            "new-worker",
            reconcile=True,
        )
        assert claimed is not None

        assert not _finish_owned_failure(
            tenant_id,
            row,
            "stale-worker",
            attempt_state=JiraIssue.AttemptStateChoices.RETRYABLE_FAILURE,
            error_code="stale",
            error_message="stale",
        )
        current = self._row(jira_integration_fixture, finding)
        assert current.attempt_state == JiraIssue.AttemptStateChoices.CREATING
        assert current.claim_token == "new-worker"

    def test_due_reconciliation_job_links_one_marker_match(
        self, jira_mock, jira_integration_fixture, findings_fixture
    ):
        finding, _ = findings_fixture
        jira_mock.send_finding.side_effect = None
        jira_mock.send_finding.return_value = JiraCreationResult(
            outcome=JiraCreationOutcome.UNCERTAIN,
            error_code="ambiguous_transport_failure",
            error_message="Jira did not confirm whether it created the issue.",
        )
        self._send(jira_integration_fixture, jira_mock, [finding.id])
        row = self._row(jira_integration_fixture, finding)
        with rls_transaction(str(jira_integration_fixture.tenant_id)):
            JiraIssue.objects.filter(id=row.id).update(
                next_reconcile_at=timezone.now() - timedelta(seconds=1)
            )
        jira_mock.search_issues_by_delivery_attempt.return_value = (
            JiraIssueSearchResult(
                outcome=JiraIssueSearchOutcome.SUCCESS,
                matches=(
                    JiraIssueSearchMatch(
                        issue_id="50001",
                        issue_key="TEST-DUE",
                        issue_url="https://test.atlassian.net/browse/TEST-DUE",
                    ),
                ),
            )
        )
        jira_mock.send_finding.reset_mock()

        with patch(
            "tasks.jobs.integrations.initialize_prowler_integration",
            return_value=jira_mock,
        ):
            result = reconcile_due_jira_issues(
                str(jira_integration_fixture.tenant_id),
                str(jira_integration_fixture.id),
                task_id="reconcile-task",
            )

        assert result["created_count"] == 1
        jira_mock.send_finding.assert_not_called()
        assert self._row(jira_integration_fixture, finding).issue_key == "TEST-DUE"

    def test_result_details_are_capped_but_counts_remain_exact(
        self, jira_mock, jira_integration_fixture
    ):
        missing_ids = [str(uuid4()) for _ in range(101)]

        result = self._send(jira_integration_fixture, jira_mock, missing_ids)

        assert result["failed_count"] == 101
        assert len(result["results"]) == 100
        assert result["truncated"] is True
        jira_mock.send_finding.assert_not_called()

    def test_page_hydration_query_count_is_bounded(
        self, jira_integration_fixture, findings_fixture
    ):
        finding1, finding2 = findings_fixture
        tenant_id = str(jira_integration_fixture.tenant_id)
        integration_id = str(jira_integration_fixture.id)
        with CaptureQueriesContext(connection) as one_finding_queries:
            _load_jira_delivery_page(tenant_id, integration_id, [str(finding1.id)])
        with CaptureQueriesContext(connection) as two_finding_queries:
            _load_jira_delivery_page(
                tenant_id,
                integration_id,
                [str(finding1.id), str(finding2.id)],
            )

        assert len(two_finding_queries) == len(one_finding_queries)

    def test_delivery_uses_prefetched_tags(
        self, jira_mock, jira_integration_fixture, findings_fixture
    ):
        finding, _ = findings_fixture
        with patch("api.models.Resource.get_tags") as get_tags:
            result = self._send(jira_integration_fixture, jira_mock, [finding.id])

        assert result["created_count"] == 1
        get_tags.assert_not_called()

    def test_jira_tasks_use_late_acknowledgement(self):
        assert jira_integration_task.acks_late is True
        assert jira_integration_task.reject_on_worker_lost is True
        assert jira_issue_reconciliation_task.acks_late is True
        assert jira_issue_reconciliation_task.reject_on_worker_lost is True
