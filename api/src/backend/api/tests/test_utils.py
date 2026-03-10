from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from rest_framework.exceptions import NotFound, ValidationError

from api.db_router import MainRouter
from api.exceptions import InvitationTokenExpiredException
from api.models import Integration, Invitation, Provider
from api.utils import (
    get_prowler_provider_kwargs,
    initialize_prowler_provider,
    merge_dicts,
    prowler_integration_connection_test,
    prowler_provider_connection_test,
    return_prowler_provider,
    validate_invitation,
)
from prowler.providers.alibabacloud.alibabacloud_provider import AlibabacloudProvider
from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.aws.lib.security_hub.security_hub import SecurityHubConnection
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.cloudflare.cloudflare_provider import CloudflareProvider
from prowler.providers.gcp.gcp_provider import GcpProvider
from prowler.providers.github.github_provider import GithubProvider
from prowler.providers.iac.iac_provider import IacProvider
from prowler.providers.image.image_provider import ImageProvider
from prowler.providers.kubernetes.kubernetes_provider import KubernetesProvider
from prowler.providers.m365.m365_provider import M365Provider
from prowler.providers.mongodbatlas.mongodbatlas_provider import MongodbatlasProvider
from prowler.providers.openstack.openstack_provider import OpenstackProvider
from prowler.providers.oraclecloud.oraclecloud_provider import OraclecloudProvider


class TestMergeDicts:
    def test_simple_merge(self):
        default_dict = {"key1": "value1", "key2": "value2"}
        replacement_dict = {"key2": "new_value2", "key3": "value3"}
        expected_result = {"key1": "value1", "key2": "new_value2", "key3": "value3"}

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result

    def test_nested_merge(self):
        default_dict = {
            "key1": "value1",
            "key2": {"nested_key1": "nested_value1", "nested_key2": "nested_value2"},
        }
        replacement_dict = {
            "key2": {
                "nested_key2": "new_nested_value2",
                "nested_key3": "nested_value3",
            },
            "key3": "value3",
        }
        expected_result = {
            "key1": "value1",
            "key2": {
                "nested_key1": "nested_value1",
                "nested_key2": "new_nested_value2",
                "nested_key3": "nested_value3",
            },
            "key3": "value3",
        }

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result

    def test_no_overlap(self):
        default_dict = {"key1": "value1"}
        replacement_dict = {"key2": "value2"}
        expected_result = {"key1": "value1", "key2": "value2"}

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result

    def test_replacement_dict_empty(self):
        default_dict = {"key1": "value1", "key2": "value2"}
        replacement_dict = {}
        expected_result = {"key1": "value1", "key2": "value2"}

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result

    def test_default_dict_empty(self):
        default_dict = {}
        replacement_dict = {"key1": "value1", "key2": "value2"}
        expected_result = {"key1": "value1", "key2": "value2"}

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result

    def test_nested_empty_in_replacement_dict(self):
        default_dict = {"key1": {"nested_key1": "nested_value1"}}
        replacement_dict = {"key1": {}}
        expected_result = {"key1": {}}

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result

    def test_deep_nested_merge(self):
        default_dict = {"key1": {"nested_key1": {"deep_key1": "deep_value1"}}}
        replacement_dict = {"key1": {"nested_key1": {"deep_key1": "new_deep_value1"}}}
        expected_result = {"key1": {"nested_key1": {"deep_key1": "new_deep_value1"}}}

        result = merge_dicts(default_dict, replacement_dict)
        assert result == expected_result


class TestReturnProwlerProvider:
    @pytest.mark.parametrize(
        "provider_type, expected_provider",
        [
            (Provider.ProviderChoices.AWS.value, AwsProvider),
            (Provider.ProviderChoices.GCP.value, GcpProvider),
            (Provider.ProviderChoices.AZURE.value, AzureProvider),
            (Provider.ProviderChoices.KUBERNETES.value, KubernetesProvider),
            (Provider.ProviderChoices.M365.value, M365Provider),
            (Provider.ProviderChoices.GITHUB.value, GithubProvider),
            (Provider.ProviderChoices.MONGODBATLAS.value, MongodbatlasProvider),
            (Provider.ProviderChoices.ORACLECLOUD.value, OraclecloudProvider),
            (Provider.ProviderChoices.IAC.value, IacProvider),
            (Provider.ProviderChoices.ALIBABACLOUD.value, AlibabacloudProvider),
            (Provider.ProviderChoices.CLOUDFLARE.value, CloudflareProvider),
            (Provider.ProviderChoices.OPENSTACK.value, OpenstackProvider),
            (Provider.ProviderChoices.IMAGE.value, ImageProvider),
        ],
    )
    def test_return_prowler_provider(self, provider_type, expected_provider):
        provider = MagicMock()
        provider.provider = provider_type
        prowler_provider = return_prowler_provider(provider)
        assert prowler_provider == expected_provider

    def test_return_prowler_provider_unsupported_provider(self):
        provider = MagicMock()
        provider.provider = "UNSUPPORTED_PROVIDER"
        with pytest.raises(ValueError):
            return return_prowler_provider(provider)


class TestInitializeProwlerProvider:
    @patch("api.utils.return_prowler_provider")
    def test_initialize_prowler_provider(self, mock_return_prowler_provider):
        provider = MagicMock()
        provider.secret.secret = {"key": "value"}
        mock_return_prowler_provider.return_value = MagicMock()

        initialize_prowler_provider(provider)
        mock_return_prowler_provider.return_value.assert_called_once_with(key="value")

    @patch("api.utils.return_prowler_provider")
    def test_initialize_prowler_provider_with_mutelist(
        self, mock_return_prowler_provider
    ):
        provider = MagicMock()
        provider.secret.secret = {"key": "value"}
        mutelist_processor = MagicMock()
        mutelist_processor.configuration = {"Mutelist": {"key": "value"}}
        mock_return_prowler_provider.return_value = MagicMock()

        initialize_prowler_provider(provider, mutelist_processor)
        mock_return_prowler_provider.return_value.assert_called_once_with(
            key="value", mutelist_content={"key": "value"}
        )


class TestProwlerProviderConnectionTest:
    @patch("api.utils.return_prowler_provider")
    def test_prowler_provider_connection_test(self, mock_return_prowler_provider):
        provider = MagicMock()
        provider.uid = "1234567890"
        provider.secret.secret = {"key": "value"}
        mock_return_prowler_provider.return_value = MagicMock()

        prowler_provider_connection_test(provider)
        mock_return_prowler_provider.return_value.test_connection.assert_called_once_with(
            key="value", provider_id="1234567890", raise_on_exception=False
        )

    @pytest.mark.django_db
    @patch("api.utils.return_prowler_provider")
    def test_prowler_provider_connection_test_without_secret(
        self, mock_return_prowler_provider, providers_fixture
    ):
        mock_return_prowler_provider.return_value = MagicMock()
        connection = prowler_provider_connection_test(providers_fixture[0])

        assert connection.is_connected is False
        assert isinstance(connection.error, Provider.secret.RelatedObjectDoesNotExist)
        assert str(connection.error) == "Provider has no secret."

    @patch("api.utils.return_prowler_provider")
    def test_prowler_provider_connection_test_image_provider(
        self, mock_return_prowler_provider
    ):
        """Test connection test for Image provider with credentials."""
        provider = MagicMock()
        provider.uid = "docker.io/myns/myimage:latest"
        provider.provider = Provider.ProviderChoices.IMAGE.value
        provider.secret.secret = {
            "registry_username": "user",
            "registry_password": "pass",
            "registry_token": "tok123",
        }
        mock_return_prowler_provider.return_value = MagicMock()

        prowler_provider_connection_test(provider)
        mock_return_prowler_provider.return_value.test_connection.assert_called_once_with(
            image="docker.io/myns/myimage:latest",
            raise_on_exception=False,
            registry_username="user",
            registry_password="pass",
            registry_token="tok123",
        )

    @patch("api.utils.return_prowler_provider")
    def test_prowler_provider_connection_test_image_provider_no_creds(
        self, mock_return_prowler_provider
    ):
        """Test connection test for Image provider without credentials."""
        provider = MagicMock()
        provider.uid = "alpine:3.18"
        provider.provider = Provider.ProviderChoices.IMAGE.value
        provider.secret.secret = {}
        mock_return_prowler_provider.return_value = MagicMock()

        prowler_provider_connection_test(provider)
        mock_return_prowler_provider.return_value.test_connection.assert_called_once_with(
            image="alpine:3.18",
            raise_on_exception=False,
        )


class TestGetProwlerProviderKwargs:
    @pytest.mark.parametrize(
        "provider_type, expected_extra_kwargs",
        [
            (
                Provider.ProviderChoices.AWS.value,
                {},
            ),
            (
                Provider.ProviderChoices.AZURE.value,
                {"subscription_ids": ["provider_uid"]},
            ),
            (
                Provider.ProviderChoices.GCP.value,
                {"project_ids": ["provider_uid"]},
            ),
            (
                Provider.ProviderChoices.KUBERNETES.value,
                {"context": "provider_uid"},
            ),
            (
                Provider.ProviderChoices.M365.value,
                {},
            ),
            (
                Provider.ProviderChoices.GITHUB.value,
                {"organizations": ["provider_uid"]},
            ),
            (
                Provider.ProviderChoices.ORACLECLOUD.value,
                {},
            ),
            (
                Provider.ProviderChoices.MONGODBATLAS.value,
                {"atlas_organization_id": "provider_uid"},
            ),
            (
                Provider.ProviderChoices.CLOUDFLARE.value,
                {"filter_accounts": ["provider_uid"]},
            ),
            (
                Provider.ProviderChoices.OPENSTACK.value,
                {},
            ),
        ],
    )
    def test_get_prowler_provider_kwargs(self, provider_type, expected_extra_kwargs):
        provider_uid = "provider_uid"
        secret_dict = {"key": "value"}
        secret_mock = MagicMock()
        secret_mock.secret = secret_dict

        provider = MagicMock()
        provider.provider = provider_type
        provider.secret = secret_mock
        provider.uid = provider_uid

        result = get_prowler_provider_kwargs(provider)

        expected_result = {**secret_dict, **expected_extra_kwargs}
        assert result == expected_result

    def test_get_prowler_provider_kwargs_with_mutelist(self):
        provider_uid = "provider_uid"
        secret_dict = {"key": "value"}
        secret_mock = MagicMock()
        secret_mock.secret = secret_dict

        mutelist_processor = MagicMock()
        mutelist_processor.configuration = {"Mutelist": {"key": "value"}}

        provider = MagicMock()
        provider.provider = Provider.ProviderChoices.AWS.value
        provider.secret = secret_mock
        provider.uid = provider_uid

        result = get_prowler_provider_kwargs(provider, mutelist_processor)

        expected_result = {**secret_dict, "mutelist_content": {"key": "value"}}
        assert result == expected_result

    def test_get_prowler_provider_kwargs_iac_provider(self):
        """Test that IaC provider gets correct kwargs with repository URL."""
        provider_uid = "https://github.com/org/repo"
        secret_dict = {"access_token": "test_token"}
        secret_mock = MagicMock()
        secret_mock.secret = secret_dict

        provider = MagicMock()
        provider.provider = Provider.ProviderChoices.IAC.value
        provider.secret = secret_mock
        provider.uid = provider_uid

        result = get_prowler_provider_kwargs(provider)

        expected_result = {
            "scan_repository_url": provider_uid,
            "oauth_app_token": "test_token",
        }
        assert result == expected_result

    def test_get_prowler_provider_kwargs_iac_provider_without_token(self):
        """Test that IaC provider works without access token for public repos."""
        provider_uid = "https://github.com/org/public-repo"
        secret_dict = {}
        secret_mock = MagicMock()
        secret_mock.secret = secret_dict

        provider = MagicMock()
        provider.provider = Provider.ProviderChoices.IAC.value
        provider.secret = secret_mock
        provider.uid = provider_uid

        result = get_prowler_provider_kwargs(provider)

        expected_result = {"scan_repository_url": provider_uid}
        assert result == expected_result

    def test_get_prowler_provider_kwargs_iac_provider_ignores_mutelist(self):
        """Test that IaC provider does NOT receive mutelist_content.

        IaC provider uses Trivy's built-in mutelist logic, so it should not
        receive mutelist_content even when a mutelist processor is configured.
        """
        provider_uid = "https://github.com/org/repo"
        secret_dict = {"access_token": "test_token"}
        secret_mock = MagicMock()
        secret_mock.secret = secret_dict

        mutelist_processor = MagicMock()
        mutelist_processor.configuration = {"Mutelist": {"key": "value"}}

        provider = MagicMock()
        provider.provider = Provider.ProviderChoices.IAC.value
        provider.secret = secret_mock
        provider.uid = provider_uid

        result = get_prowler_provider_kwargs(provider, mutelist_processor)

        # IaC provider should NOT have mutelist_content
        assert "mutelist_content" not in result
        expected_result = {
            "scan_repository_url": provider_uid,
            "oauth_app_token": "test_token",
        }
        assert result == expected_result

    def test_get_prowler_provider_kwargs_image_provider_registry_url(self):
        """Test that Image provider with a registry URL gets 'registry' kwarg."""
        provider_uid = "docker.io/myns"
        secret_dict = {
            "registry_username": "user",
            "registry_password": "pass",
        }
        secret_mock = MagicMock()
        secret_mock.secret = secret_dict

        provider = MagicMock()
        provider.provider = Provider.ProviderChoices.IMAGE.value
        provider.secret = secret_mock
        provider.uid = provider_uid

        result = get_prowler_provider_kwargs(provider)

        expected_result = {
            "registry": provider_uid,
            "registry_username": "user",
            "registry_password": "pass",
        }
        assert result == expected_result

    def test_get_prowler_provider_kwargs_image_provider_image_ref(self):
        """Test that Image provider with a full image reference gets 'images' kwarg."""
        provider_uid = "docker.io/myns/myimage:latest"
        secret_dict = {
            "registry_username": "user",
            "registry_password": "pass",
        }
        secret_mock = MagicMock()
        secret_mock.secret = secret_dict

        provider = MagicMock()
        provider.provider = Provider.ProviderChoices.IMAGE.value
        provider.secret = secret_mock
        provider.uid = provider_uid

        result = get_prowler_provider_kwargs(provider)

        expected_result = {
            "images": [provider_uid],
            "registry_username": "user",
            "registry_password": "pass",
        }
        assert result == expected_result

    def test_get_prowler_provider_kwargs_image_provider_dockerhub_image(self):
        """Test that Image provider with a short DockerHub image gets 'images' kwarg."""
        provider_uid = "alpine:3.18"
        secret_dict = {}
        secret_mock = MagicMock()
        secret_mock.secret = secret_dict

        provider = MagicMock()
        provider.provider = Provider.ProviderChoices.IMAGE.value
        provider.secret = secret_mock
        provider.uid = provider_uid

        result = get_prowler_provider_kwargs(provider)

        expected_result = {"images": [provider_uid]}
        assert result == expected_result

    def test_get_prowler_provider_kwargs_image_provider_filters_falsy_secrets(self):
        """Test that falsy secret values are filtered out for Image provider."""
        provider_uid = "docker.io/myns/myimage:latest"
        secret_dict = {
            "registry_username": "",
            "registry_password": "",
        }
        secret_mock = MagicMock()
        secret_mock.secret = secret_dict

        provider = MagicMock()
        provider.provider = Provider.ProviderChoices.IMAGE.value
        provider.secret = secret_mock
        provider.uid = provider_uid

        result = get_prowler_provider_kwargs(provider)

        expected_result = {"images": [provider_uid]}
        assert result == expected_result

    def test_get_prowler_provider_kwargs_image_provider_ignores_mutelist(self):
        """Test that Image provider does NOT receive mutelist_content.

        Image provider uses Trivy's built-in mutelist logic, so it should not
        receive mutelist_content even when a mutelist processor is configured.
        """
        provider_uid = "docker.io/myns/myimage:latest"
        secret_dict = {
            "registry_username": "user",
            "registry_password": "pass",
        }
        secret_mock = MagicMock()
        secret_mock.secret = secret_dict

        mutelist_processor = MagicMock()
        mutelist_processor.configuration = {"Mutelist": {"key": "value"}}

        provider = MagicMock()
        provider.provider = Provider.ProviderChoices.IMAGE.value
        provider.secret = secret_mock
        provider.uid = provider_uid

        result = get_prowler_provider_kwargs(provider, mutelist_processor)

        assert "mutelist_content" not in result
        expected_result = {
            "images": [provider_uid],
            "registry_username": "user",
            "registry_password": "pass",
        }
        assert result == expected_result

    def test_get_prowler_provider_kwargs_unsupported_provider(self):
        # Setup
        provider_uid = "provider_uid"
        secret_dict = {"key": "value"}
        secret_mock = MagicMock()
        secret_mock.secret = secret_dict

        provider = MagicMock()
        provider.provider = "UNSUPPORTED_PROVIDER"
        provider.secret = secret_mock
        provider.uid = provider_uid

        result = get_prowler_provider_kwargs(provider)

        expected_result = secret_dict.copy()
        assert result == expected_result

    def test_get_prowler_provider_kwargs_no_secret(self):
        # Setup
        provider_uid = "provider_uid"
        secret_mock = MagicMock()
        secret_mock.secret = {}

        provider = MagicMock()
        provider.provider = Provider.ProviderChoices.AWS.value
        provider.secret = secret_mock
        provider.uid = provider_uid

        result = get_prowler_provider_kwargs(provider)

        expected_result = {}
        assert result == expected_result


class TestValidateInvitation:
    @pytest.fixture
    def invitation(self):
        invitation = MagicMock(spec=Invitation)
        invitation.token = "VALID_TOKEN"
        invitation.email = "user@example.com"
        invitation.expires_at = datetime.now(timezone.utc) + timedelta(days=1)
        invitation.state = Invitation.State.PENDING
        invitation.tenant = MagicMock()
        return invitation

    def test_valid_invitation(self, invitation):
        with patch("api.utils.Invitation.objects.using") as mock_using:
            mock_db = mock_using.return_value
            mock_db.get.return_value = invitation

            result = validate_invitation("VALID_TOKEN", "user@example.com")

            assert result == invitation
            mock_db.get.assert_called_once_with(
                token="VALID_TOKEN", email__iexact="user@example.com"
            )

    def test_invitation_not_found_raises_validation_error(self):
        with patch("api.utils.Invitation.objects.using") as mock_using:
            mock_db = mock_using.return_value
            mock_db.get.side_effect = Invitation.DoesNotExist

            with pytest.raises(ValidationError) as exc_info:
                validate_invitation("INVALID_TOKEN", "user@example.com")

            assert exc_info.value.detail == {
                "invitation_token": "Invalid invitation code."
            }
            mock_db.get.assert_called_once_with(
                token="INVALID_TOKEN", email__iexact="user@example.com"
            )

    def test_invitation_not_found_raises_not_found(self):
        with patch("api.utils.Invitation.objects.using") as mock_using:
            mock_db = mock_using.return_value
            mock_db.get.side_effect = Invitation.DoesNotExist

            with pytest.raises(NotFound) as exc_info:
                validate_invitation(
                    "INVALID_TOKEN", "user@example.com", raise_not_found=True
                )

            assert exc_info.value.detail == "Invitation is not valid."
            mock_db.get.assert_called_once_with(
                token="INVALID_TOKEN", email__iexact="user@example.com"
            )

    def test_invitation_expired(self, invitation):
        expired_time = datetime.now(timezone.utc) - timedelta(days=1)
        invitation.expires_at = expired_time

        with (
            patch("api.utils.Invitation.objects.using") as mock_using,
            patch("api.utils.datetime") as mock_datetime,
        ):
            mock_db = mock_using.return_value
            mock_db.get.return_value = invitation
            mock_datetime.now.return_value = datetime.now(timezone.utc)

            with pytest.raises(InvitationTokenExpiredException):
                validate_invitation("VALID_TOKEN", "user@example.com")

            # Ensure the invitation state was updated to EXPIRED
            assert invitation.state == Invitation.State.EXPIRED
            invitation.save.assert_called_once_with(using=MainRouter.admin_db)

    def test_invitation_not_pending(self, invitation):
        invitation.state = Invitation.State.ACCEPTED

        with patch("api.utils.Invitation.objects.using") as mock_using:
            mock_db = mock_using.return_value
            mock_db.get.return_value = invitation

            with pytest.raises(ValidationError) as exc_info:
                validate_invitation("VALID_TOKEN", "user@example.com")

            assert exc_info.value.detail == {
                "invitation_token": "This invitation is no longer valid."
            }

    def test_invitation_with_different_email(self):
        with patch("api.utils.Invitation.objects.using") as mock_using:
            mock_db = mock_using.return_value
            mock_db.get.side_effect = Invitation.DoesNotExist

            with pytest.raises(ValidationError) as exc_info:
                validate_invitation("VALID_TOKEN", "different@example.com")

            assert exc_info.value.detail == {
                "invitation_token": "Invalid invitation code."
            }
            mock_db.get.assert_called_once_with(
                token="VALID_TOKEN", email__iexact="different@example.com"
            )

    def test_valid_invitation_uppercase_email(self):
        """Test that validate_invitation works with case-insensitive email lookup."""
        uppercase_email = "USER@example.com"

        invitation = MagicMock(spec=Invitation)
        invitation.token = "VALID_TOKEN"
        invitation.email = uppercase_email
        invitation.expires_at = datetime.now(timezone.utc) + timedelta(days=1)
        invitation.state = Invitation.State.PENDING
        invitation.tenant = MagicMock()

        with patch("api.utils.Invitation.objects.using") as mock_using:
            mock_db = mock_using.return_value
            mock_db.get.return_value = invitation

            result = validate_invitation("VALID_TOKEN", "user@example.com")

            assert result == invitation
            mock_db.get.assert_called_once_with(
                token="VALID_TOKEN", email__iexact="user@example.com"
            )


class TestProwlerIntegrationConnectionTest:
    """Test prowler_integration_connection_test function for SecurityHub regions reset."""

    @patch("api.utils.SecurityHub")
    def test_security_hub_connection_failure_resets_regions(
        self, mock_security_hub_class
    ):
        """Test that SecurityHub connection failure resets regions to empty dict."""
        # Create integration with existing regions configuration
        integration = MagicMock()
        integration.integration_type = Integration.IntegrationChoices.AWS_SECURITY_HUB
        integration.credentials = {
            "aws_access_key_id": "test_key",
            "aws_secret_access_key": "test_secret",
        }
        integration.configuration = {
            "send_only_fails": True,
            "regions": {
                "us-east-1": True,
                "us-west-2": True,
                "eu-west-1": False,
                "ap-south-1": False,
            },
        }

        # Mock provider relationship
        mock_provider = MagicMock()
        mock_provider.uid = "123456789012"
        mock_relationship = MagicMock()
        mock_relationship.provider = mock_provider
        integration.integrationproviderrelationship_set.first.return_value = (
            mock_relationship
        )

        # Mock failed SecurityHub connection
        mock_connection = SecurityHubConnection(
            is_connected=False,
            error=Exception("SecurityHub testing"),
            enabled_regions=set(),
            disabled_regions=set(),
        )
        mock_security_hub_class.test_connection.return_value = mock_connection

        # Call the function
        result = prowler_integration_connection_test(integration)

        # Assertions
        assert result.is_connected is False
        assert str(result.error) == "SecurityHub testing"

        # Verify regions were completely reset to empty dict
        assert integration.configuration["regions"] == {}

        # Verify save was called to persist the change
        integration.save.assert_called_once()

        # Verify test_connection was called with correct parameters
        mock_security_hub_class.test_connection.assert_called_once_with(
            aws_account_id="123456789012",
            raise_on_exception=False,
            aws_access_key_id="test_key",
            aws_secret_access_key="test_secret",
        )

    @patch("api.utils.SecurityHub")
    def test_security_hub_connection_success_saves_regions(
        self, mock_security_hub_class
    ):
        """Test that successful SecurityHub connection saves regions correctly."""
        integration = MagicMock()
        integration.integration_type = Integration.IntegrationChoices.AWS_SECURITY_HUB
        integration.credentials = {
            "aws_access_key_id": "valid_key",
            "aws_secret_access_key": "valid_secret",
        }
        integration.configuration = {"send_only_fails": False}

        # Mock provider relationship
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
            enabled_regions={"us-east-1", "eu-west-1"},
            disabled_regions={"ap-south-1"},
        )
        mock_security_hub_class.test_connection.return_value = mock_connection

        result = prowler_integration_connection_test(integration)

        assert result.is_connected is True

        # Verify regions were saved correctly
        assert integration.configuration["regions"]["us-east-1"] is True
        assert integration.configuration["regions"]["eu-west-1"] is True
        assert integration.configuration["regions"]["ap-south-1"] is False
        integration.save.assert_called_once()

    @patch("api.utils.rls_transaction")
    @patch("api.utils.Jira")
    def test_jira_connection_success_basic_auth(
        self, mock_jira_class, mock_rls_transaction
    ):
        integration = MagicMock()
        integration.integration_type = Integration.IntegrationChoices.JIRA
        integration.tenant_id = "test-tenant-id"
        integration.credentials = {
            "user_mail": "test@example.com",
            "api_token": "test_api_token",
            "domain": "example.atlassian.net",
        }
        integration.configuration = {}

        # Mock successful JIRA connection with projects
        mock_connection = MagicMock()
        mock_connection.is_connected = True
        mock_connection.error = None
        mock_connection.projects = {"PROJ1": "Project 1", "PROJ2": "Project 2"}
        mock_jira_class.test_connection.return_value = mock_connection

        # Mock rls_transaction context manager
        mock_rls_transaction.return_value.__enter__ = MagicMock()
        mock_rls_transaction.return_value.__exit__ = MagicMock()

        result = prowler_integration_connection_test(integration)

        assert result.is_connected is True
        assert result.error is None

        # Verify JIRA connection was called with correct parameters including domain from credentials
        mock_jira_class.test_connection.assert_called_once_with(
            user_mail="test@example.com",
            api_token="test_api_token",
            domain="example.atlassian.net",
            raise_on_exception=False,
        )

        # Verify rls_transaction was called with correct tenant_id
        mock_rls_transaction.assert_called_once_with("test-tenant-id")

        # Verify projects were saved to integration configuration
        assert integration.configuration["projects"] == {
            "PROJ1": "Project 1",
            "PROJ2": "Project 2",
        }

        # Verify integration.save() was called
        integration.save.assert_called_once()

    @patch("api.utils.rls_transaction")
    @patch("api.utils.Jira")
    def test_jira_connection_failure_invalid_credentials(
        self, mock_jira_class, mock_rls_transaction
    ):
        integration = MagicMock()
        integration.integration_type = Integration.IntegrationChoices.JIRA
        integration.tenant_id = "test-tenant-id"
        integration.credentials = {
            "user_mail": "invalid@example.com",
            "api_token": "invalid_token",
            "domain": "invalid.atlassian.net",
        }
        integration.configuration = {}

        # Mock failed JIRA connection
        mock_connection = MagicMock()
        mock_connection.is_connected = False
        mock_connection.error = Exception("Authentication failed: Invalid credentials")
        mock_connection.projects = {}  # Empty projects when connection fails
        mock_jira_class.test_connection.return_value = mock_connection

        # Mock rls_transaction context manager
        mock_rls_transaction.return_value.__enter__ = MagicMock()
        mock_rls_transaction.return_value.__exit__ = MagicMock()

        result = prowler_integration_connection_test(integration)

        assert result.is_connected is False
        assert "Authentication failed: Invalid credentials" in str(result.error)

        # Verify JIRA connection was called with correct parameters
        mock_jira_class.test_connection.assert_called_once_with(
            user_mail="invalid@example.com",
            api_token="invalid_token",
            domain="invalid.atlassian.net",
            raise_on_exception=False,
        )

        # Verify rls_transaction was called even on failure
        mock_rls_transaction.assert_called_once_with("test-tenant-id")

        # Verify empty projects dict was saved to integration configuration
        assert integration.configuration["projects"] == {}

        # Verify integration.save() was called even on connection failure
        integration.save.assert_called_once()

    @patch("api.utils.rls_transaction")
    @patch("api.utils.Jira")
    def test_jira_connection_projects_update_with_existing_configuration(
        self, mock_jira_class, mock_rls_transaction
    ):
        """Test that projects are properly updated when integration already has configuration data"""
        integration = MagicMock()
        integration.integration_type = Integration.IntegrationChoices.JIRA
        integration.tenant_id = "test-tenant-id"
        integration.credentials = {
            "user_mail": "test@example.com",
            "api_token": "test_api_token",
            "domain": "example.atlassian.net",
        }
        integration.configuration = {
            "issue_types": ["Task"],  # Existing configuration
            "projects": {"OLD_PROJ": "Old Project"},  # Will be overwritten
        }

        # Mock successful JIRA connection with new projects
        mock_connection = MagicMock()
        mock_connection.is_connected = True
        mock_connection.error = None
        mock_connection.projects = {
            "NEW_PROJ1": "New Project 1",
            "NEW_PROJ2": "New Project 2",
        }
        mock_jira_class.test_connection.return_value = mock_connection

        # Mock rls_transaction context manager
        mock_rls_transaction.return_value.__enter__ = MagicMock()
        mock_rls_transaction.return_value.__exit__ = MagicMock()

        result = prowler_integration_connection_test(integration)

        assert result.is_connected is True
        assert result.error is None

        # Verify projects were updated (old projects replaced with new ones)
        assert integration.configuration["projects"] == {
            "NEW_PROJ1": "New Project 1",
            "NEW_PROJ2": "New Project 2",
        }

        # Verify other configuration fields were preserved
        assert integration.configuration["issue_types"] == ["Task"]

        # Verify integration.save() was called
        integration.save.assert_called_once()
