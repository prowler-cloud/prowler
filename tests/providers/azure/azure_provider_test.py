import asyncio
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from azure.core.credentials import AccessToken
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.identity import DefaultAzureCredential
from mock import MagicMock

from prowler.config.config import (
    default_config_file_path,
    default_fixer_config_file_path,
    load_and_validate_config_file,
)
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.exceptions.exceptions import (
    AzureBrowserAuthNoTenantIDError,
    AzureConfigCredentialsError,
    AzureEnvironmentVariableError,
    AzureHTTPResponseError,
    AzureInvalidProviderIdError,
    AzureNoAuthenticationMethodError,
    AzureNotValidCertificateContentError,
    AzureNotValidCertificatePathError,
    AzureNotValidClientIdError,
    AzureNotValidClientSecretError,
    AzureNotValidTenantIdError,
    AzureSetUpSessionError,
    AzureTenantIDNoBrowserAuthError,
)
from prowler.providers.azure.models import AzureIdentityInfo, AzureRegionConfig
from prowler.providers.common.models import Connection


class TestAzureProvider:
    def test_azure_provider(self):
        subscription_id = None
        tenant_id = None
        # We need to set exactly one auth method
        az_cli_auth = True
        sp_env_auth = None
        browser_auth = None
        managed_identity_auth = None
        client_id = None
        client_secret = None

        fixer_config = load_and_validate_config_file(
            "azure", default_fixer_config_file_path
        )
        azure_region = "AzureCloud"

        with (
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.setup_identity",
                return_value=AzureIdentityInfo(),
            ),
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
                return_value={},
            ),
        ):
            azure_provider = AzureProvider(
                az_cli_auth,
                sp_env_auth,
                browser_auth,
                managed_identity_auth,
                tenant_id,
                azure_region,
                subscription_id,
                config_path=default_config_file_path,
                fixer_config=fixer_config,
                client_id=client_id,
                client_secret=client_secret,
            )

            assert azure_provider.region_config == AzureRegionConfig(
                name="AzureCloud",
                authority=None,
                base_url="https://management.azure.com",
                credential_scopes=["https://management.azure.com/.default"],
            )
            assert isinstance(azure_provider.session, DefaultAzureCredential)
            assert azure_provider.identity == AzureIdentityInfo(
                identity_id="",
                identity_type="",
                tenant_ids=[],
                tenant_domain="Unknown tenant domain (missing AAD permissions)",
                subscriptions={},
                locations={},
            )
            assert azure_provider.audit_config == {
                "shodan_api_key": None,
                "php_latest_version": "8.2",
                "python_latest_version": "3.12",
                "java_latest_version": "17",
                "recommended_minimal_tls_versions": ["1.2", "1.3"],
                "recommended_smb_channel_encryption_algorithms": ["AES-256-GCM"],
                "vm_backup_min_daily_retention_days": 7,
                "desired_vm_sku_sizes": [
                    "Standard_A8_v2",
                    "Standard_DS3_v2",
                    "Standard_D4s_v3",
                ],
                "defender_attack_path_minimal_risk_level": "High",
                "apim_threat_detection_llm_jacking_threshold": 0.1,
                "apim_threat_detection_llm_jacking_minutes": 1440,
                "apim_threat_detection_llm_jacking_actions": [
                    "ImageGenerations_Create",
                    "ChatCompletions_Create",
                    "Completions_Create",
                    "Embeddings_Create",
                    "FineTuning_Jobs_Create",
                    "Models_List",
                    "Deployments_List",
                    "Deployments_Get",
                    "Deployments_Create",
                    "Deployments_Delete",
                    "Messages_Create",
                    "Claude_Create",
                    "GenerateContent",
                    "GenerateText",
                    "GenerateImage",
                    "Llama_Create",
                    "CodeLlama_Create",
                    "Gemini_Generate",
                    "Claude_Generate",
                    "Llama_Generate",
                ],
            }

    def test_azure_provider_not_auth_methods(self):
        subscription_id = None
        tenant_id = None
        # We need to set exactly one auth method
        az_cli_auth = None
        sp_env_auth = None
        browser_auth = None
        managed_identity_auth = None

        config_file = default_config_file_path
        fixer_config = default_fixer_config_file_path
        azure_region = "AzureCloud"

        with (
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.setup_identity",
                return_value=AzureIdentityInfo(),
            ),
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
                return_value={},
            ),
        ):
            with pytest.raises(AzureNoAuthenticationMethodError) as exception:
                _ = AzureProvider(
                    az_cli_auth,
                    sp_env_auth,
                    browser_auth,
                    managed_identity_auth,
                    tenant_id,
                    azure_region,
                    subscription_id,
                    config_file,
                    fixer_config,
                )
            assert exception.type == AzureNoAuthenticationMethodError
            assert (
                "Azure provider requires at least one authentication method set: [--az-cli-auth | --sp-env-auth | --browser-auth | --managed-identity-auth | --certificate-auth]"
                in exception.value.args[0]
            )

    def test_azure_provider_browser_auth_but_not_tenant_id(self):
        subscription_id = None
        tenant_id = None
        # We need to set exactly one auth method
        az_cli_auth = None
        sp_env_auth = None
        browser_auth = True
        managed_identity_auth = None
        config_file = default_config_file_path
        fixer_config = default_fixer_config_file_path
        azure_region = "AzureCloud"

        with (
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.setup_identity",
                return_value=AzureIdentityInfo(),
            ),
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
                return_value={},
            ),
        ):
            with pytest.raises(AzureBrowserAuthNoTenantIDError) as exception:
                _ = AzureProvider(
                    az_cli_auth,
                    sp_env_auth,
                    browser_auth,
                    managed_identity_auth,
                    tenant_id,
                    azure_region,
                    subscription_id,
                    config_file,
                    fixer_config,
                )
            assert exception.type == AzureBrowserAuthNoTenantIDError
            assert (
                exception.value.args[0]
                == "[2004] Azure Tenant ID (--tenant-id) is required for browser authentication mode"
            )

    def test_azure_provider_not_browser_auth_but_tenant_id(self):
        subscription_id = None

        tenant_id = "test-tenant-id"
        # We need to set exactly one auth method
        az_cli_auth = None
        sp_env_auth = None
        browser_auth = False
        managed_identity_auth = None
        config_file = default_config_file_path
        fixer_config = default_fixer_config_file_path
        azure_region = "AzureCloud"

        with (
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.setup_identity",
                return_value=AzureIdentityInfo(),
            ),
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
                return_value={},
            ),
        ):
            with pytest.raises(AzureTenantIDNoBrowserAuthError) as exception:
                _ = AzureProvider(
                    az_cli_auth,
                    sp_env_auth,
                    browser_auth,
                    managed_identity_auth,
                    tenant_id,
                    azure_region,
                    subscription_id,
                    config_file,
                    fixer_config,
                )
            assert exception.type == AzureTenantIDNoBrowserAuthError
            assert (
                exception.value.args[0]
                == "[2005] Azure Tenant ID (--tenant-id) is required for browser authentication mode"
            )

    def test_test_connection_browser_auth(self):
        with (
            patch(
                "prowler.providers.azure.azure_provider.DefaultAzureCredential"
            ) as mock_default_credential,
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.setup_session"
            ) as mock_setup_session,
            patch(
                "prowler.providers.azure.azure_provider.SubscriptionClient"
            ) as mock_resource_client,
        ):
            # Mock the return value of DefaultAzureCredential
            mock_credentials = MagicMock()
            mock_credentials.get_token.return_value = AccessToken(
                token="fake_token", expires_on=9999999999
            )
            mock_default_credential.return_value = mock_credentials

            # Mock setup_session to return a mocked session object
            mock_session = MagicMock()
            mock_setup_session.return_value = mock_session

            # Mock ResourceManagementClient to avoid real API calls
            mock_client = MagicMock()
            mock_resource_client.return_value = mock_client

            test_connection = AzureProvider.test_connection(
                browser_auth=True,
                tenant_id=str(uuid4()),
                region="AzureCloud",
                raise_on_exception=False,
            )

            assert isinstance(test_connection, Connection)
            assert test_connection.is_connected
            assert test_connection.error is None

    def test_test_connection_tenant_id_client_id_client_secret(self):
        with (
            patch(
                "prowler.providers.azure.azure_provider.DefaultAzureCredential"
            ) as mock_default_credential,
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.setup_session"
            ) as mock_setup_session,
            patch(
                "prowler.providers.azure.azure_provider.SubscriptionClient"
            ) as mock_resource_client,
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.validate_static_credentials"
            ) as mock_validate_static_credentials,
        ):
            # Mock the return value of DefaultAzureCredential
            mock_credentials = MagicMock()
            mock_credentials.get_token.return_value = AccessToken(
                token="fake_token", expires_on=9999999999
            )
            mock_default_credential.return_value = {
                "client_id": str(uuid4()),
                "client_secret": str(uuid4()),
                "tenant_id": str(uuid4()),
            }

            # Mock setup_session to return a mocked session object
            mock_session = MagicMock()
            mock_setup_session.return_value = mock_session

            # Mock ValidateStaticCredentials to avoid real API calls
            mock_validate_static_credentials.return_value = None

            # Mock ResourceManagementClient to avoid real API calls
            mock_client = MagicMock()
            mock_resource_client.return_value = mock_client

            test_connection = AzureProvider.test_connection(
                browser_auth=False,
                tenant_id=str(uuid4()),
                region="AzureCloud",
                raise_on_exception=False,
                client_id=str(uuid4()),
                client_secret=str(uuid4()),
            )

            assert isinstance(test_connection, Connection)
            assert test_connection.is_connected
            assert test_connection.error is None

    def test_test_connection_provider_validation(self):
        with (
            patch(
                "prowler.providers.azure.azure_provider.DefaultAzureCredential"
            ) as mock_default_credential,
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.setup_session"
            ) as mock_setup_session,
            patch(
                "prowler.providers.azure.azure_provider.SubscriptionClient"
            ) as mock_resource_client,
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.validate_static_credentials"
            ) as mock_validate_static_credentials,
        ):
            # Mock the return value of DefaultAzureCredential
            mock_default_credential.return_value = {
                "client_id": str(uuid4()),
                "client_secret": str(uuid4()),
                "tenant_id": str(uuid4()),
            }

            # Mock setup_session to return a mocked session object
            mock_session = MagicMock()
            mock_setup_session.return_value = mock_session

            # Mock ValidateStaticCredentials to avoid real API calls
            mock_validate_static_credentials.return_value = None

            # Mock ResourceManagementClient to avoid real API calls
            mock_subscription = MagicMock()
            mock_subscription.subscription_id = "test_provider_id"
            mock_return_value = MagicMock()
            mock_return_value.subscriptions.list.return_value = [mock_subscription]
            mock_resource_client.return_value = mock_return_value

            test_connection = AzureProvider.test_connection(
                browser_auth=False,
                tenant_id=str(uuid4()),
                region="AzureCloud",
                raise_on_exception=False,
                client_id=str(uuid4()),
                client_secret=str(uuid4()),
                provider_id="test_provider_id",
            )

            assert isinstance(test_connection, Connection)
            assert test_connection.is_connected
            assert test_connection.error is None

    def test_test_connection_provider_validation_error(self):
        with (
            patch(
                "prowler.providers.azure.azure_provider.DefaultAzureCredential"
            ) as mock_default_credential,
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.setup_session"
            ) as mock_setup_session,
            patch(
                "prowler.providers.azure.azure_provider.SubscriptionClient"
            ) as mock_resource_client,
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.validate_static_credentials"
            ) as mock_validate_static_credentials,
        ):
            # Mock the return value of DefaultAzureCredential
            mock_default_credential.return_value = {
                "client_id": str(uuid4()),
                "client_secret": str(uuid4()),
                "tenant_id": str(uuid4()),
            }

            # Mock setup_session to return a mocked session object
            mock_session = MagicMock()
            mock_setup_session.return_value = mock_session

            # Mock ValidateStaticCredentials to avoid real API calls
            mock_validate_static_credentials.return_value = None

            # Mock ResourceManagementClient to avoid real API calls
            mock_subscription = MagicMock()
            mock_subscription.subscription_id = "test_invalid_provider_id"
            mock_return_value = MagicMock()
            mock_return_value.subscriptions.list.return_value = [mock_subscription]
            mock_resource_client.return_value = mock_return_value

            test_connection = AzureProvider.test_connection(
                browser_auth=False,
                tenant_id=str(uuid4()),
                region="AzureCloud",
                raise_on_exception=False,
                client_id=str(uuid4()),
                client_secret=str(uuid4()),
                provider_id="test_provider_id",
            )

            assert test_connection.error is not None
            assert isinstance(test_connection.error, AzureInvalidProviderIdError)
            assert (
                "The provided credentials are not valid for the specified Azure subscription."
                in test_connection.error.args[0]
            )

    def test_test_connection_with_ClientAuthenticationError(self):
        tenant_id = str(uuid4())
        error_message = (
            "Authentication failed: Unable to get authority configuration for "
            f"https://login.microsoftonline.com/{tenant_id}."
        )

        with (
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.setup_session"
            ) as mock_setup_session,
            patch(
                "prowler.providers.azure.azure_provider.SubscriptionClient"
            ) as mock_subscription_client,
            pytest.raises(AzureHTTPResponseError) as exception,
        ):
            mock_setup_session.return_value = MagicMock()
            mock_client = MagicMock()
            mock_client.subscriptions = MagicMock()
            mock_client.subscriptions.list.side_effect = HttpResponseError(
                message=error_message
            )
            mock_subscription_client.return_value = mock_client

            AzureProvider.test_connection(
                browser_auth=True,
                tenant_id=tenant_id,
                region="AzureCloud",
            )

        assert exception.type == AzureHTTPResponseError
        assert exception.value.args[0] == (
            f"[2010] Error in HTTP response from Azure - {error_message}"
        )

    def test_test_connection_without_any_method(self):
        with pytest.raises(AzureNoAuthenticationMethodError) as exception:
            AzureProvider.test_connection()

        assert exception.type == AzureNoAuthenticationMethodError
        assert (
            "[2003] Azure provider requires at least one authentication method set: [--az-cli-auth | --sp-env-auth | --browser-auth | --managed-identity-auth | --certificate-auth]"
            in exception.value.args[0]
        )

    def test_test_connection_with_httpresponseerror(self):
        with (
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
                return_value={},
            ),
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.setup_session"
            ) as mock_setup_session,
        ):
            mock_setup_session.side_effect = AzureHTTPResponseError(
                file="test_file", original_exception="Simulated HttpResponseError"
            )

            with pytest.raises(AzureHTTPResponseError) as exception:
                AzureProvider.test_connection(
                    az_cli_auth=True,
                    raise_on_exception=True,
                )

            assert exception.type == AzureHTTPResponseError
            assert (
                exception.value.args[0]
                == "[2010] Error in HTTP response from Azure - Simulated HttpResponseError"
            )

    def test_test_connection_with_exception(self):
        with patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_session"
        ) as mock_setup_session:
            mock_setup_session.side_effect = Exception("Simulated Exception")

            with pytest.raises(Exception) as exception:
                AzureProvider.test_connection(
                    sp_env_auth=True,
                    raise_on_exception=True,
                )

            assert exception.type is Exception
            assert exception.value.args[0] == "Simulated Exception"

    @pytest.mark.parametrize(
        "subscription_ids, expected_regions",
        [
            (None, {"region1", "region2", "region3"}),
            (["sub1", "sub2"], {"region1", "region2", "region3"}),
            ("sub1", {"region1", "region2"}),
            ("not_exists", set()),
        ],
    )
    @patch("prowler.providers.azure.azure_provider.AzureProvider.get_locations")
    @patch(
        "prowler.providers.azure.azure_provider.AzureProvider.__init__",
        return_value=None,
    )
    def test_get_regions(
        self,
        azure_provider_init_mock,  # noqa: F841
        azure_get_locations_mock,
        subscription_ids,
        expected_regions,
    ):
        azure_get_locations_mock.return_value = {
            "sub1": ["region1", "region2"],
            "sub2": ["region2", "region3"],
        }

        azure_provider = AzureProvider()
        regions = azure_provider.get_regions(subscription_ids=subscription_ids)

        assert regions == expected_regions


class TestAzureProviderValidateResourceGroups:
    @patch(
        "prowler.providers.azure.azure_provider.AzureProvider.__init__",
        return_value=None,
    )
    def _make_provider(self, _mock_init, subscriptions=None):
        provider = AzureProvider()
        provider._identity = MagicMock()
        provider._identity.subscriptions = subscriptions or {str(uuid4()): "Sub"}
        provider._session = MagicMock()
        provider._region_config = MagicMock()
        return provider

    @patch("prowler.providers.azure.azure_provider.ResourceManagementClient")
    def test_validate_resource_groups_exact_match(self, mock_rm_client):
        provider = self._make_provider()
        sub_name = list(provider._identity.subscriptions.keys())[0]

        mock_rg = MagicMock()
        mock_rg.name = "mygroup"
        mock_resource_groups = MagicMock()
        mock_resource_groups.list.return_value = [mock_rg]
        mock_rm_client.return_value.resource_groups = mock_resource_groups

        result = provider.validate_resource_groups(["mygroup"])

        assert result[sub_name] == ["mygroup"]

    @patch("prowler.providers.azure.azure_provider.ResourceManagementClient")
    def test_validate_resource_groups_mixed_case(self, mock_rm_client):
        provider = self._make_provider()
        sub_name = list(provider._identity.subscriptions.keys())[0]

        mock_rg = MagicMock()
        mock_rg.name = "MyGroup"
        mock_resource_groups = MagicMock()
        mock_resource_groups.list.return_value = [mock_rg]
        mock_rm_client.return_value.resource_groups = mock_resource_groups

        result = provider.validate_resource_groups(["mygroup"])

        assert result[sub_name] == ["MyGroup"]
        mock_resource_groups.list.assert_called_once()

    @patch("prowler.providers.azure.azure_provider.ResourceManagementClient")
    def test_validate_resource_groups_multiple_rgs(self, mock_rm_client):
        provider = self._make_provider()
        sub_name = list(provider._identity.subscriptions.keys())[0]

        rg1, rg2 = MagicMock(), MagicMock()
        rg1.name = "rg1"
        rg2.name = "rg2"
        mock_resource_groups = MagicMock()
        mock_resource_groups.list.return_value = [rg1, rg2]
        mock_rm_client.return_value.resource_groups = mock_resource_groups

        result = provider.validate_resource_groups(["rg1", "rg2"])

        assert set(result[sub_name]) == {"rg1", "rg2"}

    @patch("prowler.providers.azure.azure_provider.ResourceManagementClient")
    def test_validate_resource_groups_not_found(self, mock_rm_client):
        provider = self._make_provider()
        sub_name = list(provider._identity.subscriptions.keys())[0]

        mock_rg = MagicMock()
        mock_rg.name = "existing"
        mock_resource_groups = MagicMock()
        mock_resource_groups.list.return_value = [mock_rg]
        mock_rm_client.return_value.resource_groups = mock_resource_groups

        result = provider.validate_resource_groups(["nonexistent"])

        assert result[sub_name] == []

    def test_validate_resource_groups_empty_input(self):
        provider = self._make_provider()
        result = provider.validate_resource_groups([])
        assert result == {}

    @patch("prowler.providers.azure.azure_provider.ResourceManagementClient")
    def test_validate_resource_groups_strips_whitespace(self, mock_rm_client):
        provider = self._make_provider()
        sub_name = list(provider._identity.subscriptions.keys())[0]

        mock_rg = MagicMock()
        mock_rg.name = "rg-prod"
        mock_resource_groups = MagicMock()
        mock_resource_groups.list.return_value = [mock_rg]
        mock_rm_client.return_value.resource_groups = mock_resource_groups

        result = provider.validate_resource_groups([" rg-prod "])

        assert result[sub_name] == ["rg-prod"]

    @patch("prowler.providers.azure.azure_provider.ResourceManagementClient")
    def test_validate_resource_groups_skips_subscription_when_listing_fails(
        self, mock_rm_client
    ):
        accessible_subscription = str(uuid4())
        failing_subscription = str(uuid4())
        provider = self._make_provider(
            subscriptions={
                accessible_subscription: "Accessible Sub",
                failing_subscription: "Failing Sub",
            }
        )

        mock_rg = MagicMock()
        mock_rg.name = "rg-prod"
        accessible_client = MagicMock()
        accessible_client.resource_groups.list.return_value = [mock_rg]
        failing_client = MagicMock()
        failing_client.resource_groups.list.side_effect = Exception("Forbidden")
        mock_rm_client.side_effect = [accessible_client, failing_client]

        result = provider.validate_resource_groups(["rg-prod"])

        assert result[accessible_subscription] == ["rg-prod"]
        assert result[failing_subscription] == []


class TestAzureProviderSetupIdentitySubscriptions:
    """Regression tests ensuring identity.subscriptions preserves every
    subscription even when multiple Azure subscriptions share the same
    display_name (which is permitted by Azure)."""

    @staticmethod
    def _mock_subscription(display_name, subscription_id):
        mock_subscription = MagicMock()
        mock_subscription.display_name = display_name
        mock_subscription.subscription_id = subscription_id
        return mock_subscription

    @staticmethod
    def _build_subscriptions_client_mock(list_result=None, get_map=None):
        """Construct a fully explicit SubscriptionClient mock so the tests do
        not depend on MagicMock auto-attribute behavior, which makes the suite
        sensitive to shared state across test files."""
        subscriptions_operations = MagicMock()
        subscriptions_operations.list = MagicMock(return_value=list_result or [])
        if get_map is not None:
            subscriptions_operations.get = MagicMock(
                side_effect=lambda subscription_id: get_map[subscription_id]
            )
        else:
            subscriptions_operations.get = MagicMock()

        tenants_operations = MagicMock()
        tenants_operations.list = MagicMock(return_value=[])

        client_instance = MagicMock()
        client_instance.subscriptions = subscriptions_operations
        client_instance.tenants = tenants_operations

        client_class = MagicMock(return_value=client_instance)
        return client_class

    @staticmethod
    def _build_provider():
        """Create an AzureProvider instance ready to invoke setup_identity
        with auth flags left False so the AAD lookup branches are skipped and
        the test focuses on the subscription resolution logic."""
        with patch.object(AzureProvider, "__init__", return_value=None):
            azure_provider = AzureProvider()
        azure_provider._session = MagicMock()
        azure_provider._region_config = AzureRegionConfig(
            name="AzureCloud",
            authority=None,
            base_url="https://management.azure.com",
            credential_scopes=["https://management.azure.com/.default"],
        )
        return azure_provider

    def test_setup_identity_auto_discovery_preserves_unique_display_names(self):
        first_id = str(uuid4())
        second_id = str(uuid4())
        client_class = self._build_subscriptions_client_mock(
            list_result=[
                self._mock_subscription("Unique Name One", first_id),
                self._mock_subscription("Unique Name Two", second_id),
            ]
        )
        with patch(
            "prowler.providers.azure.azure_provider.SubscriptionClient",
            client_class,
        ):
            azure_provider = self._build_provider()

            identity = azure_provider.setup_identity(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=False,
                subscription_ids=[],
                client_id=None,
            )

        assert identity.subscriptions == {
            first_id: "Unique Name One",
            second_id: "Unique Name Two",
        }

    def test_setup_identity_auto_discovery_preserves_duplicate_display_names(
        self,
    ):
        shared_name = "Shared Display Name"
        first_id = str(uuid4())
        second_id = str(uuid4())
        client_class = self._build_subscriptions_client_mock(
            list_result=[
                self._mock_subscription(shared_name, first_id),
                self._mock_subscription(shared_name, second_id),
            ]
        )
        with patch(
            "prowler.providers.azure.azure_provider.SubscriptionClient",
            client_class,
        ):
            azure_provider = self._build_provider()

            identity = azure_provider.setup_identity(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=False,
                subscription_ids=[],
                client_id=None,
            )

        assert identity.subscriptions == {
            first_id: shared_name,
            second_id: shared_name,
        }

    def test_setup_identity_filtered_preserves_unique_display_names(self):
        first_id = str(uuid4())
        second_id = str(uuid4())
        client_class = self._build_subscriptions_client_mock(
            get_map={
                first_id: self._mock_subscription("Unique Name One", first_id),
                second_id: self._mock_subscription("Unique Name Two", second_id),
            }
        )
        with patch(
            "prowler.providers.azure.azure_provider.SubscriptionClient",
            client_class,
        ):
            azure_provider = self._build_provider()

            identity = azure_provider.setup_identity(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=False,
                subscription_ids=[first_id, second_id],
                client_id=None,
            )

        assert identity.subscriptions == {
            first_id: "Unique Name One",
            second_id: "Unique Name Two",
        }

    def test_setup_identity_filtered_preserves_duplicate_display_names(self):
        shared_name = "Shared Display Name"
        first_id = str(uuid4())
        second_id = str(uuid4())
        client_class = self._build_subscriptions_client_mock(
            get_map={
                first_id: self._mock_subscription(shared_name, first_id),
                second_id: self._mock_subscription(shared_name, second_id),
            }
        )
        with patch(
            "prowler.providers.azure.azure_provider.SubscriptionClient",
            client_class,
        ):
            azure_provider = self._build_provider()

            identity = azure_provider.setup_identity(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=False,
                subscription_ids=[first_id, second_id],
                client_id=None,
            )

        assert identity.subscriptions == {
            first_id: shared_name,
            second_id: shared_name,
        }


class TestAzureProviderSovereignCloudSupport:
    """Sovereign-cloud authentication coverage across AzureCloud,
    AzureChinaCloud and AzureUSGovernment for every authentication code path
    Prowler exposes. Pinned to issue #8425."""

    REGION_CASES = [
        (
            "AzureCloud",
            None,
            "https://management.azure.com",
            ["https://management.azure.com/.default"],
            "https://graph.microsoft.com/.default",
            "https://api.loganalytics.io",
            "login.microsoftonline.com",
        ),
        (
            "AzureChinaCloud",
            "login.chinacloudapi.cn",
            "https://management.chinacloudapi.cn",
            ["https://management.chinacloudapi.cn/.default"],
            "https://microsoftgraph.chinacloudapi.cn/.default",
            "https://api.loganalytics.azure.cn",
            "login.chinacloudapi.cn",
        ),
        (
            "AzureUSGovernment",
            "login.microsoftonline.us",
            "https://management.usgovcloudapi.net",
            ["https://management.usgovcloudapi.net/.default"],
            "https://graph.microsoft.us/.default",
            "https://api.loganalytics.us",
            "login.microsoftonline.us",
        ),
    ]

    @pytest.mark.parametrize(
        "region,authority,base_url,credential_scopes,graph_scope,logs_endpoint,_login_endpoint",
        REGION_CASES,
    )
    def test_setup_region_config_per_cloud(
        self,
        region,
        authority,
        base_url,
        credential_scopes,
        graph_scope,
        logs_endpoint,
        _login_endpoint,
    ):
        config = AzureProvider.setup_region_config(region)

        # graph_host mirrors graph_scope without the `/.default` suffix; we
        # derive it here to avoid threading a separate parameter through every
        # parametrized test in this class.
        expected_graph_host = graph_scope.removesuffix("/.default")
        assert config == AzureRegionConfig(
            name=region,
            authority=authority,
            base_url=base_url,
            credential_scopes=credential_scopes,
            graph_host=expected_graph_host,
            graph_scope=graph_scope,
            logs_endpoint=logs_endpoint,
        )

    @pytest.mark.parametrize(
        "region,authority,_base_url,_credential_scopes,_graph_scope,_logs_endpoint,_login_endpoint",
        REGION_CASES,
    )
    def test_setup_session_static_credentials_passes_authority(
        self,
        region,
        authority,
        _base_url,
        _credential_scopes,
        _graph_scope,
        _logs_endpoint,
        _login_endpoint,
    ):
        with patch(
            "prowler.providers.azure.azure_provider.ClientSecretCredential"
        ) as mock_client_secret_credential:
            azure_credentials = {
                "tenant_id": str(uuid4()),
                "client_id": str(uuid4()),
                "client_secret": "fake-secret-value",
            }
            region_config = AzureProvider.setup_region_config(region)

            AzureProvider.setup_session(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=False,
                certificate_path=None,
                tenant_id=azure_credentials["tenant_id"],
                azure_credentials=azure_credentials,
                region_config=region_config,
            )

            mock_client_secret_credential.assert_called_once_with(
                tenant_id=azure_credentials["tenant_id"],
                client_id=azure_credentials["client_id"],
                client_secret=azure_credentials["client_secret"],
                authority=authority,
            )

    @pytest.mark.parametrize(
        "region,authority,_base_url,_credential_scopes,_graph_scope,_logs_endpoint,_login_endpoint",
        REGION_CASES,
    )
    def test_setup_session_browser_auth_passes_authority(
        self,
        region,
        authority,
        _base_url,
        _credential_scopes,
        _graph_scope,
        _logs_endpoint,
        _login_endpoint,
    ):
        with patch(
            "prowler.providers.azure.azure_provider.InteractiveBrowserCredential"
        ) as mock_interactive_browser_credential:
            tenant_id = str(uuid4())
            region_config = AzureProvider.setup_region_config(region)

            AzureProvider.setup_session(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=True,
                managed_identity_auth=False,
                certificate_auth=False,
                certificate_path=None,
                tenant_id=tenant_id,
                azure_credentials=None,
                region_config=region_config,
            )

            mock_interactive_browser_credential.assert_called_once_with(
                tenant_id=tenant_id,
                authority=authority,
            )

    @pytest.mark.parametrize(
        "region,authority,_base_url,_credential_scopes,_graph_scope,_logs_endpoint,_login_endpoint",
        REGION_CASES,
    )
    def test_setup_session_default_credential_passes_authority(
        self,
        region,
        authority,
        _base_url,
        _credential_scopes,
        _graph_scope,
        _logs_endpoint,
        _login_endpoint,
    ):
        with patch(
            "prowler.providers.azure.azure_provider.DefaultAzureCredential"
        ) as mock_default_credential:
            region_config = AzureProvider.setup_region_config(region)

            AzureProvider.setup_session(
                az_cli_auth=True,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=False,
                certificate_path=None,
                tenant_id=None,
                azure_credentials=None,
                region_config=region_config,
            )

            _, called_kwargs = mock_default_credential.call_args
            assert called_kwargs["authority"] == authority
            assert called_kwargs["exclude_cli_credential"] is False
            assert called_kwargs["exclude_environment_credential"] is True
            assert called_kwargs["exclude_managed_identity_credential"] is True

    @pytest.mark.parametrize(
        "region,_authority,_base_url,_credential_scopes,graph_scope,_logs_endpoint,login_endpoint",
        REGION_CASES,
    )
    def test_verify_client_uses_per_cloud_endpoints(
        self,
        region,
        _authority,
        _base_url,
        _credential_scopes,
        graph_scope,
        _logs_endpoint,
        login_endpoint,
    ):
        tenant_id = str(uuid4())
        client_id = str(uuid4())
        client_secret = "fake-secret"
        region_config = AzureProvider.setup_region_config(region)

        with patch("prowler.providers.azure.azure_provider.requests.post") as mock_post:
            mock_post.return_value = MagicMock()
            mock_post.return_value.json.return_value = {"access_token": "fake-token"}

            AzureProvider.verify_client(
                tenant_id, client_id, client_secret, region_config
            )

            mock_post.assert_called_once()
            args, kwargs = mock_post.call_args
            assert args[0] == (
                f"https://{login_endpoint}/{tenant_id}/oauth2/v2.0/token"
            )
            assert kwargs["data"]["scope"] == graph_scope
            assert kwargs["data"]["client_id"] == client_id
            assert kwargs["data"]["client_secret"] == client_secret

    @pytest.mark.parametrize(
        "region,_authority,base_url,credential_scopes,_graph_scope,_logs_endpoint,_login_endpoint",
        REGION_CASES,
    )
    def test_test_connection_passes_base_url_to_subscription_client(
        self,
        region,
        _authority,
        base_url,
        credential_scopes,
        _graph_scope,
        _logs_endpoint,
        _login_endpoint,
    ):
        subscription_client_instance = MagicMock()
        subscription_client_instance.subscriptions = MagicMock()
        subscription_client_instance.subscriptions.list = MagicMock(return_value=[])
        subscription_client_class = MagicMock(return_value=subscription_client_instance)

        with (
            patch(
                "prowler.providers.azure.azure_provider.AzureProvider.setup_session"
            ) as mock_setup_session,
            patch(
                "prowler.providers.azure.azure_provider.SubscriptionClient",
                subscription_client_class,
            ),
        ):
            mock_setup_session.return_value = MagicMock()

            AzureProvider.test_connection(
                az_cli_auth=True,
                region=region,
                raise_on_exception=False,
            )

            subscription_client_class.assert_called_once()
            _, kwargs = subscription_client_class.call_args
            assert kwargs["base_url"] == base_url
            assert kwargs["credential_scopes"] == credential_scopes

    @pytest.mark.parametrize(
        "region,_authority,base_url,credential_scopes,_graph_scope,_logs_endpoint,_login_endpoint",
        REGION_CASES,
    )
    def test_get_locations_passes_base_url_to_subscription_client(
        self,
        region,
        _authority,
        base_url,
        credential_scopes,
        _graph_scope,
        _logs_endpoint,
        _login_endpoint,
    ):
        subscription_client_instance = MagicMock()
        subscription_client_instance.subscriptions = MagicMock()
        subscription_client_instance.subscriptions.list_locations = MagicMock(
            return_value=[]
        )
        subscription_client_class = MagicMock(return_value=subscription_client_instance)

        with (
            patch.object(AzureProvider, "__init__", return_value=None),
            patch(
                "prowler.providers.azure.azure_provider.SubscriptionClient",
                subscription_client_class,
            ),
        ):
            azure_provider = AzureProvider()
            azure_provider._session = MagicMock()
            azure_provider._region_config = AzureProvider.setup_region_config(region)
            azure_provider._identity = AzureIdentityInfo(subscriptions={})

            azure_provider.get_locations()

            subscription_client_class.assert_called_once()
            _, kwargs = subscription_client_class.call_args
            assert kwargs["base_url"] == base_url
            assert kwargs["credential_scopes"] == credential_scopes


class TestAzureProviderSetupIdentityEventLoop:
    """Regression for the Celery worker scenario where
    asyncio.get_event_loop() raised "There is no current event loop in
    thread 'MainThread'." on Python 3.12. setup_identity now uses
    asyncio.run(), which creates its own loop and must work without a
    pre-existing one in the current thread."""

    @staticmethod
    def _mock_subscription(display_name, subscription_id):
        mock_subscription = MagicMock()
        mock_subscription.display_name = display_name
        mock_subscription.subscription_id = subscription_id
        return mock_subscription

    @staticmethod
    def _build_subscriptions_client_mock(subscriptions):
        subscriptions_operations = MagicMock()
        subscriptions_operations.list = MagicMock(return_value=subscriptions)
        subscriptions_operations.get = MagicMock()

        tenants_operations = MagicMock()
        tenants_operations.list = MagicMock(return_value=[])

        client_instance = MagicMock()
        client_instance.subscriptions = subscriptions_operations
        client_instance.tenants = tenants_operations
        return MagicMock(return_value=client_instance)

    @staticmethod
    def _build_provider():
        with patch.object(AzureProvider, "__init__", return_value=None):
            azure_provider = AzureProvider()
        azure_provider._session = MagicMock()
        azure_provider._region_config = AzureRegionConfig(
            name="AzureCloud",
            authority=None,
            base_url="https://management.azure.com",
            credential_scopes=["https://management.azure.com/.default"],
        )
        return azure_provider

    def test_setup_identity_succeeds_without_active_event_loop(self):
        sub_id = str(uuid4())
        subscriptions_client = self._build_subscriptions_client_mock(
            [self._mock_subscription("Sub", sub_id)]
        )

        graph_client = MagicMock()
        graph_client.domains.get = AsyncMock(return_value=MagicMock(value=[]))
        graph_client.me.get = AsyncMock(return_value=None)

        # Simulate the Celery worker state: no event loop registered for the
        # current thread. Before the fix this combination triggered
        # `RuntimeError: There is no current event loop in thread 'MainThread'.`
        # on Python 3.12 from asyncio.get_event_loop().
        asyncio.set_event_loop(None)
        try:
            with (
                patch(
                    "prowler.providers.azure.azure_provider.GraphServiceClient",
                    return_value=graph_client,
                ),
                patch(
                    "prowler.providers.azure.azure_provider.SubscriptionClient",
                    subscriptions_client,
                ),
            ):
                azure_provider = self._build_provider()
                identity = azure_provider.setup_identity(
                    az_cli_auth=False,
                    sp_env_auth=True,
                    browser_auth=False,
                    managed_identity_auth=False,
                    certificate_auth=False,
                    subscription_ids=[],
                    client_id="00000000-0000-0000-0000-000000000000",
                )
        finally:
            # Re-arm a loop for sibling tests that may rely on the default.
            asyncio.set_event_loop(asyncio.new_event_loop())

        assert isinstance(identity, AzureIdentityInfo)
        assert identity.subscriptions == {sub_id: "Sub"}
        graph_client.domains.get.assert_awaited_once()


class TestAzureProviderCertificateAuth:
    """Coverage for the certificate-based service-principal auth path added
    by the Deploy-to-Azure quick-start (PROWLER-2378)."""

    _TENANT_ID = "12345678-1234-1234-1234-123456789012"
    _CLIENT_ID = "87654321-4321-4321-4321-210987654321"
    # Base64 of a valid tiny DER payload — the tests only check that base64
    # decoding succeeds inside `validate_static_credentials`; the actual
    # certificate parsing is mocked at the `CertificateCredential` boundary.
    _CERT_CONTENT_B64 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"

    def _region_config(self):
        return AzureProvider.setup_region_config("AzureCloud")

    @staticmethod
    def _certificate_and_key():
        from datetime import datetime, timedelta, timezone

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Prowler")])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .sign(private_key, hashes.SHA256())
        )
        return certificate, private_key

    def test_validate_arguments_rejects_client_secret_and_cert_together(self):
        with pytest.raises(AzureConfigCredentialsError) as exception:
            AzureProvider.validate_arguments(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=False,
                tenant_id=self._TENANT_ID,
                client_id=self._CLIENT_ID,
                client_secret="some-secret",
                certificate_content=self._CERT_CONTENT_B64,
                certificate_path=None,
            )
        assert "not both" in exception.value.args[0]

    def test_validate_arguments_rejects_cert_content_and_path_together(self, tmp_path):
        with pytest.raises(AzureConfigCredentialsError) as exception:
            AzureProvider.validate_arguments(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=False,
                tenant_id=self._TENANT_ID,
                client_id=self._CLIENT_ID,
                client_secret=None,
                certificate_content=self._CERT_CONTENT_B64,
                certificate_path=str(tmp_path / "anything"),
            )
        assert "not both" in exception.value.args[0]

    def test_validate_arguments_accepts_certificate_content_only(self):
        # Should not raise: cert content alone is a valid credential shape.
        AzureProvider.validate_arguments(
            az_cli_auth=False,
            sp_env_auth=False,
            browser_auth=False,
            managed_identity_auth=False,
            certificate_auth=False,
            tenant_id=self._TENANT_ID,
            client_id=self._CLIENT_ID,
            client_secret=None,
            certificate_content=self._CERT_CONTENT_B64,
            certificate_path=None,
        )

    def test_validate_arguments_rejects_client_id_without_credential_material(self):
        with pytest.raises(AzureConfigCredentialsError, match="must provide"):
            AzureProvider.validate_arguments(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=False,
                tenant_id=self._TENANT_ID,
                client_id=self._CLIENT_ID,
                client_secret=None,
                certificate_content=None,
                certificate_path=None,
            )

    def test_check_certificate_creds_env_vars_missing_content(self, monkeypatch):
        monkeypatch.setenv("AZURE_CLIENT_ID", self._CLIENT_ID)
        monkeypatch.setenv("AZURE_TENANT_ID", self._TENANT_ID)
        monkeypatch.delenv("AZURE_CERTIFICATE_CONTENT", raising=False)
        with pytest.raises(AzureEnvironmentVariableError) as exception:
            AzureProvider.check_certificate_creds_env_vars(
                check_certificate_content=True
            )
        assert "AZURE_CERTIFICATE_CONTENT" in exception.value.args[0]

    def test_check_certificate_creds_env_vars_skips_content_check_with_path(
        self, monkeypatch
    ):
        # When a certificate path is provided at construction time, we must
        # NOT require AZURE_CERTIFICATE_CONTENT in the environment.
        monkeypatch.setenv("AZURE_CLIENT_ID", self._CLIENT_ID)
        monkeypatch.setenv("AZURE_TENANT_ID", self._TENANT_ID)
        monkeypatch.delenv("AZURE_CERTIFICATE_CONTENT", raising=False)
        # Should not raise
        AzureProvider.check_certificate_creds_env_vars(check_certificate_content=False)

    def test_validate_static_credentials_rejects_non_base64_cert_content(self):
        with pytest.raises(AzureNotValidCertificateContentError):
            AzureProvider.validate_static_credentials(
                tenant_id=self._TENANT_ID,
                client_id=self._CLIENT_ID,
                client_secret=None,
                certificate_content="not_valid_base64_@@@",
                certificate_path=None,
                region_config=self._region_config(),
            )

    def test_validate_static_credentials_rejects_key_only_pem(self):
        import base64

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_only_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with (
            patch.object(AzureProvider, "verify_client"),
            pytest.raises(AzureNotValidCertificateContentError),
        ):
            AzureProvider.validate_static_credentials(
                tenant_id=self._TENANT_ID,
                client_id=self._CLIENT_ID,
                client_secret=None,
                certificate_content=base64.b64encode(key_only_pem).decode("ascii"),
                certificate_path=None,
                region_config=self._region_config(),
            )

    def test_validate_static_credentials_rejects_key_only_pkcs12(self):
        import base64

        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12

        _, private_key = self._certificate_and_key()
        key_only_pkcs12 = pkcs12.serialize_key_and_certificates(
            name=b"prowler",
            key=private_key,
            cert=None,
            cas=None,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with pytest.raises(AzureNotValidCertificateContentError):
            AzureProvider.validate_static_credentials(
                tenant_id=self._TENANT_ID,
                client_id=self._CLIENT_ID,
                client_secret=None,
                certificate_content=base64.b64encode(key_only_pkcs12).decode("ascii"),
                certificate_path=None,
                region_config=self._region_config(),
            )

    def test_validate_static_credentials_rejects_missing_credential_material(self):
        with pytest.raises(AzureNotValidClientSecretError, match="must provide"):
            AzureProvider.validate_static_credentials(
                tenant_id=self._TENANT_ID,
                client_id=self._CLIENT_ID,
                client_secret=None,
                certificate_content=None,
                certificate_path=None,
                region_config=self._region_config(),
            )

    def test_validate_static_credentials_rejects_mismatched_certificate_and_key(self):
        import base64
        from datetime import datetime, timedelta, timezone

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        certificate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        different_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Prowler")])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(certificate_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .sign(certificate_key, hashes.SHA256())
        )
        mismatched_bundle = certificate.public_bytes(
            serialization.Encoding.PEM
        ) + different_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        with (
            patch.object(AzureProvider, "verify_client"),
            pytest.raises(AzureNotValidCertificateContentError),
        ):
            AzureProvider.validate_static_credentials(
                tenant_id=self._TENANT_ID,
                client_id=self._CLIENT_ID,
                client_secret=None,
                certificate_content=base64.b64encode(mismatched_bundle).decode("ascii"),
                certificate_path=None,
                region_config=self._region_config(),
            )

    def test_validate_static_credentials_rejects_missing_cert_file(self, tmp_path):
        with pytest.raises(AzureNotValidCertificatePathError):
            AzureProvider.validate_static_credentials(
                tenant_id=self._TENANT_ID,
                client_id=self._CLIENT_ID,
                client_secret=None,
                certificate_content=None,
                certificate_path=str(tmp_path / "does-not-exist-prowler-cert.pem"),
                region_config=self._region_config(),
            )

    def test_validate_static_credentials_rejects_invalid_cert_file(self, tmp_path):
        certificate_path = tmp_path / "invalid-certificate.pem"
        certificate_path.write_bytes(b"not a certificate bundle")

        with (
            patch.object(AzureProvider, "verify_client"),
            pytest.raises(AzureNotValidCertificatePathError),
        ):
            AzureProvider.validate_static_credentials(
                tenant_id=self._TENANT_ID,
                client_id=self._CLIENT_ID,
                client_secret=None,
                certificate_content=None,
                certificate_path=str(certificate_path),
                region_config=self._region_config(),
            )

    def test_validate_static_credentials_rejects_key_only_cert_file(self, tmp_path):
        from cryptography.hazmat.primitives import serialization

        _, private_key = self._certificate_and_key()
        certificate_path = tmp_path / "key-only.pem"
        certificate_path.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        with (
            patch.object(AzureProvider, "verify_client"),
            pytest.raises(AzureNotValidCertificatePathError),
        ):
            AzureProvider.validate_static_credentials(
                tenant_id=self._TENANT_ID,
                client_id=self._CLIENT_ID,
                client_secret=None,
                certificate_content=None,
                certificate_path=str(certificate_path),
                region_config=self._region_config(),
            )

    def test_validate_static_credentials_rejects_mismatched_cert_file(self, tmp_path):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        certificate, _ = self._certificate_and_key()
        different_private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        certificate_path = tmp_path / "mismatched-certificate.pem"
        certificate_path.write_bytes(
            certificate.public_bytes(serialization.Encoding.PEM)
            + different_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        with (
            patch.object(AzureProvider, "verify_client"),
            pytest.raises(AzureNotValidCertificatePathError),
        ):
            AzureProvider.validate_static_credentials(
                tenant_id=self._TENANT_ID,
                client_id=self._CLIENT_ID,
                client_secret=None,
                certificate_content=None,
                certificate_path=str(certificate_path),
                region_config=self._region_config(),
            )

    def test_validate_static_credentials_accepts_valid_pem_cert_file(self, tmp_path):
        from cryptography.hazmat.primitives import serialization

        certificate, private_key = self._certificate_and_key()
        certificate_path = tmp_path / "certificate-bundle.pem"
        certificate_path.write_bytes(
            certificate.public_bytes(serialization.Encoding.PEM)
            + private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        with patch.object(AzureProvider, "verify_client"):
            credentials = AzureProvider.validate_static_credentials(
                tenant_id=self._TENANT_ID,
                client_id=self._CLIENT_ID,
                client_secret=None,
                certificate_content=None,
                certificate_path=str(certificate_path),
                region_config=self._region_config(),
            )

        # Assert the full contract, not just certificate_path — a stray
        # truthy certificate_content or client_secret would route
        # setup_session to the wrong branch and stay undetected.
        assert credentials == {
            "tenant_id": self._TENANT_ID,
            "client_id": self._CLIENT_ID,
            "client_secret": None,
            "certificate_content": None,
            "certificate_path": str(certificate_path),
        }

    def test_validate_static_credentials_accepts_valid_pkcs12_cert_file(self, tmp_path):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12

        certificate, private_key = self._certificate_and_key()
        certificate_path = tmp_path / "certificate-bundle.pfx"
        certificate_path.write_bytes(
            pkcs12.serialize_key_and_certificates(
                name=b"prowler",
                key=private_key,
                cert=certificate,
                cas=None,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

        with patch.object(AzureProvider, "verify_client"):
            credentials = AzureProvider.validate_static_credentials(
                tenant_id=self._TENANT_ID,
                client_id=self._CLIENT_ID,
                client_secret=None,
                certificate_content=None,
                certificate_path=str(certificate_path),
                region_config=self._region_config(),
            )

        # Same rationale as the PEM test above: assert the full dict.
        assert credentials == {
            "tenant_id": self._TENANT_ID,
            "client_id": self._CLIENT_ID,
            "client_secret": None,
            "certificate_content": None,
            "certificate_path": str(certificate_path),
        }

    def test_setup_session_static_credentials_cert_content_uses_certificate_credential(
        self,
    ):
        # When the credentials dict carries a certificate_content, setup_session
        # must instantiate CertificateCredential (not ClientSecretCredential)
        # with the decoded bytes.
        with patch(
            "prowler.providers.azure.azure_provider.CertificateCredential"
        ) as mock_cert_cred:
            AzureProvider.setup_session(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=False,
                certificate_path=None,
                tenant_id=self._TENANT_ID,
                azure_credentials={
                    "tenant_id": self._TENANT_ID,
                    "client_id": self._CLIENT_ID,
                    "client_secret": None,
                    "certificate_content": self._CERT_CONTENT_B64,
                    "certificate_path": None,
                },
                region_config=self._region_config(),
            )
            mock_cert_cred.assert_called_once()
            _, kwargs = mock_cert_cred.call_args
            assert kwargs["tenant_id"] == self._TENANT_ID
            assert kwargs["client_id"] == self._CLIENT_ID
            # The dict content is passed through base64.b64decode into bytes.
            assert isinstance(kwargs["certificate_data"], (bytes, bytearray))

    def test_setup_session_static_credentials_certificate_path_reads_bundle(
        self, tmp_path
    ):
        certificate_path = tmp_path / "prowler-cert.pem"
        certificate_path.write_bytes(b"certificate bundle")
        expected_credentials = MagicMock()

        with patch(
            "prowler.providers.azure.azure_provider._build_certificate_credential",
            return_value=expected_credentials,
        ) as build_certificate_credential:
            credentials = AzureProvider.setup_session(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=False,
                certificate_path=None,
                tenant_id=self._TENANT_ID,
                azure_credentials={
                    "tenant_id": self._TENANT_ID,
                    "client_id": self._CLIENT_ID,
                    "client_secret": None,
                    "certificate_content": None,
                    "certificate_path": str(certificate_path),
                },
                region_config=self._region_config(),
            )

        assert credentials is expected_credentials
        build_certificate_credential.assert_called_once_with(
            tenant_id=self._TENANT_ID,
            client_id=self._CLIENT_ID,
            certificate_data=b"certificate bundle",
            authority=None,
        )

    def test_setup_session_env_cert_auth_uses_certificate_credential(self, monkeypatch):
        monkeypatch.setenv("AZURE_CLIENT_ID", self._CLIENT_ID)
        monkeypatch.setenv("AZURE_TENANT_ID", self._TENANT_ID)
        monkeypatch.setenv("AZURE_CERTIFICATE_CONTENT", self._CERT_CONTENT_B64)
        with (
            patch("prowler.providers.azure.azure_provider.validate_certificate_bundle"),
            patch(
                "prowler.providers.azure.azure_provider.CertificateCredential"
            ) as mock_cert_cred,
        ):
            AzureProvider.setup_session(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=True,
                certificate_path=None,
                tenant_id=None,
                azure_credentials=None,
                region_config=self._region_config(),
            )
            mock_cert_cred.assert_called_once()
            _, kwargs = mock_cert_cred.call_args
            assert kwargs["tenant_id"] == self._TENANT_ID
            assert kwargs["client_id"] == self._CLIENT_ID

    def test_setup_session_env_cert_auth_reads_certificate_path(
        self, monkeypatch, tmp_path
    ):
        certificate_path = tmp_path / "prowler-cert.pem"
        certificate_path.write_bytes(b"environment certificate bundle")
        monkeypatch.setenv("AZURE_CLIENT_ID", self._CLIENT_ID)
        monkeypatch.setenv("AZURE_TENANT_ID", self._TENANT_ID)
        expected_credentials = MagicMock()

        with (
            patch("prowler.providers.azure.azure_provider.validate_certificate_bundle"),
            patch(
                "prowler.providers.azure.azure_provider._build_certificate_credential",
                return_value=expected_credentials,
            ) as build_certificate_credential,
        ):
            credentials = AzureProvider.setup_session(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=True,
                certificate_path=str(certificate_path),
                tenant_id=None,
                azure_credentials=None,
                region_config=self._region_config(),
            )

        assert credentials is expected_credentials
        build_certificate_credential.assert_called_once_with(
            tenant_id=self._TENANT_ID,
            client_id=self._CLIENT_ID,
            certificate_data=b"environment certificate bundle",
            authority=None,
        )

    def test_setup_session_env_cert_auth_preserves_missing_variable_error(self):
        expected_error = AzureEnvironmentVariableError(
            file="azure_provider.py",
            message="Missing certificate credentials.",
        )

        with (
            patch.object(
                AzureProvider,
                "check_certificate_creds_env_vars",
                side_effect=expected_error,
            ),
            pytest.raises(AzureEnvironmentVariableError) as exception,
        ):
            AzureProvider.setup_session(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=True,
                certificate_path=None,
                tenant_id=None,
                azure_credentials=None,
                region_config=self._region_config(),
            )

        assert exception.value is expected_error

    def test_setup_session_env_cert_auth_translates_authentication_error(
        self, monkeypatch
    ):
        monkeypatch.setenv("AZURE_CLIENT_ID", self._CLIENT_ID)
        monkeypatch.setenv("AZURE_TENANT_ID", self._TENANT_ID)
        monkeypatch.setenv("AZURE_CERTIFICATE_CONTENT", self._CERT_CONTENT_B64)

        with (
            # `validate_certificate_bundle` runs first on the env-var branch to
            # fail fast on unparseable bytes; this test isolates the
            # authentication-error translation path, so keep the placeholder
            # base64 payload from tripping the bundle check.
            patch("prowler.providers.azure.azure_provider.validate_certificate_bundle"),
            patch(
                "prowler.providers.azure.azure_provider._build_certificate_credential",
                side_effect=ClientAuthenticationError("invalid certificate"),
            ),
            pytest.raises(AzureSetUpSessionError, match="client authentication"),
        ):
            AzureProvider.setup_session(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=True,
                certificate_path=None,
                tenant_id=None,
                azure_credentials=None,
                region_config=self._region_config(),
            )

    @pytest.mark.parametrize(
        ("tenant_id", "client_id", "error_description", "expected_error"),
        [
            (
                "invalid-tenant",
                _CLIENT_ID,
                "Tenant 'invalid-tenant' was not found",
                AzureNotValidTenantIdError,
            ),
            (
                _TENANT_ID,
                "invalid-client",
                "Application with identifier 'invalid-client' was not found",
                AzureNotValidClientIdError,
            ),
            (
                _TENANT_ID,
                _CLIENT_ID,
                "Invalid client secret provided",
                AzureNotValidClientSecretError,
            ),
        ],
    )
    def test_verify_client_translates_token_endpoint_errors(
        self, tenant_id, client_id, error_description, expected_error
    ):
        with (
            patch("prowler.providers.azure.azure_provider.requests.post") as post,
            pytest.raises(expected_error),
        ):
            post.return_value.json.return_value = {
                "error_codes": [700016],
                "error_description": error_description,
            }
            AzureProvider.verify_client(
                tenant_id,
                client_id,
                "invalid-secret",
                self._region_config(),
            )

    def test_verify_client_certificate_content_acquires_graph_token(self):
        import base64

        with patch(
            "prowler.providers.azure.azure_provider.CertificateCredential"
        ) as certificate_credential:
            AzureProvider.verify_client(
                self._TENANT_ID,
                self._CLIENT_ID,
                client_secret=None,
                region_config=self._region_config(),
                certificate_content=self._CERT_CONTENT_B64,
            )

        certificate_credential.assert_called_once_with(
            client_id=self._CLIENT_ID,
            tenant_id=self._TENANT_ID,
            certificate_data=base64.b64decode(self._CERT_CONTENT_B64),
            authority=None,
        )
        certificate_credential.return_value.get_token.assert_called_once_with(
            "https://graph.microsoft.com/.default"
        )

    def test_verify_client_certificate_path_reads_bundle(self, tmp_path):
        certificate_path = tmp_path / "prowler-cert.pem"
        certificate_path.write_bytes(b"certificate bundle")

        with patch(
            "prowler.providers.azure.azure_provider.CertificateCredential"
        ) as certificate_credential:
            AzureProvider.verify_client(
                self._TENANT_ID,
                self._CLIENT_ID,
                client_secret=None,
                region_config=self._region_config(),
                certificate_path=str(certificate_path),
            )

        assert (
            certificate_credential.call_args.kwargs["certificate_data"]
            == b"certificate bundle"
        )
        certificate_credential.return_value.get_token.assert_called_once_with(
            "https://graph.microsoft.com/.default"
        )

    @pytest.mark.parametrize("credential_source", ["content", "path"])
    def test_verify_client_translates_certificate_authentication_error(
        self, credential_source, tmp_path
    ):
        certificate_content = None
        certificate_path = None
        expected_error = AzureNotValidCertificateContentError
        if credential_source == "content":
            certificate_content = self._CERT_CONTENT_B64
        else:
            path = tmp_path / "prowler-cert.pem"
            path.write_bytes(b"certificate bundle")
            certificate_path = str(path)
            expected_error = AzureNotValidCertificatePathError

        with (
            patch(
                "prowler.providers.azure.azure_provider.CertificateCredential",
                side_effect=ClientAuthenticationError("invalid certificate"),
            ),
            pytest.raises(expected_error),
        ):
            AzureProvider.verify_client(
                self._TENANT_ID,
                self._CLIENT_ID,
                client_secret=None,
                region_config=self._region_config(),
                certificate_content=certificate_content,
                certificate_path=certificate_path,
            )

    def test_verify_client_without_credential_material_returns(self):
        assert (
            AzureProvider.verify_client(
                self._TENANT_ID,
                self._CLIENT_ID,
                client_secret=None,
                region_config=self._region_config(),
            )
            is None
        )

    def test_certificate_identity_and_printed_credentials_include_thumbprint(self):
        from cryptography.hazmat.primitives import hashes, serialization

        from prowler.providers.azure.azure_provider import (
            _build_certificate_credential,
        )

        certificate, private_key = self._certificate_and_key()
        bundle = certificate.public_bytes(
            serialization.Encoding.PEM
        ) + private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        expected_thumbprint = certificate.fingerprint(hashes.SHA1()).hex().upper()
        credentials = _build_certificate_credential(
            tenant_id=self._TENANT_ID,
            client_id=self._CLIENT_ID,
            certificate_data=bundle,
            authority=None,
        )

        with patch.object(AzureProvider, "__init__", return_value=None):
            provider = AzureProvider()
        provider._session = credentials
        provider._region_config = self._region_config()

        graph_client = MagicMock()
        graph_client.domains.get = AsyncMock(return_value=MagicMock(value=[]))
        subscription_client = MagicMock()
        subscription_client.subscriptions.list.return_value = [
            MagicMock(display_name="Subscription", subscription_id="subscription-id")
        ]
        subscription_client.tenants.list.return_value = [
            MagicMock(tenant_id=self._TENANT_ID)
        ]

        with (
            patch(
                "prowler.providers.azure.azure_provider.GraphServiceClient",
                return_value=graph_client,
            ),
            patch(
                "prowler.providers.azure.azure_provider.SubscriptionClient",
                return_value=subscription_client,
            ),
        ):
            identity = provider.setup_identity(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=False,
                subscription_ids=[],
                client_id=self._CLIENT_ID,
            )

        assert identity.identity_id == self._CLIENT_ID
        assert identity.identity_type == "Service Principal with Certificate"
        assert identity.certificate_thumbprint == expected_thumbprint

        provider._identity = identity
        provider._resource_groups = {}
        with patch("prowler.providers.azure.azure_provider.print_boxes") as print_boxes:
            provider.print_credentials()

        report_lines = print_boxes.call_args.args[0]
        assert any(expected_thumbprint in line for line in report_lines)

    def test_setup_session_attaches_computed_thumbprint(self):
        # Regression guard for the thumbprint handoff added in PROWLER-2378.
        # The earlier `test_setup_session_static_credentials_cert_content_...`
        # test patches `CertificateCredential` with a `MagicMock` which
        # silently accepts any `setattr`, so even a missing hand-off would
        # look green. This test uses a REAL certificate so
        # `_compute_certificate_thumbprint` returns a real value and asserts
        # the credential object actually carries it under
        # `_PROWLER_CERT_THUMBPRINT_ATTR` — the sole reason that attribute
        # exists is `setup_identity`'s cert-branch reading it.
        import base64
        from datetime import datetime, timedelta, timezone

        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography.x509.oid import NameOID

        from prowler.providers.azure.azure_provider import (
            _PROWLER_CERT_THUMBPRINT_ATTR,
        )

        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "prowler-test")]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .sign(key, hashes.SHA256(), default_backend())
        )
        expected_thumbprint = cert.fingerprint(hashes.SHA1()).hex().upper()
        # azure-identity accepts PKCS#12; encode it so the dict looks like
        # what the API layer stores after the serializer runs.
        pfx = pkcs12.serialize_key_and_certificates(
            name=b"prowler",
            key=key,
            cert=cert,
            cas=None,
            encryption_algorithm=serialization.NoEncryption(),
        )
        cert_content_b64 = base64.b64encode(pfx).decode("ascii")

        credentials = AzureProvider.setup_session(
            az_cli_auth=False,
            sp_env_auth=False,
            browser_auth=False,
            managed_identity_auth=False,
            certificate_auth=False,
            certificate_path=None,
            tenant_id=self._TENANT_ID,
            azure_credentials={
                "tenant_id": self._TENANT_ID,
                "client_id": self._CLIENT_ID,
                "client_secret": None,
                "certificate_content": cert_content_b64,
                "certificate_path": None,
            },
            region_config=self._region_config(),
        )
        assert (
            getattr(credentials, _PROWLER_CERT_THUMBPRINT_ATTR, None)
            == expected_thumbprint
        )

    def test_setup_session_static_credentials_client_secret_still_works(self):
        # Regression guard: adding cert branches to setup_session must not
        # break the pre-existing client-secret static credentials flow.
        with patch(
            "prowler.providers.azure.azure_provider.ClientSecretCredential"
        ) as mock_secret_cred:
            AzureProvider.setup_session(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=False,
                certificate_path=None,
                tenant_id=self._TENANT_ID,
                azure_credentials={
                    "tenant_id": self._TENANT_ID,
                    "client_id": self._CLIENT_ID,
                    "client_secret": "fake-secret",
                    "certificate_content": None,
                    "certificate_path": None,
                },
                region_config=self._region_config(),
            )
            mock_secret_cred.assert_called_once_with(
                tenant_id=self._TENANT_ID,
                client_id=self._CLIENT_ID,
                client_secret="fake-secret",
                authority=self._region_config().authority,
            )


class TestAzureProviderCertificateThumbprint:
    """Coverage for `_compute_certificate_thumbprint` — the SHA-1 fingerprint
    helper that replaces azure-identity's private `_client_credential` API
    for the identity report."""

    def _self_signed_pem_and_thumbprint(self):
        # Generate a real self-signed cert in-memory so the test verifies the
        # actual thumbprint computation instead of relying on hardcoded values.
        # This mirrors what an openssl-generated cert looks like on disk.
        from datetime import datetime, timedelta, timezone

        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, "prowler-test")]
        )
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .sign(key, hashes.SHA256(), default_backend())
        )
        pem = cert.public_bytes(serialization.Encoding.PEM)
        der = cert.public_bytes(serialization.Encoding.DER)
        thumbprint = cert.fingerprint(hashes.SHA1()).hex().upper()
        return pem, der, key, thumbprint

    def test_computes_thumbprint_from_pem(self):
        from prowler.providers.azure.azure_provider import (
            _compute_certificate_thumbprint,
        )

        pem, _, _, expected = self._self_signed_pem_and_thumbprint()
        assert _compute_certificate_thumbprint(pem) == expected

    def test_computes_thumbprint_from_der(self):
        from prowler.providers.azure.azure_provider import (
            _compute_certificate_thumbprint,
        )

        _, der, _, expected = self._self_signed_pem_and_thumbprint()
        assert _compute_certificate_thumbprint(der) == expected

    def test_computes_thumbprint_from_pfx(self):
        # PowerShell's `Export('Pfx', '')` produces exactly this: PKCS#12 with
        # no password. `azure-identity.CertificateCredential` accepts it, so
        # our helper must recognise it too.
        from cryptography.hazmat.primitives.serialization import pkcs12

        from prowler.providers.azure.azure_provider import (
            _compute_certificate_thumbprint,
        )

        pem, _, key, expected = self._self_signed_pem_and_thumbprint()
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend

        cert = x509.load_pem_x509_certificate(pem, default_backend())
        pfx = pkcs12.serialize_key_and_certificates(
            name=b"prowler",
            key=key,
            cert=cert,
            cas=None,
            encryption_algorithm=serialization_no_encryption(),
        )
        assert _compute_certificate_thumbprint(pfx) == expected

    def test_returns_none_for_garbage_bytes(self):
        from prowler.providers.azure.azure_provider import (
            _compute_certificate_thumbprint,
        )

        assert _compute_certificate_thumbprint(b"definitely not a cert") is None

    def test_returns_none_for_key_only_pkcs12(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.serialization import pkcs12

        from prowler.providers.azure.azure_provider import (
            _compute_certificate_thumbprint,
        )

        _, _, key, _ = self._self_signed_pem_and_thumbprint()
        key_only_pkcs12 = pkcs12.serialize_key_and_certificates(
            name=b"prowler",
            key=key,
            cert=None,
            cas=None,
            encryption_algorithm=serialization.NoEncryption(),
        )

        assert _compute_certificate_thumbprint(key_only_pkcs12) is None


class TestAzureProviderValidateArguments:
    """Coverage for the CLI argument-validation edge cases the code review
    of PROWLER-2378 surfaced (see the SDK PR description for the finding list)."""

    _TENANT_ID = "12345678-1234-1234-1234-123456789012"
    _CLIENT_ID = "87654321-4321-4321-4321-210987654321"

    def test_certificate_path_without_certificate_auth_or_static_trio_fails(
        self, tmp_path
    ):
        # `--browser-auth --certificate-path X` used to parse cleanly and
        # silently drop the certificate in setup_session; now it fails fast.
        with pytest.raises(AzureConfigCredentialsError, match="--certificate-auth"):
            AzureProvider.validate_arguments(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=True,
                managed_identity_auth=False,
                certificate_auth=False,
                tenant_id=self._TENANT_ID,
                client_id=None,
                client_secret=None,
                certificate_content=None,
                certificate_path=str(tmp_path / "prowler-cert.pem"),
            )

    def test_certificate_auth_with_only_tenant_id_does_not_raise(self):
        # Env-var flow: only --certificate-auth (and optionally --tenant-id)
        # on the CLI; tenant_id/client_id/cert come from env at setup_session.
        AzureProvider.validate_arguments(
            az_cli_auth=False,
            sp_env_auth=False,
            browser_auth=False,
            managed_identity_auth=False,
            certificate_auth=True,
            tenant_id=self._TENANT_ID,
            client_id=None,
            client_secret=None,
            certificate_content=None,
            certificate_path=None,
        )

    def test_certificate_auth_with_certificate_path_only_does_not_raise(self, tmp_path):
        # The documented env-var + --certificate-path combination: setup_session
        # reads AZURE_TENANT_ID / AZURE_CLIENT_ID and loads the file from disk.
        AzureProvider.validate_arguments(
            az_cli_auth=False,
            sp_env_auth=False,
            browser_auth=False,
            managed_identity_auth=False,
            certificate_auth=True,
            tenant_id=None,
            client_id=None,
            client_secret=None,
            certificate_content=None,
            certificate_path=str(tmp_path / "prowler-cert.pem"),
        )


class TestAzureProviderSetupSessionCertificateOverrides:
    """Ensure the env-var certificate path prefers explicit args over env vars
    and validates the bundle before instantiating CertificateCredential."""

    _TENANT_ID = "12345678-1234-1234-1234-123456789012"
    _STALE_TENANT_ID = "99999999-9999-9999-9999-999999999999"
    _CLIENT_ID = "87654321-4321-4321-4321-210987654321"

    def _region_config(self):
        return AzureProvider.setup_region_config("AzureCloud")

    def test_explicit_tenant_id_wins_over_env_tenant_id(self, monkeypatch, tmp_path):
        certificate_path = tmp_path / "prowler-cert.pem"
        certificate_path.write_bytes(b"env cert bundle")
        monkeypatch.setenv("AZURE_CLIENT_ID", self._CLIENT_ID)
        monkeypatch.setenv("AZURE_TENANT_ID", self._STALE_TENANT_ID)

        with (
            patch("prowler.providers.azure.azure_provider.validate_certificate_bundle"),
            patch(
                "prowler.providers.azure.azure_provider._build_certificate_credential"
            ) as build_certificate_credential,
        ):
            AzureProvider.setup_session(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=True,
                certificate_path=str(certificate_path),
                tenant_id=self._TENANT_ID,
                azure_credentials=None,
                region_config=self._region_config(),
            )

        _, kwargs = build_certificate_credential.call_args
        assert kwargs["tenant_id"] == self._TENANT_ID

    def test_env_var_branch_validates_bundle_before_building_credential(
        self, monkeypatch, tmp_path
    ):
        # A malformed base64/bundle must raise a certificate-specific error
        # BEFORE CertificateCredential is instantiated so the audit loop
        # never runs against a bad bundle.
        certificate_path = tmp_path / "prowler-cert.pem"
        certificate_path.write_bytes(b"not a real cert bundle")
        monkeypatch.setenv("AZURE_CLIENT_ID", self._CLIENT_ID)
        monkeypatch.setenv("AZURE_TENANT_ID", self._TENANT_ID)

        with (
            patch(
                "prowler.providers.azure.azure_provider._build_certificate_credential"
            ) as build_certificate_credential,
            pytest.raises(AzureNotValidCertificatePathError),
        ):
            AzureProvider.setup_session(
                az_cli_auth=False,
                sp_env_auth=False,
                browser_auth=False,
                managed_identity_auth=False,
                certificate_auth=True,
                certificate_path=str(certificate_path),
                tenant_id=None,
                azure_credentials=None,
                region_config=self._region_config(),
            )

        build_certificate_credential.assert_not_called()


class TestValidateCertificateBundleOrdering:
    """PEM bundles can arrive with the intermediate CA before the leaf. The
    validator must find the certificate that actually pairs with the private
    key instead of trusting the first block."""

    def _self_signed(self):
        from datetime import datetime, timedelta, timezone

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Prowler")])
        certificate = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .sign(private_key, hashes.SHA256())
        )
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return cert_pem, key_pem

    def test_accepts_intermediate_before_leaf(self):
        from prowler.providers.azure.lib.certificate import (
            validate_certificate_bundle,
        )

        leaf_cert_pem, leaf_key_pem = self._self_signed()
        other_cert_pem, _ = self._self_signed()

        bundle = other_cert_pem + leaf_cert_pem + leaf_key_pem

        # No exception: `validate_certificate_bundle` walks every cert block
        # and pairs the private key with the one that actually matches.
        validate_certificate_bundle(bundle)


def serialization_no_encryption():
    # Kept out of the test method so the PKCS#12 test reads cleanly. Wraps
    # the deliberate "no password" export path.
    from cryptography.hazmat.primitives import serialization

    return serialization.NoEncryption()
