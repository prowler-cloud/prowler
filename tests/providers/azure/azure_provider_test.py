from unittest.mock import patch
from uuid import uuid4

import pytest
from azure.core.credentials import AccessToken
from azure.core.exceptions import HttpResponseError
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
    AzureHTTPResponseError,
    AzureInvalidProviderIdError,
    AzureNoAuthenticationMethodError,
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
                "Azure provider requires at least one authentication method set: [--az-cli-auth | --sp-env-auth | --browser-auth | --managed-identity-auth]"
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
            "[2003] Azure provider requires at least one authentication method set: [--az-cli-auth | --sp-env-auth | --browser-auth | --managed-identity-auth]"
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

        assert config == AzureRegionConfig(
            name=region,
            authority=authority,
            base_url=base_url,
            credential_scopes=credential_scopes,
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
