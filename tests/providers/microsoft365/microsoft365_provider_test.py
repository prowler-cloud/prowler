from unittest.mock import patch
from uuid import uuid4

import pytest
from azure.core.credentials import AccessToken
from azure.identity import DefaultAzureCredential
from mock import MagicMock

from prowler.config.config import (
    default_config_file_path,
    default_fixer_config_file_path,
    load_and_validate_config_file,
)
from prowler.providers.common.models import Connection
from prowler.providers.microsoft365.exceptions.exceptions import (
    Microsoft365HTTPResponseError,
    Microsoft365InvalidProviderIdError,
    Microsoft365NoAuthenticationMethodError,
)
from prowler.providers.microsoft365.microsoft365_provider import Microsoft365Provider
from prowler.providers.microsoft365.models import (
    Microsoft365IdentityInfo,
    Microsoft365RegionConfig,
)


class TestMicrosoft365Provider:
    def test_microsoft365_provider(self):
        tenant_id = None
        client_id = None
        client_secret = None

        fixer_config = load_and_validate_config_file(
            "microsoft365", default_fixer_config_file_path
        )
        azure_region = "AzureCloud"

        with patch(
            "prowler.providers.microsoft365.microsoft365_provider.Microsoft365Provider.setup_identity",
            return_value=Microsoft365IdentityInfo(),
        ):
            microsoft365_provider = Microsoft365Provider(
                tenant_id,
                azure_region,
                config_path=default_config_file_path,
                fixer_config=fixer_config,
                client_id=client_id,
                client_secret=client_secret,
            )

            assert microsoft365_provider.region_config == Microsoft365RegionConfig(
                name="AzureCloud",
                authority=None,
                base_url="https://management.azure.com",
                credential_scopes=["https://management.azure.com/.default"],
            )
            assert isinstance(microsoft365_provider.session, DefaultAzureCredential)
            assert microsoft365_provider.identity == Microsoft365IdentityInfo(
                identity_id="",
                identity_type="",
                tenant_id="",
                tenant_domain="Unknown tenant domain (missing AAD permissions)",
            )
            assert microsoft365_provider.audit_config == {
                "shodan_api_key": None,
                "php_latest_version": "8.2",
                "python_latest_version": "3.12",
                "java_latest_version": "17",
            }

    def test_test_connection_tenant_id_client_id_client_secret(self):
        with patch(
            "prowler.providers.microsoft365.microsoft365_provider.DefaultAzureCredential"
        ) as mock_default_credential, patch(
            "prowler.providers.microsoft365.microsoft365_provider.Microsoft365Provider.setup_session"
        ) as mock_setup_session, patch(
            "prowler.providers.microsoft365.microsoft365_provider.SubscriptionClient"
        ) as mock_resource_client, patch(
            "prowler.providers.microsoft365.microsoft365_provider.Microsoft365Provider.validate_static_credentials"
        ) as mock_validate_static_credentials:

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

            test_connection = Microsoft365Provider.test_connection(
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
        with patch(
            "prowler.providers.microsoft365.microsoft365_provider.DefaultAzureCredential"
        ) as mock_default_credential, patch(
            "prowler.providers.microsoft365.microsoft365_provider.Microsoft365Provider.setup_session"
        ) as mock_setup_session, patch(
            "prowler.providers.microsoft365.microsoft365_provider.SubscriptionClient"
        ) as mock_resource_client, patch(
            "prowler.providers.microsoft365.microsoft365_provider.Microsoft365Provider.validate_static_credentials"
        ) as mock_validate_static_credentials:

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

            test_connection = Microsoft365Provider.test_connection(
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
        with patch(
            "prowler.providers.microsoft365.microsoft365_provider.DefaultAzureCredential"
        ) as mock_default_credential, patch(
            "prowler.providers.microsoft365.microsoft365_provider.Microsoft365Provider.setup_session"
        ) as mock_setup_session, patch(
            "prowler.providers.microsoft365.microsoft365_provider.SubscriptionClient"
        ) as mock_resource_client, patch(
            "prowler.providers.microsoft365.microsoft365_provider.Microsoft365Provider.validate_static_credentials"
        ) as mock_validate_static_credentials:

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

            test_connection = Microsoft365Provider.test_connection(
                browser_auth=False,
                tenant_id=str(uuid4()),
                region="AzureCloud",
                raise_on_exception=False,
                client_id=str(uuid4()),
                client_secret=str(uuid4()),
                provider_id="test_provider_id",
            )

            assert test_connection.error is not None
            assert isinstance(test_connection.error, Microsoft365InvalidProviderIdError)
            assert (
                "The provided credentials are not valid for the specified Microsoft365 subscription."
                in test_connection.error.args[0]
            )

    def test_test_connection_with_ClientAuthenticationError(self):
        with pytest.raises(Microsoft365HTTPResponseError) as exception:
            tenant_id = str(uuid4())
            Microsoft365Provider.test_connection(
                browser_auth=True,
                tenant_id=tenant_id,
                region="AzureCloud",
            )

        assert exception.type == Microsoft365HTTPResponseError
        assert (
            exception.value.args[0]
            == f"[2010] Error in HTTP response from Microsoft365 - Authentication failed: Unable to get authority configuration for https://login.microsoftonline.com/{tenant_id}. Authority would typically be in a format of https://login.microsoftonline.com/your_tenant or https://tenant_name.ciamlogin.com or https://tenant_name.b2clogin.com/tenant.onmicrosoft.com/policy.  Also please double check your tenant name or GUID is correct."
        )

    def test_test_connection_without_any_method(self):
        with pytest.raises(Microsoft365NoAuthenticationMethodError) as exception:
            Microsoft365Provider.test_connection()

        assert exception.type == Microsoft365NoAuthenticationMethodError
        assert (
            "[2003] Microsoft365 provider requires at least one authentication method set: [--az-cli-auth | --sp-env-auth | --browser-auth | --managed-identity-auth]"
            in exception.value.args[0]
        )

    def test_test_connection_with_httpresponseerror(self):
        with patch(
            "prowler.providers.microsoft365.microsoft365_provider.Microsoft365Provider.get_locations",
            return_value={},
        ), patch(
            "prowler.providers.microsoft365.microsoft365_provider.Microsoft365Provider.setup_session"
        ) as mock_setup_session:

            mock_setup_session.side_effect = Microsoft365HTTPResponseError(
                file="test_file", original_exception="Simulated HttpResponseError"
            )

            with pytest.raises(Microsoft365HTTPResponseError) as exception:
                Microsoft365Provider.test_connection(
                    az_cli_auth=True,
                    raise_on_exception=True,
                )

            assert exception.type == Microsoft365HTTPResponseError
            assert (
                exception.value.args[0]
                == "[2010] Error in HTTP response from Microsoft365 - Simulated HttpResponseError"
            )

    def test_test_connection_with_exception(self):
        with patch(
            "prowler.providers.microsoft365.microsoft365_provider.Microsoft365Provider.setup_session"
        ) as mock_setup_session:

            mock_setup_session.side_effect = Exception("Simulated Exception")

            with pytest.raises(Exception) as exception:
                Microsoft365Provider.test_connection(
                    sp_env_auth=True,
                    raise_on_exception=True,
                )

            assert exception.type == Exception
            assert exception.value.args[0] == "Simulated Exception"
