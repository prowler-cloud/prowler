from argparse import Namespace
from datetime import datetime
from os import rmdir
from unittest.mock import patch
from uuid import uuid4

import pytest
from azure.core.credentials import AccessToken
from azure.identity import DefaultAzureCredential
from freezegun import freeze_time
from mock import MagicMock

from prowler.config.config import (
    default_config_file_path,
    default_fixer_config_file_path,
)
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.exceptions.exceptions import (
    AzureBrowserAuthNoTenantIDError,
    AzureHTTPResponseError,
    AzureNoAuthenticationMethodError,
    AzureTenantIDNoBrowserAuthError,
)
from prowler.providers.azure.models import (
    AzureIdentityInfo,
    AzureOutputOptions,
    AzureRegionConfig,
)
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

        config_file = default_config_file_path
        fixer_config = default_fixer_config_file_path
        azure_region = "AzureCloud"

        with patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_identity",
            return_value=AzureIdentityInfo(),
        ), patch(
            "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
            return_value={},
        ):
            azure_provider = AzureProvider(
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

        with patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_identity",
            return_value=AzureIdentityInfo(),
        ), patch(
            "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
            return_value={},
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

        with patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_identity",
            return_value=AzureIdentityInfo(),
        ), patch(
            "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
            return_value={},
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
                == "[1918] Azure Tenant ID (--tenant-id) is required for browser authentication mode"
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

        with patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_identity",
            return_value=AzureIdentityInfo(),
        ), patch(
            "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
            return_value={},
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
                == "[1919] Azure Tenant ID (--tenant-id) is required for browser authentication mode"
            )

    @freeze_time(datetime.today())
    def test_azure_provider_output_options_with_domain(self):
        arguments = Namespace()
        subscription_id = None
        tenant_id = None

        # We need to set exactly one auth method
        az_cli_auth = None
        sp_env_auth = True
        browser_auth = None
        managed_identity_auth = None

        config_file = default_config_file_path
        fixer_config = default_fixer_config_file_path
        azure_region = "AzureCloud"

        # Output Options
        arguments.output_formats = ["csv"]
        arguments.output_directory = "output_test_directory"
        output_directory = arguments.output_directory
        arguments.status = []
        arguments.verbose = True
        arguments.only_logs = False
        arguments.unix_timestamp = False
        arguments.shodan = "test-api-key"

        tenant_domain = "test-domain"
        with patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_identity",
            return_value=AzureIdentityInfo(tenant_domain=tenant_domain),
        ), patch(
            "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
            return_value={},
        ), patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_session",
            return_value=DefaultAzureCredential(),
        ):
            azure_provider = AzureProvider(
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
            # This is needed since the output_options requires to get the global provider to get the audit config
            with patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=azure_provider,
            ):

                azure_provider.output_options = arguments, {}

                assert isinstance(azure_provider.output_options, AzureOutputOptions)
                assert azure_provider.output_options.status == []
                assert azure_provider.output_options.output_modes == [
                    "csv",
                ]
                assert (
                    azure_provider.output_options.output_directory == output_directory
                )
                assert azure_provider.output_options.bulk_checks_metadata == {}
                assert azure_provider.output_options.verbose
                # Flaky due to the millisecond part of the timestamp
                # assert (
                #     azure_provider.output_options.output_filename
                #     == f"prowler-output-{azure_provider.identity.tenant_domain}-{datetime.today().strftime('%Y%m%d%H%M%S')}"
                # )
                assert (
                    f"prowler-output-{azure_provider.identity.tenant_domain}"
                    in azure_provider.output_options.output_filename
                )

                # Delete testing directory
                # TODO: move this to a fixtures file
                rmdir(f"{arguments.output_directory}/compliance")
                rmdir(arguments.output_directory)

    def test_test_connection_browser_auth(self):
        with patch(
            "prowler.providers.azure.azure_provider.DefaultAzureCredential"
        ) as mock_default_credential, patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_session"
        ) as mock_setup_session, patch(
            "prowler.providers.azure.azure_provider.SubscriptionClient"
        ) as mock_resource_client:

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

    def test_test_connection_with_ClientAuthenticationError(self):
        with pytest.raises(AzureHTTPResponseError) as exception:
            tenant_id = str(uuid4())
            AzureProvider.test_connection(
                browser_auth=True,
                tenant_id=tenant_id,
                region="AzureCloud",
            )

        assert exception.type == AzureHTTPResponseError
        assert (
            exception.value.args[0]
            == f"[1924] Error in HTTP response from Azure - Authentication failed: Unable to get authority configuration for https://login.microsoftonline.com/{tenant_id}. Authority would typically be in a format of https://login.microsoftonline.com/your_tenant or https://tenant_name.ciamlogin.com or https://tenant_name.b2clogin.com/tenant.onmicrosoft.com/policy.  Also please double check your tenant name or GUID is correct."
        )

    def test_test_connection_without_any_method(self):
        with pytest.raises(AzureNoAuthenticationMethodError) as exception:
            AzureProvider.test_connection()

        assert exception.type == AzureNoAuthenticationMethodError
        assert (
            "[1917] Azure provider requires at least one authentication method set: [--az-cli-auth | --sp-env-auth | --browser-auth | --managed-identity-auth]"
            in exception.value.args[0]
        )

    def test_test_connection_with_httpresponseerror(self):
        with patch(
            "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
            return_value={},
        ), patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_session"
        ) as mock_setup_session:

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
                == "[1924] Error in HTTP response from Azure - Simulated HttpResponseError"
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

            assert exception.type == Exception
            assert exception.value.args[0] == "Simulated Exception"
