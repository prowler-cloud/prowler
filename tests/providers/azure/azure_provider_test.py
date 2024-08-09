from argparse import Namespace
from datetime import datetime
from os import rmdir
from unittest.mock import patch

import pytest
from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential
from freezegun import freeze_time

from prowler.config.config import (
    default_config_file_path,
    default_fixer_config_file_path,
)
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.models import (
    AzureIdentityInfo,
    AzureOutputOptions,
    AzureRegionConfig,
)
from prowler.providers.common.models import Connection


class TestAzureProvider:
    def test_azure_provider(self):
        arguments = Namespace()
        arguments.subscription_id = None
        arguments.tenant_id = None
        # We need to set exactly one auth method
        arguments.az_cli_auth = True
        arguments.sp_env_auth = None
        arguments.browser_auth = None
        arguments.managed_identity_auth = None

        arguments.config_file = default_config_file_path
        arguments.fixer_config = default_fixer_config_file_path
        arguments.azure_region = "AzureCloud"

        with patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_identity",
            return_value=AzureIdentityInfo(),
        ), patch(
            "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
            return_value={},
        ):
            azure_provider = AzureProvider(arguments)

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
        arguments = Namespace()
        arguments.subscription_id = None
        arguments.tenant_id = None
        # We need to set exactly one auth method
        arguments.az_cli_auth = None
        arguments.sp_env_auth = None
        arguments.browser_auth = None
        arguments.managed_identity_auth = None

        arguments.config_file = default_config_file_path
        arguments.fixer_config = default_fixer_config_file_path
        arguments.azure_region = "AzureCloud"

        with patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_identity",
            return_value=AzureIdentityInfo(),
        ), patch(
            "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
            return_value={},
        ):

            with pytest.raises(SystemExit) as exception:
                _ = AzureProvider(arguments)
            assert exception.type == SystemExit
            assert (
                exception.value.args[0]
                == "Azure provider requires at least one authentication method set: [--az-cli-auth | --sp-env-auth | --browser-auth | --managed-identity-auth]"
            )

    def test_azure_provider_browser_auth_but_not_tenant_id(self):
        arguments = Namespace()
        arguments.subscription_id = None
        arguments.tenant_id = None
        # We need to set exactly one auth method
        arguments.az_cli_auth = None
        arguments.sp_env_auth = None
        arguments.browser_auth = True
        arguments.managed_identity_auth = None

        arguments.config_file = default_config_file_path
        arguments.fixer_config = default_fixer_config_file_path
        arguments.azure_region = "AzureCloud"

        with patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_identity",
            return_value=AzureIdentityInfo(),
        ), patch(
            "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
            return_value={},
        ):

            with pytest.raises(SystemExit) as exception:
                _ = AzureProvider(arguments)
            assert exception.type == SystemExit
            assert (
                exception.value.args[0]
                == "Azure Tenant ID (--tenant-id) is required for browser authentication mode"
            )

    def test_azure_provider_not_browser_auth_but_tenant_id(self):
        arguments = Namespace()
        arguments.subscription_id = None
        arguments.tenant_id = "test-tenant-id"
        # We need to set exactly one auth method
        arguments.az_cli_auth = None
        arguments.sp_env_auth = None
        arguments.browser_auth = False
        arguments.managed_identity_auth = None

        arguments.config_file = default_config_file_path
        arguments.fixer_config = default_fixer_config_file_path
        arguments.azure_region = "AzureCloud"

        with patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_identity",
            return_value=AzureIdentityInfo(),
        ), patch(
            "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
            return_value={},
        ):

            with pytest.raises(SystemExit) as exception:
                _ = AzureProvider(arguments)
            assert exception.type == SystemExit
            assert (
                exception.value.args[0]
                == "Azure provider requires at least one authentication method set: [--az-cli-auth | --sp-env-auth | --browser-auth | --managed-identity-auth]"
            )

    @freeze_time(datetime.today())
    def test_azure_provider_output_options_with_domain(self):
        arguments = Namespace()
        arguments.subscription_id = None
        arguments.tenant_id = None

        # We need to set exactly one auth method
        arguments.az_cli_auth = None
        arguments.sp_env_auth = True
        arguments.browser_auth = None
        arguments.managed_identity_auth = None

        arguments.config_file = default_config_file_path
        arguments.fixer_config = default_fixer_config_file_path
        arguments.azure_region = "AzureCloud"

        # Output Options
        arguments.output_formats = ["csv"]
        arguments.output_directory = "output_test_directory"
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
            azure_provider = AzureProvider(arguments)
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
                    azure_provider.output_options.output_directory
                    == arguments.output_directory
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

    def test_test_connection(self):
        arguments = Namespace()
        arguments.subscription_id = None
        arguments.tenant_id = "test-tenant-id"
        # We need to set exactly one auth method
        arguments.az_cli_auth = False
        arguments.sp_env_auth = False
        arguments.browser_auth = True
        arguments.managed_identity_auth = None

        arguments.config_file = default_config_file_path
        arguments.fixer_config = default_fixer_config_file_path
        arguments.azure_region = "AzureCloud"

        with patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_identity",
            return_value=AzureIdentityInfo(),
        ), patch(
            "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
            return_value={},
        ), patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_session"
        ) as mock_setup_session:

            mock_setup_session.return_value = DefaultAzureCredential()
            # We need to set exactly one auth method
            test_connection = AzureProvider.test_connection(
                arguments.az_cli_auth,
                arguments.sp_env_auth,
                arguments.browser_auth,
                arguments.managed_identity_auth,
                arguments.tenant_id,
                arguments.azure_region,
                raise_exception=True,
            )

            assert isinstance(test_connection, Connection)
            assert test_connection.is_connected
            assert test_connection.error is None

    def test_test_connection_with_httpresponseerror(self):
        arguments = Namespace()
        arguments.subscription_id = None
        arguments.tenant_id = None
        # We need to set exactly one auth method
        arguments.az_cli_auth = None
        arguments.sp_env_auth = True
        arguments.browser_auth = None
        arguments.managed_identity_auth = None

        arguments.config_file = default_config_file_path
        arguments.fixer_config = default_fixer_config_file_path
        arguments.azure_region = "AzureCloud"

        with patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_identity",
            return_value=AzureIdentityInfo(),
        ), patch(
            "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
            return_value={},
        ), patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_session"
        ) as mock_setup_session, patch(
            "prowler.providers.azure.azure_provider.logger"
        ) as mock_logger:

            mock_setup_session.side_effect = HttpResponseError(
                "Simulated HttpResponseError"
            )

            with pytest.raises(HttpResponseError) as excinfo:
                AzureProvider.test_connection(
                    arguments.az_cli_auth,
                    arguments.sp_env_auth,
                    arguments.browser_auth,
                    arguments.managed_identity_auth,
                    arguments.tenant_id,
                    arguments.azure_region,
                    raise_exception=True,
                )

            assert excinfo.type == HttpResponseError
            assert str(excinfo.value) == "Simulated HttpResponseError"

            mock_setup_session.assert_called_once_with(
                arguments.az_cli_auth,
                arguments.sp_env_auth,
                arguments.browser_auth,
                arguments.managed_identity_auth,
                arguments.tenant_id,
                AzureRegionConfig(
                    name=arguments.azure_region,
                    authority=None,
                    base_url="https://management.azure.com",
                    credential_scopes=["https://management.azure.com/.default"],
                ),
            )

            mock_logger.error.assert_called_once_with(
                "HttpResponseError[418]: Simulated HttpResponseError"
            )

    def test_test_connection_with_exception(self):
        arguments = Namespace()
        arguments.subscription_id = None
        arguments.tenant_id = None
        # We need to set exactly one auth method
        arguments.az_cli_auth = None
        arguments.sp_env_auth = True
        arguments.browser_auth = None
        arguments.managed_identity_auth = None

        arguments.config_file = default_config_file_path
        arguments.fixer_config = default_fixer_config_file_path
        arguments.azure_region = "AzureCloud"

        with patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_identity",
            return_value=AzureIdentityInfo(),
        ), patch(
            "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
            return_value={},
        ), patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_session"
        ) as mock_setup_session, patch(
            "prowler.providers.azure.azure_provider.logger"
        ) as mock_logger:

            mock_setup_session.side_effect = Exception("Simulated Exception")

            with pytest.raises(Exception) as excinfo:
                AzureProvider.test_connection(
                    arguments.az_cli_auth,
                    arguments.sp_env_auth,
                    arguments.browser_auth,
                    arguments.managed_identity_auth,
                    arguments.tenant_id,
                    arguments.azure_region,
                    raise_exception=True,
                )

            assert excinfo.type == Exception
            assert str(excinfo.value) == "Simulated Exception"

            mock_setup_session.assert_called_once_with(
                arguments.az_cli_auth,
                arguments.sp_env_auth,
                arguments.browser_auth,
                arguments.managed_identity_auth,
                arguments.tenant_id,
                AzureRegionConfig(
                    name=arguments.azure_region,
                    authority=None,
                    base_url="https://management.azure.com",
                    credential_scopes=["https://management.azure.com/.default"],
                ),
            )

            mock_logger.critical.assert_called_once_with(
                "Exception[418]: Simulated Exception"
            )
