from argparse import Namespace
from datetime import datetime
from os import rmdir

import pytest
from azure.identity import DefaultAzureCredential
from freezegun import freeze_time
from mock import patch

from prowler.config.config import default_config_file_path
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.models import (
    AzureIdentityInfo,
    AzureOutputOptions,
    AzureRegionConfig,
)


class TestAzureProvider:
    def test_azure_provider(self):
        arguments = Namespace()
        arguments.subscription_ids = None
        arguments.tenant_id = None
        # We need to set exactly one auth method
        arguments.az_cli_auth = True
        arguments.sp_env_auth = None
        arguments.browser_auth = None
        arguments.managed_identity_auth = None

        arguments.config_file = default_config_file_path
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

    def test_zure_provider_not_auth_methods(self):
        arguments = Namespace()
        arguments.subscription_ids = None
        arguments.tenant_id = None
        # We need to set exactly one auth method
        arguments.az_cli_auth = None
        arguments.sp_env_auth = None
        arguments.browser_auth = None
        arguments.managed_identity_auth = None

        arguments.config_file = default_config_file_path
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
        arguments.subscription_ids = None
        arguments.tenant_id = None
        # We need to set exactly one auth method
        arguments.az_cli_auth = None
        arguments.sp_env_auth = None
        arguments.browser_auth = True
        arguments.managed_identity_auth = None

        arguments.config_file = default_config_file_path
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
        arguments.subscription_ids = None
        arguments.tenant_id = "test-tenant-id"
        # We need to set exactly one auth method
        arguments.az_cli_auth = None
        arguments.sp_env_auth = None
        arguments.browser_auth = False
        arguments.managed_identity_auth = None

        arguments.config_file = default_config_file_path
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

    @patch("prowler.config.config.output_file_timestamp", new="20230101120000")
    @freeze_time(datetime.today())
    def test_azure_provider_output_options_with_domain(self):
        arguments = Namespace()
        arguments.subscription_ids = None
        arguments.tenant_id = None

        # We need to set exactly one auth method
        arguments.az_cli_auth = None
        arguments.sp_env_auth = True
        arguments.browser_auth = None
        arguments.managed_identity_auth = None

        arguments.config_file = default_config_file_path
        arguments.azure_region = "AzureCloud"

        # Output Options
        arguments.output_modes = ["csv"]
        arguments.output_directory = "output_test_directory"
        arguments.status = []
        arguments.verbose = True
        arguments.only_logs = False
        arguments.unix_timestamp = False
        arguments.shodan = "test-api-key"
        arguments.mutelist_file = ""

        tenant_domain = "test-domain"
        with patch(
            "prowler.providers.azure.azure_provider.AzureProvider.setup_identity",
            return_value=AzureIdentityInfo(tenant_domain=tenant_domain),
        ), patch(
            "prowler.providers.azure.azure_provider.AzureProvider.get_locations",
            return_value={},
        ):
            azure_provider = AzureProvider(arguments)

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
            # assert azure_provider.output_options.mutelist_file == ""
            assert azure_provider.output_options.bulk_checks_metadata == {}
            assert azure_provider.output_options.verbose
            assert (
                azure_provider.output_options.output_filename
                == f"prowler-output-{azure_provider.identity.tenant_domain}-{datetime.today().strftime('%Y%m%d%H%M%S')}"
            )

            # Delete testing directory
            # TODO: move this to a fixtures file
            rmdir(f"{arguments.output_directory}/compliance")
            rmdir(arguments.output_directory)

    def test_azure_provider_output_options_tenant_ids(self):
        # Output Options
        arguments = Namespace()
        arguments.output_modes = ["csv"]
        arguments.output_directory = "output_test_directory"
        arguments.status = []
        arguments.verbose = True
        arguments.only_logs = False
        arguments.unix_timestamp = False
        arguments.shodan = "test-api-key"
        arguments.mutelist_file = ""

        tenants = ["tenant-1", "tenant-2"]

        azure_output_options = AzureOutputOptions(
            arguments, {}, AzureIdentityInfo(tenant_ids=tenants)
        )

        assert isinstance(azure_output_options, AzureOutputOptions)
        assert azure_output_options.status == []
        assert azure_output_options.output_modes == [
            "csv",
        ]
        assert azure_output_options.output_directory == arguments.output_directory
        # assert azure_provider.output_options.mutelist_file == ""
        assert azure_output_options.bulk_checks_metadata == {}
        assert azure_output_options.verbose
        assert (
            azure_output_options.output_filename
            == f"prowler-output-{'-'.join(tenants)}-{datetime.today().strftime('%Y%m%d%H%M%S')}"
        )

        # Delete testing directory
        # TODO: move this to a fixtures file
        rmdir(f"{arguments.output_directory}/compliance")
        rmdir(arguments.output_directory)
