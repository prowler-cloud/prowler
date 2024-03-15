import pytest
from azure.identity import DefaultAzureCredential
from mock import MagicMock, patch

from prowler.config.config import default_config_file_path
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.models import AzureIdentityInfo, AzureRegionConfig


def mock_set_identity_info(*_):
    return AzureIdentityInfo()


def mock_set_azure_credentials(*_):
    return {}


class TestAzureProvider:
    def test_azure_provider(self):
        arguments = MagicMock
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
        arguments = MagicMock
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
        arguments = MagicMock
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
        arguments = MagicMock
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

    # def test_set_provider_output_options_azure_domain(self):
    #     #  Set the cloud provider
    #     provider = "azure"
    #     # Set the arguments passed
    #     arguments = Namespace()
    #     arguments.quiet = True
    #     arguments.output_modes = ["csv"]
    #     arguments.output_directory = "output_test_directory"
    #     arguments.verbose = True
    #     arguments.only_logs = False
    #     arguments.unix_timestamp = False
    #     arguments.shodan = "test-api-key"

    #     # Mock Azure Audit Info
    #     audit_info = self.set_mocked_azure_audit_info()
    #     audit_info.identity.tenant_domain = "test-domain"

    #     mutelist_file = ""
    #     bulk_checks_metadata = {}
    #     output_options = set_provider_output_options(
    #         provider, arguments, audit_info, mutelist_file, bulk_checks_metadata
    #     )
    #     assert isinstance(output_options, Azure_Output_Options)
    #     assert output_options.is_quiet
    #     assert output_options.output_modes == [
    #         "csv",
    #     ]
    #     assert output_options.output_directory == arguments.output_directory
    #     assert output_options.mutelist_file == ""
    #     assert output_options.bulk_checks_metadata == {}
    #     assert output_options.verbose
    #     assert (
    #         output_options.output_filename
    #         == f"prowler-output-{audit_info.identity.tenant_domain}-{DATETIME}"
    #     )

    #     # Delete testing directory
    #     rmdir(arguments.output_directory)

    # def test_set_provider_output_options_azure_tenant_ids(self):
    #     #  Set the cloud provider
    #     provider = "azure"
    #     # Set the arguments passed
    #     arguments = Namespace()
    #     arguments.quiet = True
    #     arguments.output_modes = ["csv"]
    #     arguments.output_directory = "output_test_directory"
    #     arguments.verbose = True
    #     arguments.only_logs = False
    #     arguments.unix_timestamp = False
    #     arguments.shodan = "test-api-key"

    #     # Mock Azure Audit Info
    #     audit_info = self.set_mocked_azure_audit_info()
    #     tenants = ["tenant-1", "tenant-2"]
    #     audit_info.identity.tenant_ids = tenants

    #     mutelist_file = ""
    #     bulk_checks_metadata = {}
    #     output_options = set_provider_output_options(
    #         provider, arguments, audit_info, mutelist_file, bulk_checks_metadata
    #     )
    #     assert isinstance(output_options, Azure_Output_Options)
    #     assert output_options.is_quiet
    #     assert output_options.output_modes == [
    #         "csv",
    #     ]
    #     assert output_options.output_directory == arguments.output_directory
    #     assert output_options.mutelist_file == ""
    #     assert output_options.bulk_checks_metadata == {}
    #     assert output_options.verbose
    #     assert (
    #         output_options.output_filename
    #         == f"prowler-output-{'-'.join(tenants)}-{DATETIME}"
    #     )

    #     # Delete testing directory
    #     rmdir(arguments.output_directory)
