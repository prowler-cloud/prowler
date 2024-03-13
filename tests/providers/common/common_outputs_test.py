from argparse import Namespace
from os import rmdir

from mock import patch

from prowler.providers.azure.lib.audit_info.audit_info import (
    Azure_Audit_Info,
    AzureIdentityInfo,
    AzureRegionConfig,
)
from prowler.providers.common.outputs import (
    Aws_Output_Options,
    Azure_Output_Options,
    Gcp_Output_Options,
    Kubernetes_Output_Options,
    set_provider_output_options,
)
from prowler.providers.gcp.lib.audit_info.models import GCP_Audit_Info
from prowler.providers.kubernetes.lib.audit_info.models import Kubernetes_Audit_Info

AWS_ACCOUNT_NUMBER = "012345678912"
DATETIME = "20230101120000"


@patch("prowler.providers.common.outputs.output_file_timestamp", new=DATETIME)
class Test_Common_Output_Options:
    # Mocked Azure Audit Info
    def set_mocked_azure_audit_info(self):
        audit_info = Azure_Audit_Info(
            credentials=None,
            identity=AzureIdentityInfo(),
            audit_metadata=None,
            audit_resources=None,
            audit_config=None,
            azure_region_config=AzureRegionConfig(),
            locations=None,
        )
        return audit_info

    # Mocked GCP Audit Info
    def set_mocked_gcp_audit_info(self):
        audit_info = GCP_Audit_Info(
            credentials=None,
            default_project_id="test-project1",
            project_ids=["test-project1", "test-project2"],
            audit_resources=None,
            audit_metadata=None,
            audit_config=None,
        )
        return audit_info

    # Mocked Kusbernete Audit Info
    def set_mocked_kubernetes_audit_info(self):
        audit_info = Kubernetes_Audit_Info(
            api_client=None,
            context={
                "name": "test-context",
                "context": {"cluster": "test-cluster", "user": "XXXXXXXXX"},
            },
            audit_resources=None,
            audit_metadata=None,
            audit_config=None,
        )
        return audit_info

    def test_set_provider_output_options_aws(self):
        #  Set the cloud provider
        provider = "aws"
        # Set the arguments passed
        arguments = Namespace()
        arguments.quiet = True
        arguments.output_modes = ["csv", "json"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.output_filename = "output_test_filename"
        arguments.security_hub = True
        arguments.shodan = "test-api-key"
        arguments.only_logs = False
        arguments.unix_timestamp = False
        arguments.send_sh_only_fails = True

        audit_info = self.set_mocked_aws_audit_info()
        mutelist_file = ""
        bulk_checks_metadata = {}
        output_options = set_provider_output_options(
            provider, arguments, audit_info, mutelist_file, bulk_checks_metadata
        )
        assert isinstance(output_options, Aws_Output_Options)
        assert output_options.security_hub_enabled
        assert output_options.send_sh_only_fails
        assert output_options.is_quiet
        assert output_options.output_modes == ["csv", "json", "json-asff"]
        assert output_options.output_directory == arguments.output_directory
        assert output_options.mutelist_file == ""
        assert output_options.bulk_checks_metadata == {}
        assert output_options.verbose
        assert output_options.output_filename == arguments.output_filename

        # Delete testing directory
        rmdir(arguments.output_directory)

    def test_set_provider_output_options_gcp(self):
        #  Set the cloud provider
        provider = "gcp"
        # Set the arguments passed
        arguments = Namespace()
        arguments.quiet = True
        arguments.output_modes = ["csv", "json"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.output_filename = "output_test_filename"
        arguments.only_logs = False
        arguments.unix_timestamp = False

        audit_info = self.set_mocked_gcp_audit_info()
        mutelist_file = ""
        bulk_checks_metadata = {}
        output_options = set_provider_output_options(
            provider, arguments, audit_info, mutelist_file, bulk_checks_metadata
        )
        assert isinstance(output_options, Gcp_Output_Options)
        assert output_options.is_quiet
        assert output_options.output_modes == ["csv", "json"]
        assert output_options.output_directory == arguments.output_directory
        assert output_options.mutelist_file == ""
        assert output_options.bulk_checks_metadata == {}
        assert output_options.verbose
        assert output_options.output_filename == arguments.output_filename

        # Delete testing directory
        rmdir(arguments.output_directory)

    def test_set_provider_output_options_kubernetes(self):
        #  Set the cloud provider
        provider = "kubernetes"
        # Set the arguments passed
        arguments = Namespace()
        arguments.quiet = True
        arguments.output_modes = ["csv", "json"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.output_filename = "output_test_filename"
        arguments.only_logs = False
        arguments.unix_timestamp = False

        audit_info = self.set_mocked_kubernetes_audit_info()
        mutelist_file = ""
        bulk_checks_metadata = {}
        output_options = set_provider_output_options(
            provider, arguments, audit_info, mutelist_file, bulk_checks_metadata
        )
        assert isinstance(output_options, Kubernetes_Output_Options)
        assert output_options.is_quiet
        assert output_options.output_modes == ["csv", "json"]
        assert output_options.output_directory == arguments.output_directory
        assert output_options.mutelist_file == ""
        assert output_options.bulk_checks_metadata == {}
        assert output_options.verbose
        assert output_options.output_filename == arguments.output_filename

        # Delete testing directory
        rmdir(arguments.output_directory)

    def test_set_provider_output_options_aws_no_output_filename(self):
        #  Set the cloud provider
        provider = "aws"
        # Set the arguments passed
        arguments = Namespace()
        arguments.quiet = True
        arguments.output_modes = ["csv", "json"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.security_hub = True
        arguments.shodan = "test-api-key"
        arguments.only_logs = False
        arguments.unix_timestamp = False
        arguments.send_sh_only_fails = True

        # Mock AWS Audit Info
        audit_info = self.set_mocked_aws_audit_info()

        mutelist_file = ""
        bulk_checks_metadata = {}
        output_options = set_provider_output_options(
            provider, arguments, audit_info, mutelist_file, bulk_checks_metadata
        )
        assert isinstance(output_options, Aws_Output_Options)
        assert output_options.security_hub_enabled
        assert output_options.send_sh_only_fails
        assert output_options.is_quiet
        assert output_options.output_modes == ["csv", "json", "json-asff"]
        assert output_options.output_directory == arguments.output_directory
        assert output_options.mutelist_file == ""
        assert output_options.bulk_checks_metadata == {}
        assert output_options.verbose
        assert (
            output_options.output_filename
            == f"prowler-output-{AWS_ACCOUNT_NUMBER}-{DATETIME}"
        )

        # Delete testing directory
        rmdir(arguments.output_directory)

    def test_set_provider_output_options_azure_domain(self):
        #  Set the cloud provider
        provider = "azure"
        # Set the arguments passed
        arguments = Namespace()
        arguments.quiet = True
        arguments.output_modes = ["csv", "json"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.only_logs = False
        arguments.unix_timestamp = False
        arguments.shodan = "test-api-key"

        # Mock Azure Audit Info
        audit_info = self.set_mocked_azure_audit_info()
        audit_info.identity.tenant_domain = "test-domain"

        mutelist_file = ""
        bulk_checks_metadata = {}
        output_options = set_provider_output_options(
            provider, arguments, audit_info, mutelist_file, bulk_checks_metadata
        )
        assert isinstance(output_options, Azure_Output_Options)
        assert output_options.is_quiet
        assert output_options.output_modes == [
            "csv",
            "json",
        ]
        assert output_options.output_directory == arguments.output_directory
        assert output_options.mutelist_file == ""
        assert output_options.bulk_checks_metadata == {}
        assert output_options.verbose
        assert (
            output_options.output_filename
            == f"prowler-output-{audit_info.identity.tenant_domain}-{DATETIME}"
        )

        # Delete testing directory
        rmdir(arguments.output_directory)

    def test_set_provider_output_options_azure_tenant_ids(self):
        #  Set the cloud provider
        provider = "azure"
        # Set the arguments passed
        arguments = Namespace()
        arguments.quiet = True
        arguments.output_modes = ["csv", "json"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.only_logs = False
        arguments.unix_timestamp = False
        arguments.shodan = "test-api-key"

        # Mock Azure Audit Info
        audit_info = self.set_mocked_azure_audit_info()
        tenants = ["tenant-1", "tenant-2"]
        audit_info.identity.tenant_ids = tenants

        mutelist_file = ""
        bulk_checks_metadata = {}
        output_options = set_provider_output_options(
            provider, arguments, audit_info, mutelist_file, bulk_checks_metadata
        )
        assert isinstance(output_options, Azure_Output_Options)
        assert output_options.is_quiet
        assert output_options.output_modes == [
            "csv",
            "json",
        ]
        assert output_options.output_directory == arguments.output_directory
        assert output_options.mutelist_file == ""
        assert output_options.bulk_checks_metadata == {}
        assert output_options.verbose
        assert (
            output_options.output_filename
            == f"prowler-output-{'-'.join(tenants)}-{DATETIME}"
        )

        # Delete testing directory
        rmdir(arguments.output_directory)
