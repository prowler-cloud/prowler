from argparse import Namespace

from boto3 import session
from mock import patch

from prowler.providers.aws.lib.audit_info.audit_info import AWS_Audit_Info
from prowler.providers.azure.lib.audit_info.audit_info import (
    Azure_Audit_Info,
    Azure_Identity_Info,
)
from prowler.providers.common.outputs import (
    Aws_Output_Options,
    Azure_Output_Options,
    set_provider_output_options,
)

AWS_ACCOUNT_NUMBER = "012345678912"
DATETIME = "20230101120000"


def mock_change_config_var(*_):
    pass


@patch(
    "prowler.providers.common.outputs.change_config_var",
    new=mock_change_config_var,
)
@patch("prowler.providers.common.outputs.output_file_timestamp", new=DATETIME)
class Test_Common_Output_Options:
    # Mocked Azure Audit Info
    def set_mocked_azure_audit_info(self):
        audit_info = Azure_Audit_Info(
            credentials=None,
            identity=Azure_Identity_Info(),
            audit_metadata=None,
            audit_resources=None,
        )
        return audit_info

    # Mocked AWS Audit Info
    def set_mocked_aws_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    def test_set_provider_output_options_aws(self):
        #  Set the cloud provider
        provider = "aws"
        # Set the arguments passed
        arguments = Namespace()
        arguments.quiet = True
        arguments.output_modes = ["html", "csv", "json"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.output_filename = "output_test_filename"
        arguments.security_hub = True
        arguments.shodan = "test-api-key"
        arguments.only_logs = False

        audit_info = self.set_mocked_aws_audit_info()
        allowlist_file = ""
        bulk_checks_metadata = {}
        output_options = set_provider_output_options(
            provider, arguments, audit_info, allowlist_file, bulk_checks_metadata
        )
        assert isinstance(output_options, Aws_Output_Options)
        assert output_options.security_hub_enabled
        assert output_options.is_quiet
        assert output_options.output_modes == ["html", "csv", "json", "json-asff"]
        assert output_options.output_directory == arguments.output_directory
        assert output_options.allowlist_file == ""
        assert output_options.bulk_checks_metadata == {}
        assert output_options.verbose
        assert output_options.output_filename == arguments.output_filename

    def test_set_provider_output_options_aws_no_output_filename(self):
        #  Set the cloud provider
        provider = "aws"
        # Set the arguments passed
        arguments = Namespace()
        arguments.quiet = True
        arguments.output_modes = ["html", "csv", "json"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.security_hub = True
        arguments.shodan = "test-api-key"
        arguments.only_logs = False

        # Mock AWS Audit Info
        audit_info = self.set_mocked_aws_audit_info()

        allowlist_file = ""
        bulk_checks_metadata = {}
        output_options = set_provider_output_options(
            provider, arguments, audit_info, allowlist_file, bulk_checks_metadata
        )
        assert isinstance(output_options, Aws_Output_Options)
        assert output_options.security_hub_enabled
        assert output_options.is_quiet
        assert output_options.output_modes == ["html", "csv", "json", "json-asff"]
        assert output_options.output_directory == arguments.output_directory
        assert output_options.allowlist_file == ""
        assert output_options.bulk_checks_metadata == {}
        assert output_options.verbose
        assert (
            output_options.output_filename
            == f"prowler-output-{AWS_ACCOUNT_NUMBER}-{DATETIME}"
        )

    def test_set_provider_output_options_azure_domain(self):
        #  Set the cloud provider
        provider = "azure"
        # Set the arguments passed
        arguments = Namespace()
        arguments.quiet = True
        arguments.output_modes = ["html", "csv", "json"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.only_logs = False

        # Mock Azure Audit Info
        audit_info = self.set_mocked_azure_audit_info()
        audit_info.identity.domain = "test-domain"

        allowlist_file = ""
        bulk_checks_metadata = {}
        output_options = set_provider_output_options(
            provider, arguments, audit_info, allowlist_file, bulk_checks_metadata
        )
        assert isinstance(output_options, Azure_Output_Options)
        assert output_options.is_quiet
        assert output_options.output_modes == [
            "html",
            "csv",
            "json",
        ]
        assert output_options.output_directory == arguments.output_directory
        assert output_options.allowlist_file == ""
        assert output_options.bulk_checks_metadata == {}
        assert output_options.verbose
        assert (
            output_options.output_filename
            == f"prowler-output-{audit_info.identity.domain}-{DATETIME}"
        )

    def test_set_provider_output_options_azure_tenant_ids(self):
        #  Set the cloud provider
        provider = "azure"
        # Set the arguments passed
        arguments = Namespace()
        arguments.quiet = True
        arguments.output_modes = ["html", "csv", "json"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.only_logs = False

        # Mock Azure Audit Info
        audit_info = self.set_mocked_azure_audit_info()
        tenants = ["tenant-1", "tenant-2"]
        audit_info.identity.tenant_ids = tenants

        allowlist_file = ""
        bulk_checks_metadata = {}
        output_options = set_provider_output_options(
            provider, arguments, audit_info, allowlist_file, bulk_checks_metadata
        )
        assert isinstance(output_options, Azure_Output_Options)
        assert output_options.is_quiet
        assert output_options.output_modes == [
            "html",
            "csv",
            "json",
        ]
        assert output_options.output_directory == arguments.output_directory
        assert output_options.allowlist_file == ""
        assert output_options.bulk_checks_metadata == {}
        assert output_options.verbose
        assert (
            output_options.output_filename
            == f"prowler-output-{'-'.join(tenants)}-{DATETIME}"
        )
