from argparse import Namespace

from boto3 import session
from mock import patch

from prowler.lib.outputs.html import get_assessment_summary
from prowler.providers.aws.lib.audit_info.audit_info import AWS_Audit_Info
from prowler.providers.azure.lib.audit_info.audit_info import (
    Azure_Audit_Info,
    Azure_Identity_Info,
)
from prowler.providers.common.outputs import (
    Aws_Output_Options,
    Azure_Output_Options,
    Gcp_Output_Options,
    set_provider_output_options,
)
from prowler.providers.gcp.lib.audit_info.models import GCP_Audit_Info

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
            mfa_enabled=False,
        )
        return audit_info

    # Mocked GCP Audit Info
    def set_mocked_gcp_audit_info(self):
        audit_info = GCP_Audit_Info(
            credentials=None,
            default_project_id="test-project1",
            project_ids=["test-project1", "test-project2"],
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=None,
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
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id="test-user",
            audited_partition="aws",
            audited_identity_arn="test-user-arn",
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
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

    def test_set_provider_output_options_gcp(self):
        #  Set the cloud provider
        provider = "gcp"
        # Set the arguments passed
        arguments = Namespace()
        arguments.quiet = True
        arguments.output_modes = ["html", "csv", "json"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.output_filename = "output_test_filename"
        arguments.only_logs = False

        audit_info = self.set_mocked_gcp_audit_info()
        allowlist_file = ""
        bulk_checks_metadata = {}
        output_options = set_provider_output_options(
            provider, arguments, audit_info, allowlist_file, bulk_checks_metadata
        )
        assert isinstance(output_options, Gcp_Output_Options)
        assert output_options.is_quiet
        assert output_options.output_modes == ["html", "csv", "json"]
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

    def test_azure_get_assessment_summary(self):
        # Mock Azure Audit Info
        audit_info = self.set_mocked_azure_audit_info()
        tenants = ["tenant-1", "tenant-2"]
        audit_info.identity.tenant_ids = tenants
        audit_info.identity.subscriptions = {
            "Azure subscription 1": "12345-qwerty",
            "Subscription2": "12345-qwerty",
        }
        printed_subscriptions = []
        for key, value in audit_info.identity.subscriptions.items():
            intermediate = key + " : " + value
            printed_subscriptions.append(intermediate)
        assert (
            get_assessment_summary(audit_info)
            == f"""
            <div class="col-md-2">
                <div class="card">
                    <div class="card-header">
                        Azure Assessment Summary
                    </div>
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item">
                            <b>Azure Tenant IDs:</b> {" ".join(audit_info.identity.tenant_ids)}
                        </li>
                        <li class="list-group-item">
                            <b>Azure Tenant Domain:</b> {audit_info.identity.domain}
                        </li>
                        <li class="list-group-item">
                            <b>Azure Subscriptions:</b> {" ".join(printed_subscriptions)}
                        </li>
                    </ul>
                </div>
            </div>
            <div class="col-md-4">
            <div class="card">
                <div class="card-header">
                    Azure Credentials
                </div>
                <ul class="list-group list-group-flush">
                    <li class="list-group-item">
                        <b>Azure Identity Type:</b> {audit_info.identity.identity_type}
                        </li>
                        <li class="list-group-item">
                            <b>Azure Identity ID:</b> {audit_info.identity.identity_id}
                        </li>
                    </ul>
                </div>
            </div>
            """
        )

    def test_aws_get_assessment_summary(self):
        # Mock AWS Audit Info
        audit_info = self.set_mocked_aws_audit_info()

        assert (
            get_assessment_summary(audit_info)
            == f"""
            <div class="col-md-2">
                <div class="card">
                    <div class="card-header">
                        AWS Assessment Summary
                    </div>
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item">
                            <b>AWS Account:</b> {audit_info.audited_account}
                        </li>
                        <li class="list-group-item">
                            <b>AWS-CLI Profile:</b> {audit_info.profile}
                        </li>
                        <li class="list-group-item">
                            <b>Audited Regions:</b> All Regions
                        </li>
                    </ul>
                </div>
            </div>
            <div class="col-md-4">
            <div class="card">
                <div class="card-header">
                    AWS Credentials
                </div>
                <ul class="list-group list-group-flush">
                    <li class="list-group-item">
                        <b>User Id:</b> {audit_info.audited_user_id}
                        </li>
                        <li class="list-group-item">
                            <b>Caller Identity ARN:</b> {audit_info.audited_identity_arn}
                        </li>
                    </ul>
                </div>
            </div>
            """
        )

    def test_gcp_get_assessment_summary(self):
        # Mock Azure Audit Info
        audit_info = self.set_mocked_gcp_audit_info()
        profile = "default"
        assert (
            get_assessment_summary(audit_info)
            == f"""
            <div class="col-md-2">
                <div class="card">
                    <div class="card-header">
                        GCP Assessment Summary
                    </div>
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item">
                            <b>GCP Project IDs:</b> {', '.join(audit_info.project_ids)}
                        </li>
                    </ul>
                </div>
            </div>
            <div class="col-md-4">
                <div class="card">
                    <div class="card-header">
                        GCP Credentials
                    </div>
                    <ul class="list-group list-group-flush">
                        <li class="list-group-item">
                            <b>GCP Account:</b> {profile}
                        </li>
                    </ul>
                </div>
            </div>
            """
        )
