from datetime import datetime
from unittest.mock import MagicMock, patch

from prowler.lib.check.models import (
    CheckMetadata,
    Code,
    Recommendation,
    Remediation,
    Severity,
)
from prowler.lib.outputs.common import Status
from prowler.lib.outputs.finding import Finding
from tests.lib.outputs.fixtures.fixtures import generate_finding_output


def mock_check_metadata(provider):
    return CheckMetadata(
        Provider=provider,
        CheckID="mock_check_id",
        CheckTitle="mock_check_title",
        CheckType=[],
        CheckAliases=[],
        ServiceName="mock_service_name",
        SubServiceName="",
        ResourceIdTemplate="",
        Severity="high",
        ResourceType="",
        Description="",
        Risk="",
        RelatedUrl="",
        Remediation=Remediation(
            Code=Code(
                NativeIaC="",
                Terraform="",
                CLI="",
                Other="",
            ),
            Recommendation=Recommendation(
                Text="",
                Url="",
            ),
        ),
        Categories=[],
        DependsOn=["check1", "check2"],
        RelatedTo=["check1", "check2"],
        Notes="mock_notes",
        Compliance=[],
    )


def mock_get_check_compliance(*_):
    return {"mock_compliance_key": "mock_compliance_value"}


class TestFinding:
    @patch(
        "prowler.lib.outputs.finding.get_check_compliance",
        new=mock_get_check_compliance,
    )
    def test_generate_output_aws(self):
        # Mock provider
        provider = MagicMock()
        provider.type = "aws"
        provider.identity.profile = "mock_auth"
        provider.identity.account = "mock_account_uid"
        provider.identity.partition = "aws"
        provider.organizations_metadata.account_name = "mock_account_name"
        provider.organizations_metadata.account_email = "mock_account_email"
        provider.organizations_metadata.organization_arn = "mock_account_org_uid"
        provider.organizations_metadata.organization_id = "mock_account_org_name"
        provider.organizations_metadata.account_tags = {"tag1": "value1"}

        # Mock check result
        check_output = MagicMock()
        check_output.resource_id = "test_resource_id"
        check_output.resource_arn = "test_resource_arn"
        check_output.resource_details = "test_resource_details"
        check_output.resource_tags = {"tag1": "value1"}
        check_output.region = "us-west-1"
        check_output.partition = "aws"
        check_output.status = Status.PASS
        check_output.status_extended = "mock_status_extended"
        check_output.muted = False
        check_output.check_metadata = mock_check_metadata(provider="aws")

        # Mock output options
        output_options = MagicMock()
        output_options.unix_timestamp = False

        # Generate the finding
        finding_output = Finding.generate_output(provider, check_output, output_options)

        # Finding
        assert isinstance(finding_output, Finding)
        assert finding_output.auth_method == "profile: mock_auth"
        assert finding_output.resource_name == "test_resource_id"
        assert finding_output.resource_uid == "test_resource_arn"
        assert finding_output.resource_details == "test_resource_details"
        assert finding_output.region == "us-west-1"
        assert finding_output.compliance == {
            "mock_compliance_key": "mock_compliance_value"
        }
        assert finding_output.status == Status.PASS
        assert finding_output.status_extended == "mock_status_extended"
        assert finding_output.muted is False
        assert finding_output.resource_tags == {"tag1": "value1"}
        assert finding_output.partition == "aws"
        assert finding_output.account_uid == "mock_account_uid"
        assert finding_output.account_name == "mock_account_name"
        assert finding_output.account_email == "mock_account_email"
        assert finding_output.account_organization_uid == "mock_account_org_uid"
        assert finding_output.account_organization_name == "mock_account_org_name"
        assert finding_output.account_tags == {"tag1": "value1"}

        # Metadata
        assert finding_output.metadata.Provider == "aws"
        assert finding_output.metadata.CheckID == "mock_check_id"
        assert finding_output.metadata.CheckTitle == "mock_check_title"
        assert finding_output.metadata.CheckType == []
        assert finding_output.metadata.CheckAliases == []
        assert finding_output.metadata.ServiceName == "mock_service_name"
        assert finding_output.metadata.SubServiceName == ""
        assert finding_output.metadata.ResourceIdTemplate == ""
        assert finding_output.metadata.Severity == Severity.high
        assert finding_output.metadata.ResourceType == ""
        assert finding_output.metadata.Description == ""
        assert finding_output.metadata.Risk == ""
        assert finding_output.metadata.RelatedUrl == ""
        assert finding_output.metadata.Remediation.Code.NativeIaC == ""
        assert finding_output.metadata.Remediation.Code.Terraform == ""
        assert finding_output.metadata.Remediation.Code.CLI == ""
        assert finding_output.metadata.Remediation.Code.Other == ""
        assert finding_output.metadata.Remediation.Recommendation.Text == ""
        assert finding_output.metadata.Remediation.Recommendation.Url == ""
        assert finding_output.metadata.Categories == []
        assert finding_output.metadata.DependsOn == ["check1", "check2"]
        assert finding_output.metadata.RelatedTo == ["check1", "check2"]
        assert finding_output.metadata.Notes == "mock_notes"
        assert finding_output.metadata.Compliance == []

        # Properties
        assert finding_output.provider == "aws"
        assert finding_output.check_id == "mock_check_id"
        assert finding_output.severity == Severity.high.value
        assert finding_output.status == Status.PASS.value
        assert finding_output.resource_type == ""
        assert finding_output.service_name == "mock_service_name"
        assert finding_output.raw == {}

    @patch(
        "prowler.lib.outputs.finding.get_check_compliance",
        new=mock_get_check_compliance,
    )
    def test_generate_output_azure(self):
        # Mock provider
        provider = MagicMock()
        provider.type = "azure"
        provider.identity.identity_type = "mock_identity_type"
        provider.identity.identity_id = "mock_identity_id"
        provider.identity.subscriptions = {
            "mock_subscription_id": "mock_subscription_name"
        }
        provider.identity.tenant_ids = ["mock_tenant_id_1", "mock_tenant_id_2"]
        provider.identity.tenant_domain = "mock_tenant_domain"
        provider.region_config.name = "AzureCloud"

        # Mock check result
        check_output = MagicMock()
        check_output.resource_name = "test_resource_name"
        check_output.resource_id = "test_resource_id"
        check_output.resource_details = "test_resource_details"
        check_output.resource_tags = {}
        check_output.subscription = "mock_subscription_id"
        check_output.resource_name = "test_resource_name"
        check_output.location = "us-west-1"
        check_output.region = "us-west-1"
        check_output.status = Status.PASS
        check_output.status_extended = "mock_status_extended"
        check_output.muted = False
        check_output.check_metadata = mock_check_metadata(provider="azure")

        # Mock output options
        output_options = MagicMock()
        output_options.unix_timestamp = True

        # Generate the finding
        finding_output = Finding.generate_output(provider, check_output, output_options)

        # Finding
        assert isinstance(finding_output, Finding)
        assert finding_output.auth_method == "mock_identity_type: mock_identity_id"
        assert finding_output.account_organization_uid == "mock_tenant_id_1"
        assert finding_output.account_organization_name == "mock_tenant_domain"
        assert finding_output.account_uid == "mock_subscription_name"
        assert finding_output.account_name == "mock_subscription_id"
        assert finding_output.resource_name == "test_resource_name"
        assert finding_output.resource_uid == "test_resource_id"
        assert finding_output.region == "us-west-1"
        assert finding_output.compliance == {
            "mock_compliance_key": "mock_compliance_value"
        }
        assert finding_output.status == Status.PASS
        assert finding_output.status_extended == "mock_status_extended"
        assert finding_output.muted is False
        assert finding_output.resource_tags == {}
        assert finding_output.partition == "AzureCloud"

        assert isinstance(finding_output.timestamp, int)

        # Metadata
        assert finding_output.metadata.Provider == "azure"
        assert finding_output.metadata.CheckID == "mock_check_id"
        assert finding_output.metadata.CheckTitle == "mock_check_title"
        assert finding_output.metadata.CheckType == []
        assert finding_output.metadata.CheckAliases == []
        assert finding_output.metadata.ServiceName == "mock_service_name"
        assert finding_output.metadata.SubServiceName == ""
        assert finding_output.metadata.ResourceIdTemplate == ""
        assert finding_output.metadata.Severity == Severity.high
        assert finding_output.metadata.ResourceType == ""
        assert finding_output.metadata.Description == ""
        assert finding_output.metadata.Risk == ""
        assert finding_output.metadata.RelatedUrl == ""
        assert finding_output.metadata.Remediation.Code.NativeIaC == ""
        assert finding_output.metadata.Remediation.Code.Terraform == ""
        assert finding_output.metadata.Remediation.Code.CLI == ""
        assert finding_output.metadata.Remediation.Code.Other == ""
        assert finding_output.metadata.Remediation.Recommendation.Text == ""
        assert finding_output.metadata.Remediation.Recommendation.Url == ""
        assert finding_output.metadata.Categories == []
        assert finding_output.metadata.DependsOn == ["check1", "check2"]
        assert finding_output.metadata.RelatedTo == ["check1", "check2"]
        assert finding_output.metadata.Notes == "mock_notes"
        assert finding_output.metadata.Compliance == []

    @patch(
        "prowler.lib.outputs.finding.get_check_compliance",
        new=mock_get_check_compliance,
    )
    def test_generate_output_gcp(self):
        # Mock provider
        provider = MagicMock()
        provider.type = "gcp"
        provider.identity.profile = "mock_auth"
        # Organization
        organization = MagicMock()
        organization.id = "mock_organization_id"
        organization.display_name = "mock_organization_name"
        # Project
        project = MagicMock()
        project.id = "mock_project_id"
        project.name = "mock_project_name"
        project.labels = {"tag1": "value1"}
        project.organization = organization
        provider.projects = {"mock_project_id": project}

        # Mock check result
        check_output = MagicMock()
        check_output.resource_id = "test_resource_id"
        check_output.resource_name = "test_resource_name"
        check_output.resource_details = "test_resource_details"
        check_output.project_id = "mock_project_id"
        check_output.resource_name = "test_resource_name"
        check_output.location = "us-west-1"
        check_output.status = Status.PASS
        check_output.status_extended = "mock_status_extended"
        check_output.muted = False
        check_output.check_metadata = mock_check_metadata(provider="gcp")

        # Mock output options
        output_options = MagicMock()
        output_options.unix_timestamp = True

        # Generate the finding
        finding_output = Finding.generate_output(provider, check_output, output_options)

        # Finding
        assert isinstance(finding_output, Finding)
        assert finding_output.auth_method == "Principal: mock_auth"
        assert finding_output.resource_name == "test_resource_name"
        assert finding_output.resource_uid == "test_resource_id"
        assert finding_output.region == "us-west-1"
        assert finding_output.compliance == {
            "mock_compliance_key": "mock_compliance_value"
        }
        assert finding_output.status == Status.PASS
        assert finding_output.status_extended == "mock_status_extended"
        assert finding_output.muted is False
        assert finding_output.resource_tags == {}
        assert finding_output.partition is None
        assert finding_output.account_uid == "mock_project_id"
        assert finding_output.account_name == "mock_project_name"
        assert finding_output.account_email is None
        assert finding_output.account_organization_uid == "mock_organization_id"
        assert finding_output.account_organization_name == "mock_organization_name"
        assert finding_output.account_tags == {"tag1": "value1"}
        assert isinstance(finding_output.timestamp, int)

        # Metadata
        assert finding_output.metadata.Provider == "gcp"
        assert finding_output.metadata.CheckID == "mock_check_id"
        assert finding_output.metadata.CheckTitle == "mock_check_title"
        assert finding_output.metadata.CheckType == []
        assert finding_output.metadata.CheckAliases == []
        assert finding_output.metadata.ServiceName == "mock_service_name"
        assert finding_output.metadata.SubServiceName == ""
        assert finding_output.metadata.ResourceIdTemplate == ""
        assert finding_output.metadata.Severity == Severity.high
        assert finding_output.metadata.ResourceType == ""
        assert finding_output.metadata.Description == ""
        assert finding_output.metadata.Risk == ""
        assert finding_output.metadata.RelatedUrl == ""
        assert finding_output.metadata.Remediation.Code.NativeIaC == ""
        assert finding_output.metadata.Remediation.Code.Terraform == ""
        assert finding_output.metadata.Remediation.Code.CLI == ""
        assert finding_output.metadata.Remediation.Code.Other == ""
        assert finding_output.metadata.Remediation.Recommendation.Text == ""
        assert finding_output.metadata.Remediation.Recommendation.Url == ""
        assert finding_output.metadata.Categories == []
        assert finding_output.metadata.DependsOn == ["check1", "check2"]
        assert finding_output.metadata.RelatedTo == ["check1", "check2"]
        assert finding_output.metadata.Notes == "mock_notes"
        assert finding_output.metadata.Compliance == []

    @patch(
        "prowler.lib.outputs.finding.get_check_compliance",
        new=mock_get_check_compliance,
    )
    def test_generate_output_kubernetes(self):
        # Mock provider
        provider = MagicMock()
        provider.type = "kubernetes"
        provider.identity.context = "In-Cluster"
        provider.identity.cluster = "test_cluster"

        # Mock check result
        check_output = MagicMock()
        check_output.resource_name = "test_resource_name"
        check_output.resource_id = "test_resource_id"
        check_output.namespace = "test_namespace"
        check_output.resource_details = "test_resource_details"
        check_output.status = Status.PASS
        check_output.status_extended = "mock_status_extended"
        check_output.muted = False
        check_output.check_metadata = mock_check_metadata(provider="kubernetes")
        check_output.timestamp = datetime.now()

        # Mock Output Options
        output_options = MagicMock()
        output_options.unix_timestamp = True

        # Generate the finding
        finding_output = Finding.generate_output(provider, check_output, output_options)

        # Finding
        assert isinstance(finding_output, Finding)
        assert finding_output.auth_method == "in-cluster"
        assert finding_output.resource_name == "test_resource_name"
        assert finding_output.resource_uid == "test_resource_id"
        assert finding_output.region == "namespace: test_namespace"
        assert finding_output.account_name == "context: In-Cluster"
        assert finding_output.compliance == {
            "mock_compliance_key": "mock_compliance_value"
        }
        assert finding_output.status == Status.PASS
        assert finding_output.status_extended == "mock_status_extended"
        assert finding_output.muted is False
        assert finding_output.resource_tags == {}
        assert finding_output.partition is None
        assert finding_output.account_uid == "test_cluster"
        assert finding_output.account_name == "context: In-Cluster"
        assert finding_output.account_email is None
        assert finding_output.account_organization_uid is None
        assert finding_output.account_organization_name is None
        assert finding_output.account_tags == {}
        assert isinstance(finding_output.timestamp, int)

        # Metadata
        assert finding_output.metadata.Provider == "kubernetes"
        assert finding_output.metadata.CheckID == "mock_check_id"
        assert finding_output.metadata.CheckTitle == "mock_check_title"
        assert finding_output.metadata.CheckType == []
        assert finding_output.metadata.CheckAliases == []
        assert finding_output.metadata.ServiceName == "mock_service_name"
        assert finding_output.metadata.SubServiceName == ""
        assert finding_output.metadata.ResourceIdTemplate == ""
        assert finding_output.metadata.Severity == Severity.high
        assert finding_output.metadata.ResourceType == ""
        assert finding_output.metadata.Description == ""
        assert finding_output.metadata.Risk == ""
        assert finding_output.metadata.RelatedUrl == ""
        assert finding_output.metadata.Remediation.Code.NativeIaC == ""
        assert finding_output.metadata.Remediation.Code.Terraform == ""
        assert finding_output.metadata.Remediation.Code.CLI == ""
        assert finding_output.metadata.Remediation.Code.Other == ""
        assert finding_output.metadata.Remediation.Recommendation.Text == ""
        assert finding_output.metadata.Remediation.Recommendation.Url == ""
        assert finding_output.metadata.Categories == []
        assert finding_output.metadata.DependsOn == ["check1", "check2"]
        assert finding_output.metadata.RelatedTo == ["check1", "check2"]
        assert finding_output.metadata.Notes == "mock_notes"
        assert finding_output.metadata.Compliance == []

    def assert_keys_lowercase(self, d):
        for k, v in d.items():
            assert k.islower()
            if isinstance(v, dict):
                self.assert_keys_lowercase(v)

    def test_get_metadata(self):
        metadata = generate_finding_output().get_metadata()

        assert metadata is not None
        assert isinstance(metadata, dict)
        self.assert_keys_lowercase(metadata)
