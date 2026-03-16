from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from pydantic.v1 import ValidationError

from prowler.lib.check.models import (
    CheckMetadata,
    Code,
    Recommendation,
    Remediation,
    Severity,
)
from prowler.lib.outputs.common import Status
from prowler.lib.outputs.finding import Finding
from prowler.providers.github.models import GithubAppIdentityInfo
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.github.github_fixtures import (
    ACCOUNT_ID,
    ACCOUNT_NAME,
    ACCOUNT_URL,
    APP_ID,
)


def mock_check_metadata(provider):
    return CheckMetadata(
        Provider=provider,
        CheckID="service_check_id",
        CheckTitle="mock_check_title",
        CheckType=[],
        CheckAliases=[],
        ServiceName="service",
        SubServiceName="",
        ResourceIdTemplate="",
        Severity="high",
        ResourceType="mock_resource_type",
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
    return {
        "CIS-2.0": ["1.12"],
        "CIS-3.0": ["1.12"],
        "ENS-RD2022": ["op.acc.2.gcp.rbak.1"],
        "MITRE-ATTACK": ["T1098"],
    }


class DummyTag:
    def __init__(self, key, value):
        self.key = key
        self.value = value


class DummyTags:
    def __init__(self, tags):
        self._tags = tags

    def all(self):
        return self._tags


class DummyResource:
    def __init__(
        self,
        uid,
        name,
        resource_arn,
        region,
        tags,
        details=None,
        metadata=None,
        partition=None,
    ):
        self.uid = uid
        self.name = name
        self.resource_arn = resource_arn
        self.region = region
        self.tags = DummyTags(tags)
        self.details = details or ""
        self.metadata = metadata or "{}"
        self.partition = partition

    def __iter__(self):
        yield "uid", self.uid
        yield "name", self.name
        yield "region", self.region
        yield "tags", self.tags


class DummyResources:
    """Simulate a collection with a first() method."""

    def __init__(self, resource):
        self._resource = resource

    def first(self):
        return self._resource


class DummyProvider:
    def __init__(self, uid):
        self.uid = uid
        self.type = "aws"


class DummyScan:
    def __init__(self, provider):
        self.provider = provider


class DummyAPIFinding:
    """
    A dummy API finding model to simulate the database model.
    Attributes will be added dynamically.
    """


class TestFinding:
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
        check_output.resource = {"metadata": "mock_metadata"}
        check_output.compliance = {
            "CIS-2.0": ["1.12"],
            "CIS-3.0": ["1.12"],
            "ENS-RD2022": ["op.acc.2.gcp.rbak.1"],
            "MITRE-ATTACK": ["T1098"],
        }

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
        assert finding_output.resource_metadata == {"metadata": "mock_metadata"}
        assert finding_output.partition == "aws"
        assert finding_output.region == "us-west-1"
        assert finding_output.compliance == {
            "CIS-2.0": ["1.12"],
            "CIS-3.0": ["1.12"],
            "ENS-RD2022": ["op.acc.2.gcp.rbak.1"],
            "MITRE-ATTACK": ["T1098"],
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
        assert finding_output.metadata.CheckID == "service_check_id"
        assert finding_output.metadata.CheckTitle == "mock_check_title"
        assert finding_output.metadata.CheckType == []
        assert finding_output.metadata.CheckAliases == []
        assert finding_output.metadata.ServiceName == "service"
        assert finding_output.metadata.SubServiceName == ""
        assert finding_output.metadata.ResourceIdTemplate == ""
        assert finding_output.metadata.Severity == Severity.high
        assert finding_output.metadata.ResourceType == "mock_resource_type"
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
        assert finding_output.check_id == "service_check_id"
        assert finding_output.severity == Severity.high.value
        assert finding_output.status == Status.PASS.value
        assert finding_output.resource_type == "mock_resource_type"
        assert finding_output.service_name == "service"
        assert finding_output.raw == {}

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
        check_output.resource = {}
        check_output.compliance = {
            "CIS-2.0": ["1.12"],
            "CIS-3.0": ["1.12"],
            "ENS-RD2022": ["op.acc.2.gcp.rbak.1"],
            "MITRE-ATTACK": ["T1098"],
        }

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
            "CIS-2.0": ["1.12"],
            "CIS-3.0": ["1.12"],
            "ENS-RD2022": ["op.acc.2.gcp.rbak.1"],
            "MITRE-ATTACK": ["T1098"],
        }
        assert finding_output.status == Status.PASS
        assert finding_output.status_extended == "mock_status_extended"
        assert finding_output.muted is False
        assert finding_output.resource_tags == {}
        assert finding_output.partition == "AzureCloud"

        assert isinstance(finding_output.timestamp, int)

        # Metadata
        assert finding_output.metadata.Provider == "azure"
        assert finding_output.metadata.CheckID == "service_check_id"
        assert finding_output.metadata.CheckTitle == "mock_check_title"
        assert finding_output.metadata.CheckType == []
        assert finding_output.metadata.CheckAliases == []
        assert finding_output.metadata.ServiceName == "service"
        assert finding_output.metadata.SubServiceName == ""
        assert finding_output.metadata.ResourceIdTemplate == ""
        assert finding_output.metadata.Severity == Severity.high
        assert finding_output.metadata.ResourceType == "mock_resource_type"
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
        check_output.resource = {}
        check_output.compliance = {
            "CIS-2.0": ["1.12"],
            "CIS-3.0": ["1.12"],
            "ENS-RD2022": ["op.acc.2.gcp.rbak.1"],
            "MITRE-ATTACK": ["T1098"],
        }

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
            "CIS-2.0": ["1.12"],
            "CIS-3.0": ["1.12"],
            "ENS-RD2022": ["op.acc.2.gcp.rbak.1"],
            "MITRE-ATTACK": ["T1098"],
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
        assert finding_output.metadata.CheckID == "service_check_id"
        assert finding_output.metadata.CheckTitle == "mock_check_title"
        assert finding_output.metadata.CheckType == []
        assert finding_output.metadata.CheckAliases == []
        assert finding_output.metadata.ServiceName == "service"
        assert finding_output.metadata.SubServiceName == ""
        assert finding_output.metadata.ResourceIdTemplate == ""
        assert finding_output.metadata.Severity == Severity.high
        assert finding_output.metadata.ResourceType == "mock_resource_type"
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

    def test_generate_output_googleworkspace(self):
        provider = MagicMock()
        provider.type = "googleworkspace"
        provider.identity.delegated_user = "admin@test-company.com"
        provider.identity.customer_id = "C1234567"
        provider.identity.domain = "test-company.com"

        check_output = MagicMock()
        check_output.resource_id = "test_resource_id"
        check_output.resource_name = "test_resource_name"
        check_output.resource_details = ""
        check_output.location = "global"
        check_output.status = Status.PASS
        check_output.status_extended = "mock_status_extended"
        check_output.muted = False
        check_output.check_metadata = mock_check_metadata(provider="googleworkspace")
        check_output.resource = {}
        check_output.compliance = {}

        output_options = MagicMock()
        output_options.unix_timestamp = True

        finding_output = Finding.generate_output(provider, check_output, output_options)

        assert isinstance(finding_output, Finding)
        assert finding_output.auth_method == "service_account: admin@test-company.com"
        assert finding_output.account_uid == "C1234567"
        assert finding_output.account_name == "test-company.com"
        assert finding_output.resource_name == "test_resource_name"
        assert finding_output.resource_uid == "test_resource_id"
        assert finding_output.region == "global"
        assert finding_output.status == Status.PASS
        assert finding_output.muted is False

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
        check_output.resource = {}
        check_output.compliance = {
            "CIS-2.0": ["1.12"],
            "CIS-3.0": ["1.12"],
            "ENS-RD2022": ["op.acc.2.gcp.rbak.1"],
            "MITRE-ATTACK": ["T1098"],
        }

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
            "CIS-2.0": ["1.12"],
            "CIS-3.0": ["1.12"],
            "ENS-RD2022": ["op.acc.2.gcp.rbak.1"],
            "MITRE-ATTACK": ["T1098"],
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
        assert finding_output.metadata.CheckID == "service_check_id"
        assert finding_output.metadata.CheckTitle == "mock_check_title"
        assert finding_output.metadata.CheckType == []
        assert finding_output.metadata.CheckAliases == []
        assert finding_output.metadata.ServiceName == "service"
        assert finding_output.metadata.SubServiceName == ""
        assert finding_output.metadata.ResourceIdTemplate == ""
        assert finding_output.metadata.Severity == Severity.high
        assert finding_output.metadata.ResourceType == "mock_resource_type"
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

    def test_generate_output_github_personal_access_token(self):
        """Test GitHub output generation with Personal Access Token authentication."""
        # Mock provider using Personal Access Token
        provider = MagicMock()
        provider.type = "github"
        # Use the actual GithubIdentityInfo for Personal Access Token
        from prowler.providers.github.models import GithubIdentityInfo

        provider.identity = GithubIdentityInfo(
            account_name=ACCOUNT_NAME, account_id=ACCOUNT_ID, account_url=ACCOUNT_URL
        )
        provider.auth_method = "Personal Access Token"

        # Mock check result
        check_output = MagicMock()
        check_output.resource_id = "test_repository"
        check_output.resource_name = "test_repository"
        check_output.resource_details = "GitHub repository test_repository"
        check_output.resource_tags = {"topic": "security"}
        check_output.owner = "test-owner"  # GitHub uses owner for region
        check_output.status = Status.PASS
        check_output.status_extended = "Repository has security features enabled"
        check_output.muted = False
        check_output.check_metadata = mock_check_metadata(provider="github")
        check_output.resource = {"url": "https://github.com/owner/test_repository"}
        check_output.compliance = {
            "CIS-2.0": ["1.12"],
            "ENS-RD2022": ["op.acc.2.gcp.rbak.1"],
        }

        # Mock output options
        output_options = MagicMock()
        output_options.unix_timestamp = False

        # Generate the finding
        finding_output = Finding.generate_output(provider, check_output, output_options)

        # Assert basic finding properties
        assert isinstance(finding_output, Finding)
        assert finding_output.provider == "github"
        assert finding_output.auth_method == "Personal Access Token"
        assert finding_output.resource_name == "test_repository"
        assert finding_output.resource_uid == "test_repository"
        assert finding_output.region == "test-owner"
        assert finding_output.status == Status.PASS
        assert (
            finding_output.status_extended == "Repository has security features enabled"
        )
        assert finding_output.muted is False
        assert finding_output.resource_tags == {"topic": "security"}

        # Assert account information for Personal Access Token
        assert finding_output.account_name == ACCOUNT_NAME
        assert finding_output.account_uid == ACCOUNT_ID
        assert finding_output.account_email is None
        assert finding_output.account_organization_uid is None
        assert finding_output.account_organization_name is None
        assert finding_output.account_tags == {}

        # Metadata checks
        assert finding_output.metadata.Provider == "github"
        assert finding_output.metadata.CheckID == "service_check_id"
        assert finding_output.metadata.ServiceName == "service"
        assert finding_output.metadata.Severity == Severity.high
        assert finding_output.metadata.ResourceType == "mock_resource_type"

    def test_generate_output_github_app_authentication(self):
        """Test GitHub output generation with GitHub App authentication."""
        # Mock provider using GitHub App authentication - this is the key test case for the bug fix
        provider = MagicMock()
        provider.type = "github"
        # GitHub App identity only has app_id, not account_name/account_id
        provider.identity = GithubAppIdentityInfo(
            app_id=APP_ID, app_name="test-app", installations=["test-org"]
        )
        provider.auth_method = "GitHub App Token"

        # Mock check result
        check_output = MagicMock()
        check_output.resource_id = "test_repository"
        check_output.resource_name = "test_repository"
        check_output.resource_details = "GitHub repository test_repository"
        check_output.resource_tags = {"language": "python"}
        check_output.owner = "test-owner"  # GitHub provider uses owner for region
        check_output.status = Status.FAIL
        check_output.status_extended = (
            "Repository lacks required security configuration"
        )
        check_output.muted = False
        check_output.check_metadata = mock_check_metadata(provider="github")
        check_output.resource = {"url": "https://github.com/org/test_repository"}
        check_output.compliance = {
            "CIS-2.0": ["1.12"],
            "MITRE-ATTACK": ["T1098"],
        }

        # Mock output options
        output_options = MagicMock()
        output_options.unix_timestamp = True

        # Generate the finding - this was failing before the fix
        finding_output = Finding.generate_output(provider, check_output, output_options)

        # Assert basic finding properties
        assert isinstance(finding_output, Finding)
        assert finding_output.provider == "github"
        assert finding_output.auth_method == "GitHub App Token"
        assert finding_output.resource_name == "test_repository"
        assert finding_output.resource_uid == "test_repository"
        assert finding_output.region == "test-owner"
        assert finding_output.status == Status.FAIL
        assert (
            finding_output.status_extended
            == "Repository lacks required security configuration"
        )
        assert finding_output.muted is False
        assert finding_output.resource_tags == {"language": "python"}
        assert isinstance(finding_output.timestamp, int)

        # Assert account information for GitHub App - this is the core of the bug fix
        # Before the fix, this would fail because GithubAppIdentityInfo doesn't have account_name
        # After the fix, it should use app_name
        assert finding_output.account_name == "test-app"
        assert finding_output.account_uid == APP_ID
        assert finding_output.account_email is None
        assert finding_output.account_organization_uid is None
        assert finding_output.account_organization_name is None
        assert finding_output.account_tags == {}

        # Metadata checks
        assert finding_output.metadata.Provider == "github"
        assert finding_output.metadata.CheckID == "service_check_id"
        assert finding_output.metadata.ServiceName == "service"
        assert finding_output.metadata.Severity == Severity.high
        assert finding_output.metadata.ResourceType == "mock_resource_type"

    def test_generate_output_iac_remote(self):
        # Mock provider
        provider = MagicMock()
        provider.type = "iac"
        provider.scan_repository_url = "https://github.com/user/repo"
        provider.auth_method = "No auth"

        # Mock check result
        check_output = MagicMock()
        check_output.file_path = "/path/to/iac/file.tf"
        check_output.resource_name = "aws_s3_bucket.example"
        check_output.resource_path = "/path/to/iac/file.tf"
        check_output.resource_line_range = "1:5"
        check_output.region = "main"  # Branch name for remote IaC scans
        check_output.resource = {
            "resource": "aws_s3_bucket.example",
            "value": {},
        }
        check_output.resource_details = "test_resource_details"
        check_output.status = Status.PASS
        check_output.status_extended = "mock_status_extended"
        check_output.muted = False
        check_output.check_metadata = mock_check_metadata(provider="iac")
        check_output.compliance = {}

        # Mock output options
        output_options = MagicMock()
        output_options.unix_timestamp = False

        # Generate the finding
        finding_output = Finding.generate_output(provider, check_output, output_options)

        # Finding
        assert isinstance(finding_output, Finding)
        assert finding_output.auth_method == "No auth"
        assert finding_output.resource_name == "aws_s3_bucket.example"
        assert finding_output.resource_uid == "aws_s3_bucket.example"
        assert finding_output.region == "main"  # Branch name, not line range
        assert finding_output.status == Status.PASS
        assert finding_output.status_extended == "mock_status_extended"
        assert finding_output.muted is False

        # Metadata
        assert finding_output.metadata.Provider == "iac"
        assert finding_output.metadata.CheckID == "service_check_id"
        assert finding_output.metadata.CheckTitle == "mock_check_title"
        assert finding_output.metadata.CheckType == []
        assert finding_output.metadata.CheckAliases == []
        assert finding_output.metadata.ServiceName == "service"
        assert finding_output.metadata.SubServiceName == ""
        assert finding_output.metadata.ResourceIdTemplate == ""

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

    @patch(
        "prowler.lib.outputs.finding.get_check_compliance",
        new=mock_get_check_compliance,
    )
    def test_generate_output_validation_error(self):
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
        check_output.status_extended = "mock_status_extended"
        check_output.muted = False
        check_output.check_metadata = mock_check_metadata(provider="aws")
        check_output.resource = {}

        # Mock output options
        output_options = MagicMock()
        output_options.unix_timestamp = False

        # Bad Status Value
        check_output.status = "Invalid"

        # Generate the finding
        with pytest.raises(ValidationError):
            Finding.generate_output(provider, check_output, output_options)

    @patch(
        "prowler.lib.outputs.finding.get_check_compliance",
        new=mock_get_check_compliance,
    )
    def test_transform_api_finding_aws(self):
        """
        Test that a dummy API Finding is correctly
        transformed into a Finding instance.
        """
        # Set up the dummy API finding attributes
        inserted_at = 1234567890
        provider = DummyProvider(uid="account123")
        provider.type = "aws"
        provider.organizations_metadata = SimpleNamespace(
            account_name="test-account",
            account_email="test@example.com",
            organization_arn="arn:aws:organizations::123456789012:organization/o-abcdef123456",
            organization_id="o-abcdef123456",
            account_tags={"Environment": "prod", "Project": "test"},
        )
        provider.identity = SimpleNamespace(
            account="123456789012", partition="aws", profile="default"
        )
        scan = DummyScan(provider=provider)

        # Create a dummy resource with one tag
        tag = DummyTag("env", "prod")
        resource = DummyResource(
            uid="res-uid-1",
            name="ResourceName1",
            resource_arn="arn",
            region="us-east-1",
            tags=[tag],
        )
        resources = DummyResources(resource)

        # Create a dummy check_metadata dict with all required fields
        check_metadata = {
            "provider": "test_provider",
            "checkid": "service_check_001",
            "checktitle": "Test Check",
            "checktype": ["type1"],
            "servicename": "service",
            "subservicename": "SubService",
            "severity": "high",
            "resourcetype": "TestResource",
            "description": "A test check",
            "risk": "High risk",
            "relatedurl": "http://example.com",
            "remediation": {
                "recommendation": {"text": "Fix it", "url": "http://fix.com"},
                "code": {
                    "nativeiac": "iac_code",
                    "terraform": "terraform_code",
                    "cli": "cli_code",
                    "other": "other_code",
                },
            },
            "resourceidtemplate": "template",
            "categories": ["cat-one", "cat-two"],
            "dependson": ["dep1"],
            "relatedto": ["rel1"],
            "notes": "Some notes",
        }

        # Create the dummy API finding and assign required attributes
        dummy_finding = DummyAPIFinding()
        dummy_finding.inserted_at = inserted_at
        dummy_finding.scan = scan
        dummy_finding.uid = "finding-uid-1"
        dummy_finding.status = "FAIL"  # will be converted to Status("FAIL")
        dummy_finding.status_extended = "extended"
        dummy_finding.check_metadata = check_metadata
        dummy_finding.resources = resources
        dummy_finding.muted = True

        # Call the transform_api_finding classmethod
        finding_obj = Finding.transform_api_finding(dummy_finding, provider)

        # Check that metadata was built correctly
        meta = finding_obj.metadata
        assert meta.Provider == "test_provider"
        assert meta.CheckID == "service_check_001"
        assert meta.CheckTitle == "Test Check"
        assert meta.CheckType == ["type1"]
        assert meta.ServiceName == "service"
        assert meta.SubServiceName == "SubService"
        assert meta.Severity == "high"
        assert meta.ResourceType == "TestResource"
        assert meta.Description == "A test check"
        assert meta.Risk == "High risk"
        assert meta.RelatedUrl == "http://example.com"
        assert meta.Remediation.Recommendation.Text == "Fix it"
        assert meta.Remediation.Recommendation.Url == "http://fix.com"
        assert meta.Remediation.Code.NativeIaC == "iac_code"
        assert meta.Remediation.Code.Terraform == "terraform_code"
        assert meta.Remediation.Code.CLI == "cli_code"
        assert meta.Remediation.Code.Other == "other_code"
        assert meta.ResourceIdTemplate == "template"
        assert meta.Categories == ["cat-one", "cat-two"]
        assert meta.DependsOn == ["dep1"]
        assert meta.RelatedTo == ["rel1"]
        assert meta.Notes == "Some notes"

        # Check other Finding fields
        assert (
            finding_obj.uid
            == "prowler-aws-service_check_001-123456789012-us-east-1-ResourceName1"
        )
        assert finding_obj.status == Status("FAIL")
        assert finding_obj.status_extended == "extended"
        # From the dummy resource
        assert finding_obj.resource_uid == "res-uid-1"
        assert finding_obj.resource_name == "ResourceName1"
        assert finding_obj.resource_details == ""
        # unroll_tags is called on a list with one tag -> expect {"env": "prod"}
        assert finding_obj.resource_tags == {"env": "prod"}
        assert finding_obj.region == "us-east-1"
        assert finding_obj.compliance == {
            "CIS-2.0": ["1.12"],
            "CIS-3.0": ["1.12"],
            "ENS-RD2022": ["op.acc.2.gcp.rbak.1"],
            "MITRE-ATTACK": ["T1098"],
        }

    @patch(
        "prowler.lib.outputs.finding.get_check_compliance",
        new=mock_get_check_compliance,
    )
    def test_transform_api_finding_azure(self):
        provider = MagicMock()
        provider.type = "azure"
        provider.identity.identity_type = "mock_identity_type"
        provider.identity.identity_id = "mock_identity_id"
        provider.identity.subscriptions = {"default": "default"}
        provider.identity.tenant_ids = ["test-ing-432a-a828-d9c965196f87"]
        provider.identity.tenant_domain = "mock_tenant_domain"
        provider.region_config.name = "AzureCloud"

        api_finding = DummyAPIFinding()
        api_finding.id = "019514b3-9a66-7cde-921e-9d1ca0531ceb"
        api_finding.inserted_at = "2025-02-17 16:17:49"
        api_finding.updated_at = "2025-02-17 16:17:49"
        api_finding.uid = (
            "prowler-azure-defender_auto_provisioning_log_analytics_agent_vms_on-"
            "test-ing-4646-bed4-e74f14020726-global-default"
        )
        api_finding.delta = "new"
        api_finding.status = "FAIL"
        api_finding.status_extended = "Defender Auto Provisioning Log Analytics Agents from subscription Azure subscription 1 is set to OFF."
        api_finding.severity = "medium"
        api_finding.impact = "medium"
        api_finding.impact_extended = ""
        api_finding.raw_result = {}
        api_finding.check_id = "defender_auto_provisioning_log_analytics_agent_vms_on"
        api_finding.check_metadata = {
            "risk": "Missing critical security information about your Azure VMs, such as security alerts, security recommendations, and change tracking.",
            "notes": "",
            "checkid": "defender_auto_provisioning_log_analytics_agent_vms_on",
            "provider": "azure",
            "severity": "medium",
            "checktype": [],
            "dependson": [],
            "relatedto": [],
            "categories": [],
            "checktitle": "Ensure that Auto provisioning of 'Log Analytics agent for Azure VMs' is Set to 'On'",
            "compliance": None,
            "relatedurl": "https://docs.microsoft.com/en-us/azure/security-center/security-center-data-security",
            "description": (
                "Ensure that Auto provisioning of 'Log Analytics agent for Azure VMs' is Set to 'On'. "
                "The Microsoft Monitoring Agent scans for various security-related configurations and events such as system updates, "
                "OS vulnerabilities, endpoint protection, and provides alerts."
            ),
            "remediation": {
                "code": {
                    "cli": "",
                    "other": "https://www.trendmicro.com/cloudoneconformity-staging/knowledge-base/azure/SecurityCenter/automatic-provisioning-of-monitoring-agent.html",
                    "nativeiac": "",
                    "terraform": "",
                },
                "recommendation": {
                    "url": "https://learn.microsoft.com/en-us/azure/defender-for-cloud/monitoring-components",
                    "text": (
                        "Ensure comprehensive visibility into possible security vulnerabilities, including missing updates, "
                        "misconfigured operating system security settings, and active threats, allowing for timely mitigation and improved overall security posture"
                    ),
                },
            },
            "servicename": "defender",
            "checkaliases": [],
            "resourcetype": "AzureDefenderPlan",
            "subservicename": "",
            "resourceidtemplate": "",
        }
        api_finding.tags = {}
        api_resource = DummyResource(
            uid="/subscriptions/test-ing-4646-bed4-e74f14020726/providers/Microsoft.Security/autoProvisioningSettings/default",
            name="default",
            resource_arn="arn",
            region="global",
            tags=[],
        )
        api_finding.resources = DummyResources(api_resource)
        api_finding.subscription = "default"
        api_finding.muted = False
        finding_obj = Finding.transform_api_finding(api_finding, provider)

        assert finding_obj.account_organization_uid == "test-ing-432a-a828-d9c965196f87"
        assert finding_obj.account_organization_name == "mock_tenant_domain"
        assert finding_obj.resource_uid == api_resource.uid
        assert finding_obj.resource_name == api_resource.name
        assert finding_obj.region == api_resource.region
        assert finding_obj.resource_tags == {}
        assert finding_obj.compliance == {
            "CIS-2.0": ["1.12"],
            "CIS-3.0": ["1.12"],
            "ENS-RD2022": ["op.acc.2.gcp.rbak.1"],
            "MITRE-ATTACK": ["T1098"],
        }

        assert finding_obj.status == Status("FAIL")
        assert finding_obj.status_extended == (
            "Defender Auto Provisioning Log Analytics Agents from subscription Azure subscription 1 is set to OFF."
        )

        meta = finding_obj.metadata
        assert meta.Provider == "azure"
        assert meta.CheckID == "defender_auto_provisioning_log_analytics_agent_vms_on"
        assert (
            meta.CheckTitle
            == "Ensure that Auto provisioning of 'Log Analytics agent for Azure VMs' is Set to 'On'"
        )
        assert meta.Severity == "medium"
        assert meta.ResourceType == "AzureDefenderPlan"
        assert (
            meta.Remediation.Recommendation.Url
            == "https://learn.microsoft.com/en-us/azure/defender-for-cloud/monitoring-components"
        )
        assert meta.Remediation.Recommendation.Text.startswith(
            "Ensure comprehensive visibility"
        )

        expected_segments = [
            "prowler-azure",
            "defender_auto_provisioning_log_analytics_agent_vms_on",
            api_resource.region,
            api_resource.name,
        ]
        for segment in expected_segments:
            assert segment in finding_obj.uid

    @patch(
        "prowler.lib.outputs.finding.get_check_compliance",
        new=mock_get_check_compliance,
    )
    def test_transform_api_finding_gcp(self):
        provider = MagicMock()
        provider.type = "gcp"
        provider.identity.profile = "gcp_profile"
        dummy_project = MagicMock()
        dummy_project.id = "project1"
        dummy_project.name = "TestProject"
        dummy_project.labels = {"env": "prod"}
        dummy_org = MagicMock()
        dummy_org.id = "org-123"
        dummy_org.display_name = "Test Org"
        dummy_project.organization = dummy_org
        provider.projects = {"project1": dummy_project}

        dummy_finding = DummyAPIFinding()
        dummy_finding.inserted_at = "2025-02-17 16:17:49"
        dummy_finding.updated_at = "2025-02-17 16:17:49"
        dummy_finding.scan = DummyScan(provider=provider)
        dummy_finding.uid = "finding-uid-gcp"
        dummy_finding.status = "PASS"
        dummy_finding.status_extended = "GCP check extended"
        check_metadata = {
            "provider": "gcp",
            "checkid": "service_gcp_check_001",
            "checktitle": "Test GCP Check",
            "checktype": [],
            "servicename": "service",
            "subservicename": "",
            "severity": "medium",
            "resourcetype": "GCPResourceType",
            "description": "GCP check description",
            "risk": "Medium risk",
            "relatedurl": "http://gcp.example.com",
            "remediation": {
                "code": {
                    "nativeiac": "iac_code",
                    "terraform": "terraform_code",
                    "cli": "cli_code",
                    "other": "other_code",
                },
                "recommendation": {"text": "Fix it", "url": "http://fix-gcp.com"},
            },
            "resourceidtemplate": "template",
            "categories": ["cat-one", "cat-two"],
            "dependson": ["dep1"],
            "relatedto": ["rel1"],
            "notes": "Some notes",
        }
        dummy_finding.check_metadata = check_metadata
        dummy_finding.raw_result = {}
        dummy_finding.project_id = "project1"
        dummy_finding.muted = True

        resource = DummyResource(
            uid="gcp-resource-uid",
            name="gcp-resource-name",
            resource_arn="arn",
            region="us-central1",
            tags=[],
        )
        dummy_finding.resources = DummyResources(resource)
        finding_obj = Finding.transform_api_finding(dummy_finding, provider)

        assert finding_obj.auth_method == "Principal: gcp_profile"
        assert finding_obj.account_uid == dummy_project.id
        assert finding_obj.account_name == dummy_project.name
        assert finding_obj.account_tags == dummy_project.labels
        assert finding_obj.resource_name == resource.name
        assert finding_obj.resource_uid == resource.uid
        assert finding_obj.region == resource.region
        assert finding_obj.account_organization_uid == dummy_project.organization.id
        assert (
            finding_obj.account_organization_name
            == dummy_project.organization.display_name
        )
        assert finding_obj.compliance == {
            "CIS-2.0": ["1.12"],
            "CIS-3.0": ["1.12"],
            "ENS-RD2022": ["op.acc.2.gcp.rbak.1"],
            "MITRE-ATTACK": ["T1098"],
        }
        assert finding_obj.status == Status("PASS")
        assert finding_obj.status_extended == "GCP check extended"
        expected_uid = f"prowler-gcp-{check_metadata['checkid']}-{dummy_project.id}-{resource.region}-{resource.name}"
        assert finding_obj.uid == expected_uid

    @patch(
        "prowler.lib.outputs.finding.get_check_compliance",
        new=mock_get_check_compliance,
    )
    def test_transform_api_finding_kubernetes(self):
        provider = MagicMock()
        provider.type = "kubernetes"
        provider.identity.context = "In-Cluster"
        provider.identity.cluster = "cluster-1"
        api_finding = DummyAPIFinding()
        api_finding.inserted_at = 1234567890
        api_finding.scan = DummyScan(provider=provider)
        api_finding.uid = "finding-uid-k8s"
        api_finding.status = "PASS"
        api_finding.status_extended = "K8s check extended"
        check_metadata = {
            "provider": "kubernetes",
            "checkid": "service_k8s_check_001",
            "checktitle": "Test K8s Check",
            "checktype": [],
            "servicename": "service",
            "subservicename": "",
            "severity": "low",
            "resourcetype": "K8sResourceType",
            "description": "K8s check description",
            "risk": "Low risk",
            "relatedurl": "http://k8s.example.com",
            "remediation": {
                "code": {
                    "nativeiac": "iac_code",
                    "terraform": "terraform_code",
                    "cli": "cli_code",
                    "other": "other_code",
                },
                "recommendation": {"text": "Fix it", "url": "http://fix-k8s.com"},
            },
            "resourceidtemplate": "template",
            "categories": ["cat-one"],
            "dependson": [],
            "relatedto": [],
            "notes": "K8s notes",
        }
        api_finding.check_metadata = check_metadata
        api_finding.raw_result = {}
        api_finding.resource_name = "k8s-resource-name"
        api_finding.resource_id = "k8s-resource-uid"
        resource = DummyResource(
            uid="k8s-resource-uid",
            name="k8s-resource-name",
            resource_arn="arn",
            region="",
            tags=[],
        )
        resource.region = "namespace: default"
        api_finding.resources = DummyResources(resource)
        api_finding.muted = True
        finding_obj = Finding.transform_api_finding(api_finding, provider)
        assert finding_obj.auth_method == "in-cluster"
        assert finding_obj.resource_name == "k8s-resource-name"
        assert finding_obj.resource_uid == "k8s-resource-uid"
        assert finding_obj.account_name == "context: In-Cluster"
        assert finding_obj.account_uid == "cluster-1"
        assert finding_obj.region == "namespace: default"

    @patch(
        "prowler.lib.outputs.finding.get_check_compliance",
        new=mock_get_check_compliance,
    )
    def test_transform_api_finding_m365(self):
        provider = MagicMock()
        provider.type = "m365"
        provider.identity.identity_type = "ms_identity_type"
        provider.identity.identity_id = "ms_identity_id"
        provider.identity.tenant_id = "ms-tenant-id"
        provider.identity.tenant_domain = "ms-tenant-domain"
        dummy_finding = DummyAPIFinding()
        dummy_finding.inserted_at = 1234567890
        dummy_finding.scan = DummyScan(provider=provider)
        dummy_finding.uid = "finding-uid-m365"
        dummy_finding.status = "PASS"
        dummy_finding.status_extended = "M365 check extended"
        check_metadata = {
            "provider": "m365",
            "checkid": "service_m365_check_001",
            "checktitle": "Test M365 Check",
            "checktype": [],
            "servicename": "service",
            "subservicename": "",
            "severity": "high",
            "resourcetype": "M365ResourceType",
            "description": "M365 check description",
            "risk": "High risk",
            "relatedurl": "http://m365.example.com",
            "remediation": {
                "code": {
                    "nativeiac": "iac_code",
                    "terraform": "terraform_code",
                    "cli": "cli_code",
                    "other": "other_code",
                },
                "recommendation": {"text": "Fix it", "url": "http://fix-m365.com"},
            },
            "resourceidtemplate": "template",
            "categories": ["cat-one"],
            "dependson": [],
            "relatedto": [],
            "notes": "M365 notes",
        }
        dummy_finding.check_metadata = check_metadata
        dummy_finding.raw_result = {}
        dummy_finding.resource_name = "ms-resource-name"
        dummy_finding.resource_id = "ms-resource-uid"
        dummy_finding.location = "global"
        resource = DummyResource(
            uid="ms-resource-uid",
            name="ms-resource-name",
            resource_arn="arn",
            region="global",
            tags=[],
        )
        dummy_finding.resources = DummyResources(resource)
        dummy_finding.muted = True
        finding_obj = Finding.transform_api_finding(dummy_finding, provider)
        assert finding_obj.auth_method == "ms_identity_type: ms_identity_id"
        assert finding_obj.account_uid == "ms-tenant-id"
        assert finding_obj.account_name == "ms-tenant-domain"
        assert finding_obj.resource_name == "ms-resource-name"
        assert finding_obj.resource_uid == "ms-resource-uid"
        assert finding_obj.region == "global"

    def test_transform_findings_stats_all_fails_muted(self):
        """
        Test _transform_findings_stats when every failing finding is muted.
        """
        # Create a dummy scan object with a unique_resource_count
        dummy_scan = SimpleNamespace(unique_resource_count=10)
        # Build summaries covering each severity branch.
        ss1 = SimpleNamespace(
            _pass=1, fail=2, total=3, muted=2, severity="critical", scan=dummy_scan
        )
        ss2 = SimpleNamespace(
            _pass=2, fail=0, total=2, muted=0, severity="high", scan=dummy_scan
        )
        ss3 = SimpleNamespace(
            _pass=2, fail=3, total=5, muted=3, severity="medium", scan=dummy_scan
        )
        ss4 = SimpleNamespace(
            _pass=3, fail=0, total=3, muted=0, severity="low", scan=dummy_scan
        )

        summaries = [ss1, ss2, ss3, ss4]
        stats = Finding._transform_findings_stats(summaries)

        # Expected calculations:
        # total_pass = 1+2+2+3 = 8
        # total_fail = 2+0+3+0 = 5
        # findings_count = 3+2+5+3 = 13
        # muted_pass = (ss1: 1) + (ss3: 2) = 3
        # muted_fail = (ss1: 2) + (ss3: 3) = 5
        expected = {
            "total_pass": 8,
            "total_muted_pass": 3,
            "total_fail": 5,
            "total_muted_fail": 5,
            "resources_count": 10,
            "findings_count": 13,
            "total_critical_severity_fail": 2,
            "total_critical_severity_pass": 1,
            "total_high_severity_fail": 0,
            "total_high_severity_pass": 2,
            "total_medium_severity_fail": 3,
            "total_medium_severity_pass": 2,
            "total_low_severity_fail": 0,
            "total_low_severity_pass": 3,
            "all_fails_are_muted": True,  # total_fail equals muted_fail and total_fail > 0
        }
        assert stats == expected

    def test_transform_findings_stats_not_all_fails_muted(self):
        """
        Test _transform_findings_stats when at least one failing finding is not muted.
        """
        dummy_scan = SimpleNamespace(unique_resource_count=5)
        # Build summaries: one summary has fail > 0 but muted == 0
        ss1 = SimpleNamespace(
            _pass=1, fail=2, total=3, muted=0, severity="critical", scan=dummy_scan
        )
        ss2 = SimpleNamespace(
            _pass=2, fail=1, total=3, muted=1, severity="high", scan=dummy_scan
        )
        summaries = [ss1, ss2]
        stats = Finding._transform_findings_stats(summaries)

        # Expected calculations:
        # total_pass = 1+2 = 3
        # total_fail = 2+1 = 3
        # findings_count = 3+3 = 6
        # muted_pass = (ss2: 2) since ss1 muted is 0
        # muted_fail = (ss2: 1)
        # Severity breakdown: critical: pass 1, fail 2; high: pass 2, fail 1
        expected = {
            "total_pass": 3,
            "total_muted_pass": 2,
            "total_fail": 3,
            "total_muted_fail": 1,
            "resources_count": 5,
            "findings_count": 6,
            "total_critical_severity_fail": 2,
            "total_critical_severity_pass": 1,
            "total_high_severity_fail": 1,
            "total_high_severity_pass": 2,
            "total_medium_severity_fail": 0,
            "total_medium_severity_pass": 0,
            "total_low_severity_fail": 0,
            "total_low_severity_pass": 0,
            "all_fails_are_muted": False,  # 3 (total_fail) != 1 (muted_fail)
        }
        assert stats == expected

    def test_transform_api_finding_validation_error(self):
        """
        Test that if required data is missing (causing a ValidationError)
        the function logs the error and re-raises the exception.
        For example, if the metadata dict is missing required keys.
        """
        provider = DummyProvider(uid="account123")
        # Create a dummy API finding that is missing some required metadata
        dummy_finding = DummyAPIFinding()
        dummy_finding.inserted_at = 1234567890
        dummy_finding.scan = DummyScan(provider=provider)
        dummy_finding.uid = "finding-uid-invalid"
        dummy_finding.status = "PASS"
        dummy_finding.status_extended = "extended"
        # Missing required metadata keys – using an empty dict
        dummy_finding.check_metadata = {}
        # Provide a dummy resources with a minimal resource
        tag = DummyTag("env", "prod")
        resource = DummyResource(
            uid="res-uid-1",
            name="ResourceName1",
            resource_arn="arn",
            region="us-east-1",
            tags=[tag],
        )
        dummy_finding.resources = DummyResources(resource)

        with pytest.raises(KeyError):
            Finding.transform_api_finding(dummy_finding, provider)
