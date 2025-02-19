from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

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
    def __init__(self, uid, name, region, tags):
        self.uid = uid
        self.name = name
        self.region = region
        self.tags = DummyTags(tags)


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

    pass


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
        check_output.resource = {}

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
        check_output.resource = {}

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
        check_output.resource = {}

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
        check_output.resource = {}

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

    def test_transform_api_finding(self):
        """
        Test that a dummy API Finding is correctly
        transformed into a Finding instance.
        """
        # Set up the dummy API finding attributes
        inserted_at = 1234567890
        provider = DummyProvider(uid="account123")
        scan = DummyScan(provider=provider)

        # Create a dummy resource with one tag
        tag = DummyTag("env", "prod")
        resource = DummyResource(
            uid="res-uid-1", name="ResourceName1", region="us-east-1", tags=[tag]
        )
        resources = DummyResources(resource)

        # Create a dummy check_metadata dict with all required fields
        check_metadata = {
            "provider": "test_provider",
            "checkid": "check-001",
            "checktitle": "Test Check",
            "checktype": ["type1"],
            "servicename": "TestService",
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

        # Call the transform_api_finding classmethod
        finding_obj = Finding.transform_api_finding(dummy_finding, provider)

        # Fields directly set in transform_api_finding
        assert finding_obj.auth_method == "profile: "
        assert finding_obj.timestamp == inserted_at
        assert finding_obj.account_uid == "account123"
        assert finding_obj.account_name == ""

        # Check that metadata was built correctly
        meta = finding_obj.metadata
        assert meta.Provider == "test_provider"
        assert meta.CheckID == "check-001"
        assert meta.CheckTitle == "Test Check"
        assert meta.CheckType == ["type1"]
        assert meta.ServiceName == "TestService"
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
        assert finding_obj.uid == "finding-uid-1"
        assert finding_obj.status == Status("FAIL")
        assert finding_obj.status_extended == "extended"
        # From the dummy resource
        assert finding_obj.resource_uid == "res-uid-1"
        assert finding_obj.resource_name == "ResourceName1"
        assert finding_obj.resource_details == ""
        # unroll_tags is called on a list with one tag -> expect {"env": "prod"}
        assert finding_obj.resource_tags == {"env": "prod"}
        assert finding_obj.region == "us-east-1"
        # compliance is hardcoded to an empty dict
        assert finding_obj.compliance == {}

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
            uid="res-uid-1", name="ResourceName1", region="us-east-1", tags=[tag]
        )
        dummy_finding.resources = DummyResources(resource)

        with pytest.raises(KeyError):
            Finding.transform_api_finding(dummy_finding, provider)
