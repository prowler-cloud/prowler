# from datetime import datetime
from os import path

from py_ocsf_models.events.base_event import SeverityID, StatusID
from py_ocsf_models.events.findings.detection_finding import (
    TypeID as DetectionFindingTypeID,
)
from py_ocsf_models.events.findings.finding import ActivityID, FindingInformation
from py_ocsf_models.objects.account import Account, TypeID
from py_ocsf_models.objects.cloud import Cloud
from py_ocsf_models.objects.group import Group
from py_ocsf_models.objects.metadata import Metadata
from py_ocsf_models.objects.organization import Organization
from py_ocsf_models.objects.product import Product

# from py_ocsf_models.events.findings.detection_finding import DetectionFinding
from py_ocsf_models.objects.remediation import Remediation
from py_ocsf_models.objects.resource_details import ResourceDetails

from prowler.config.config import prowler_version
from prowler.lib.outputs.json_ocsf.json_ocsf import (
    fill_json_ocsf,
    get_account_type_id_by_provider,
    get_finding_status_id,
)
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1

METADATA_FIXTURE_PATH = (
    f"{path.dirname(path.realpath(__file__))}/../fixtures/metadata.json"
)


class TestOutputJSONOCSF:
    # test_fill_json_ocsf_iso_format_timestamp
    def test_finding_output_cloud_pass_low_muted(self):
        finding_output = generate_finding_output(
            "PASS", "low", True, AWS_REGION_EU_WEST_1
        )

        finding_json_ocsf = fill_json_ocsf(finding_output)

        # Activity
        assert finding_json_ocsf.activity_id == ActivityID.Create.value
        assert finding_json_ocsf.activity_name == ActivityID.Create.name

        # Finding Information
        finding_information = finding_json_ocsf.finding_info

        assert isinstance(finding_information, FindingInformation)
        assert finding_information.created_time == finding_output.timestamp
        assert finding_information.desc == finding_output.description
        assert finding_information.title == finding_output.check_title
        assert finding_information.uid == finding_output.finding_uid
        assert finding_information.product_uid == "prowler"

        # Event time
        assert finding_json_ocsf.event_time == finding_output.timestamp

        # Remediation
        remediation = finding_json_ocsf.remediation
        assert isinstance(remediation, Remediation)
        assert remediation.desc == finding_output.remediation_recommendation_text
        assert remediation.references == []

        # Severity
        assert finding_json_ocsf.severity_id == SeverityID.Low
        assert finding_json_ocsf.severity == SeverityID.Low.name

        # Status
        assert finding_json_ocsf.status_id == StatusID.Suppressed.value
        assert finding_json_ocsf.status == StatusID.Suppressed.name
        assert finding_json_ocsf.status_code == finding_output.status
        assert finding_json_ocsf.status_detail == finding_output.status_extended

        # Risk
        assert finding_json_ocsf.risk_details == finding_output.risk

        # Unmapped Data
        assert finding_json_ocsf.unmapped == {
            "check_type": finding_output.check_type,
            "related_url": finding_output.related_url,
            "categories": finding_output.categories,
            "depends_on": finding_output.depends_on,
            "related_to": finding_output.related_to,
            "notes": finding_output.notes,
            "compliance": finding_output.compliance,
        }

        # ResourceDetails
        resource_details = finding_json_ocsf.resources

        assert len(resource_details) == 1
        assert isinstance(resource_details, list)
        assert isinstance(resource_details[0], ResourceDetails)
        assert resource_details[0].labels == []
        assert resource_details[0].name == finding_output.resource_name
        assert resource_details[0].uid == finding_output.resource_uid
        assert resource_details[0].type == finding_output.resource_type
        assert resource_details[0].cloud_partition == finding_output.partition
        assert resource_details[0].region == finding_output.region
        assert resource_details[0].data == {"details": finding_output.resource_details}

        resource_details_group = resource_details[0].group
        assert isinstance(resource_details_group, Group)
        assert resource_details_group.name == finding_output.service_name

        # Metadata
        metadata = finding_json_ocsf.metadata
        assert isinstance(metadata, Metadata)
        assert metadata.event_code == finding_output.check_id

        metadata_product = metadata.product
        assert isinstance(metadata_product, Product)
        assert metadata_product.name == "Prowler"
        assert metadata_product.vendor_name == "Prowler"
        assert metadata_product.version == prowler_version

        # Type
        assert finding_json_ocsf.type_uid == DetectionFindingTypeID.Create
        assert finding_json_ocsf.type_name == DetectionFindingTypeID.Create.name

        # Cloud
        cloud = finding_json_ocsf.cloud
        assert isinstance(cloud, Cloud)
        assert cloud.provider == "aws"
        assert cloud.region == finding_output.region

        cloud_account = cloud.account
        assert isinstance(cloud_account, Account)
        assert cloud_account.name == finding_output.account_name
        assert cloud_account.type_id == TypeID.AWS_Account
        assert cloud_account.type == TypeID.AWS_Account.name
        assert cloud_account.uid == finding_output.account_uid
        assert cloud_account.labels == finding_output.account_tags

        cloud_organization = cloud.org
        assert isinstance(cloud_organization, Organization)
        assert cloud_organization.uid == finding_output.account_organization_uid
        assert cloud_organization.name == finding_output.account_organization_name

    def test_finding_output_cloud_fail_low_not_muted(self):
        finding_output = generate_finding_output(
            "FAIL", "low", False, AWS_REGION_EU_WEST_1
        )

        finding_json_ocsf = fill_json_ocsf(finding_output)

        # Status
        assert finding_json_ocsf.status_id == StatusID.New.value
        assert finding_json_ocsf.status == StatusID.New.name
        assert finding_json_ocsf.status_code == finding_output.status
        assert finding_json_ocsf.status_detail == finding_output.status_extended

    def test_finding_output_cloud_pass_low_not_muted(self):
        finding_output = generate_finding_output(
            "PASS", "low", False, AWS_REGION_EU_WEST_1
        )

        finding_json_ocsf = fill_json_ocsf(finding_output)

        # Status
        assert finding_json_ocsf.status_id == StatusID.Other.value
        assert finding_json_ocsf.status == StatusID.Other.name
        assert finding_json_ocsf.status_code == finding_output.status
        assert finding_json_ocsf.status_detail == finding_output.status_extended

    # Returns TypeID.AWS_Account when provider is 'aws'
    def test_returns_aws_account_when_provider_is_aws(self):
        provider = "aws"
        result = get_account_type_id_by_provider(provider)

        assert result == TypeID.AWS_Account

    # Returns TypeID.Azure_AD_Account when provider is 'azure'
    def test_returns_azure_ad_account_when_provider_is_azure(self):
        provider = "azure"
        result = get_account_type_id_by_provider(provider)

        assert result == TypeID.Azure_AD_Account

    # Returns TypeID.GCP_Account when provider is 'gcp'
    def test_returns_gcp_account_when_provider_is_gcp(self):
        provider = "gcp"
        result = get_account_type_id_by_provider(provider)

        assert result == TypeID.GCP_Account

    # Returns TypeID.Other when provider is None
    def test_returns_other_when_provider_is_none(self):
        provider = None
        result = get_account_type_id_by_provider(provider)

        assert result == TypeID.Other

    # Returns StatusID.New when status is "FAIL" and muted is False
    def test_new_when_status_fail_and_not_muted(self):
        status = "FAIL"
        muted = False
        result = get_finding_status_id(status, muted)

        assert result == StatusID.New

    # Returns StatusID.Suppressed when status is "FAIL" and muted is True
    def test_suppressed_when_status_fail_and_muted(self):
        status = "FAIL"
        muted = True
        result = get_finding_status_id(status, muted)

        assert result == StatusID.Suppressed

    # Returns StatusID.Other when status is None and muted is False
    def test_other_when_status_whatever_and_not_muted(self):
        status = None
        muted = False
        result = get_finding_status_id(status, muted)

        assert result == StatusID.Other

    # Returns StatusID.Suppresed when status is None and muted is True
    def test_other_when_status_whatever_and_muted(self):
        status = None
        muted = True
        result = get_finding_status_id(status, muted)

        assert result == StatusID.Suppressed

    # Returns StatusID.Suppressed when muted is True and status is not "FAIL"
    def test_suppressed_when_status_pass_and_muted(self):
        status = "PASS"
        muted = True
        result = get_finding_status_id(status, muted)

        assert result == StatusID.Suppressed

    # Returns StatusID.Other when muted is False and status is not "FAIL"
    def test_other_when_status_pass_and_not_muted(self):
        status = "PASS"
        muted = False
        result = get_finding_status_id(status, muted)

        assert result == StatusID.Other
