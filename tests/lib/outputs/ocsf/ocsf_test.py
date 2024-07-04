import json
from datetime import datetime
from io import StringIO

from mock import patch
from py_ocsf_models.events.base_event import SeverityID, StatusID
from py_ocsf_models.events.findings.detection_finding import DetectionFinding
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
from py_ocsf_models.objects.remediation import Remediation
from py_ocsf_models.objects.resource_details import ResourceDetails

from prowler.config.config import prowler_version
from prowler.lib.outputs.ocsf.ocsf import OCSF
from tests.lib.outputs.fixtures.fixtures import generate_finding_output
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1

now = datetime.now()
expected_json_output = json.dumps(
    [
        {
            "metadata": {
                "event_code": "test-check-id",
                "product": {
                    "name": "Prowler",
                    "vendor_name": "Prowler",
                    "version": "4.2.4",
                },
                "version": "1.2.0",
            },
            "severity_id": 2,
            "severity": "Low",
            "status": "New",
            "status_code": "FAIL",
            "status_detail": "status extended",
            "status_id": 1,
            "unmapped": {
                "check_type": "test-type",
                "related_url": "test-url",
                "categories": "test-category",
                "depends_on": "test-dependency",
                "related_to": "test-related-to",
                "notes": "test-notes",
                "compliance": {"test-compliance": "test-compliance"},
            },
            "activity_name": "Create",
            "activity_id": 1,
            "finding_info": {
                "created_time": now.isoformat(),
                "desc": "check description",
                "product_uid": "prowler",
                "title": "test-check-id",
                "uid": "test-unique-finding",
            },
            "resources": [
                {
                    "cloud_partition": "aws",
                    "region": "eu-west-1",
                    "data": {"details": "resource_details"},
                    "group": {"name": "test-service"},
                    "labels": [],
                    "name": "resource_name",
                    "type": "test-resource",
                    "uid": "resource-id",
                }
            ],
            "category_name": "Findings",
            "category_uid": 2,
            "class_name": "DetectionFinding",
            "class_uid": 2004,
            "cloud": {
                "account": {
                    "name": "123456789012",
                    "type": "AWS_Account",
                    "type_id": 10,
                    "uid": "123456789012",
                    "labels": ["test-tag:test-value"],
                },
                "org": {"name": "test-organization", "uid": "test-organization-id"},
                "provider": "aws",
                "region": "eu-west-1",
            },
            "event_time": now.isoformat(),
            "remediation": {"desc": "", "references": []},
            "risk_details": "test-risk",
            "type_uid": 200401,
            "type_name": "Create",
        }
    ]
)


class TestOCSF:
    def test_transform(self):
        findings = [generate_finding_output("FAIL", "low", False, AWS_REGION_EU_WEST_1)]

        ocsf = OCSF(findings)

        output_data = ocsf.data[0]
        assert isinstance(output_data, DetectionFinding)

    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [
            generate_finding_output("FAIL", "low", False, AWS_REGION_EU_WEST_1, now)
        ]

        output = OCSF(findings)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()

        assert json.loads(content) == json.loads(expected_json_output)

    def test_finding_output_cloud_pass_low_muted(self):
        finding_output = generate_finding_output(
            "PASS", "low", True, AWS_REGION_EU_WEST_1
        )

        finding_ocsf = OCSF([finding_output])
        finding_ocsf = finding_ocsf.data[0]
        # Activity
        assert finding_ocsf.activity_id == ActivityID.Create.value
        assert finding_ocsf.activity_name == ActivityID.Create.name

        # Finding Information
        finding_information = finding_ocsf.finding_info

        assert isinstance(finding_information, FindingInformation)
        assert finding_information.created_time == finding_output.timestamp
        assert finding_information.desc == finding_output.description
        assert finding_information.title == finding_output.check_title
        assert finding_information.uid == finding_output.finding_uid
        assert finding_information.product_uid == "prowler"

        # Event time
        assert finding_ocsf.event_time == finding_output.timestamp

        # Remediation
        remediation = finding_ocsf.remediation
        assert isinstance(remediation, Remediation)
        assert remediation.desc == finding_output.remediation_recommendation_text
        assert remediation.references == []

        # Severity
        assert finding_ocsf.severity_id == SeverityID.Low
        assert finding_ocsf.severity == SeverityID.Low.name

        # Status
        assert finding_ocsf.status_id == StatusID.Suppressed.value
        assert finding_ocsf.status == StatusID.Suppressed.name
        assert finding_ocsf.status_code == finding_output.status
        assert finding_ocsf.status_detail == finding_output.status_extended

        # Risk
        assert finding_ocsf.risk_details == finding_output.risk

        # Unmapped Data
        assert finding_ocsf.unmapped == {
            "check_type": finding_output.check_type,
            "related_url": finding_output.related_url,
            "categories": finding_output.categories,
            "depends_on": finding_output.depends_on,
            "related_to": finding_output.related_to,
            "notes": finding_output.notes,
            "compliance": finding_output.compliance,
        }

        # ResourceDetails
        resource_details = finding_ocsf.resources

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
        metadata = finding_ocsf.metadata
        assert isinstance(metadata, Metadata)
        assert metadata.event_code == finding_output.check_id

        metadata_product = metadata.product
        assert isinstance(metadata_product, Product)
        assert metadata_product.name == "Prowler"
        assert metadata_product.vendor_name == "Prowler"
        assert metadata_product.version == prowler_version

        # Type
        assert finding_ocsf.type_uid == DetectionFindingTypeID.Create
        assert finding_ocsf.type_name == DetectionFindingTypeID.Create.name

        # Cloud
        cloud = finding_ocsf.cloud
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

    def test_finding_output_kubernetes(self):
        finding_output = generate_finding_output(
            "PASS", "low", True, AWS_REGION_EU_WEST_1, provider="kubernetes"
        )

        finding_ocsf = OCSF([finding_output])
        finding_ocsf = finding_ocsf.data[0]

        assert finding_ocsf.container.name == finding_output.resource_name
        assert finding_ocsf.container.uid == finding_output.resource_uid

    def test_finding_output_cloud_fail_low_not_muted(self):
        finding_output = generate_finding_output(
            "FAIL", "low", False, AWS_REGION_EU_WEST_1
        )

        finding_ocsf = OCSF([finding_output])
        finding_ocsf = finding_ocsf.data[0]

        # Status
        assert finding_ocsf.status_id == StatusID.New.value
        assert finding_ocsf.status == StatusID.New.name
        assert finding_ocsf.status_code == finding_output.status
        assert finding_ocsf.status_detail == finding_output.status_extended

    def test_finding_output_cloud_pass_low_not_muted(self):
        finding_output = generate_finding_output(
            "PASS", "low", False, AWS_REGION_EU_WEST_1
        )

        finding_ocsf = OCSF([finding_output])
        finding_ocsf = finding_ocsf.data[0]

        # Status
        assert finding_ocsf.status_id == StatusID.Other.value
        assert finding_ocsf.status == StatusID.Other.name
        assert finding_ocsf.status_code == finding_output.status
        assert finding_ocsf.status_detail == finding_output.status_extended

    # Returns TypeID.AWS_Account when provider is 'aws'
    def test_returns_aws_account_when_provider_is_aws(self):
        provider = "aws"
        assert OCSF.get_account_type_id_by_provider(provider) == TypeID.AWS_Account

    # Returns TypeID.Azure_AD_Account when provider is 'azure'
    def test_returns_azure_ad_account_when_provider_is_azure(self):
        provider = "azure"
        assert OCSF.get_account_type_id_by_provider(provider) == TypeID.Azure_AD_Account

    # Returns TypeID.GCP_Account when provider is 'gcp'
    def test_returns_gcp_account_when_provider_is_gcp(self):
        provider = "gcp"
        assert OCSF.get_account_type_id_by_provider(provider) == TypeID.GCP_Account

    # Returns TypeID.Other when provider is None
    def test_returns_other_when_provider_is_none(self):
        provider = "None"
        assert OCSF.get_account_type_id_by_provider(provider) == TypeID.Other

    # Returns StatusID.New when status is "FAIL" and muted is False
    def test_new_when_status_fail_and_not_muted(self):
        status = "FAIL"
        muted = False
        assert OCSF.get_finding_status_id(status, muted) == StatusID.New

    # Returns StatusID.Suppressed when status is "FAIL" and muted is True
    def test_suppressed_when_status_fail_and_muted(self):
        status = "FAIL"
        muted = True
        assert OCSF.get_finding_status_id(status, muted) == StatusID.Suppressed

    # Returns StatusID.Other when status is PASS and muted is False
    def test_other_when_status_whatever_and_not_muted(self):
        status = "PASS"
        muted = False
        assert OCSF.get_finding_status_id(status, muted) == StatusID.Other

    # Returns StatusID.Suppresed when status is PASS and muted is True
    def test_other_when_status_whatever_and_muted(self):
        status = "PASS"
        muted = True
        assert OCSF.get_finding_status_id(status, muted) == StatusID.Suppressed

    # Returns StatusID.Suppressed when muted is True and status is not "FAIL"
    def test_suppressed_when_status_pass_and_muted(self):
        status = "PASS"
        muted = True
        assert OCSF.get_finding_status_id(status, muted) == StatusID.Suppressed

    # Returns StatusID.Other when muted is False and status is not "FAIL"
    def test_other_when_status_pass_and_not_muted(self):
        status = "PASS"
        muted = False
        assert OCSF.get_finding_status_id(status, muted) == StatusID.Other
