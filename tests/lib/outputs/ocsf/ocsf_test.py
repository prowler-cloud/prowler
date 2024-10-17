import json
from datetime import datetime
from io import StringIO

import requests
from freezegun import freeze_time
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


class TestOCSF:
    # TODO: improve this test checking the fields
    def test_transform(self):
        findings = [
            generate_finding_output(
                status="FAIL",
                severity="low",
                muted=False,
                region=AWS_REGION_EU_WEST_1,
                resource_tags={"Name": "test", "Environment": "dev"},
            )
        ]

        ocsf = OCSF(findings)

        output_data = ocsf.data[0]

        assert isinstance(output_data, DetectionFinding)
        assert output_data.activity_id == ActivityID.Create.value
        assert output_data.activity_name == ActivityID.Create.name
        assert output_data.message == findings[0].status_extended
        assert output_data.finding_info.created_time == int(
            findings[0].timestamp.timestamp()
        )
        assert output_data.finding_info.created_time_dt == findings[0].timestamp
        assert output_data.finding_info.desc == findings[0].metadata.Description
        assert output_data.finding_info.title == findings[0].metadata.CheckTitle
        assert output_data.finding_info.uid == findings[0].uid
        assert output_data.finding_info.product_uid == "prowler"
        assert output_data.finding_info.types == ["test-type"]
        assert output_data.time == int(findings[0].timestamp.timestamp())
        assert output_data.time_dt == findings[0].timestamp
        assert (
            output_data.remediation.desc
            == findings[0].metadata.Remediation.Recommendation.Text
        )
        assert output_data.remediation.references == []
        assert output_data.severity_id == SeverityID.Low
        assert output_data.severity == SeverityID.Low.name
        assert output_data.status_id == StatusID.New.value
        assert output_data.status == StatusID.New.name
        assert output_data.status_code == findings[0].status
        assert output_data.status_detail == findings[0].status_extended
        assert output_data.risk_details == findings[0].metadata.Risk
        assert output_data.resources[0].labels == ["Name:test", "Environment:dev"]
        assert output_data.resources[0].name == findings[0].resource_name
        assert output_data.resources[0].uid == findings[0].resource_uid
        assert output_data.resources[0].type == findings[0].metadata.ResourceType
        assert output_data.resources[0].cloud_partition == findings[0].partition
        assert output_data.resources[0].region == findings[0].region
        assert output_data.resources[0].data == {
            "details": findings[0].resource_details
        }
        assert output_data.metadata.profiles == ["cloud", "datetime"]
        assert output_data.metadata.tenant_uid == "test-organization-id"
        assert output_data.metadata.event_code == findings[0].metadata.CheckID
        assert output_data.metadata.product.name == "Prowler"
        assert output_data.metadata.product.vendor_name == "Prowler"
        assert output_data.metadata.product.uid == "prowler"
        assert output_data.metadata.product.version == prowler_version
        assert output_data.type_uid == DetectionFindingTypeID.Create
        assert (
            output_data.type_name
            == f"Detection Finding: {DetectionFindingTypeID.Create.name}"
        )
        assert output_data.unmapped == {
            "related_url": findings[0].metadata.RelatedUrl,
            "categories": findings[0].metadata.Categories,
            "depends_on": findings[0].metadata.DependsOn,
            "related_to": findings[0].metadata.RelatedTo,
            "notes": findings[0].metadata.Notes,
            "compliance": findings[0].compliance,
        }

    def test_validate_ocsf(self):
        mock_file = StringIO()
        findings = [
            generate_finding_output(
                status="FAIL",
                severity="low",
                muted=False,
                region=AWS_REGION_EU_WEST_1,
                timestamp=datetime.now(),
                resource_details="resource_details",
                resource_name="resource_name",
                resource_uid="resource-id",
                status_extended="status extended",
            )
        ]

        output = OCSF(findings)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        json_data = json.loads(content)
        url = "https://schema.ocsf.io/api/v2/validate"
        headers = {"content-type": "application/json"}
        response = requests.post(url, headers=headers, json=json_data[0])
        assert response.json()["error_count"] == 0

    @freeze_time(datetime.now())
    def test_batch_write_data_to_file(self):
        mock_file = StringIO()
        findings = [
            generate_finding_output(
                status="FAIL",
                severity="low",
                muted=False,
                region=AWS_REGION_EU_WEST_1,
                timestamp=datetime.now(),
                resource_details="resource_details",
                resource_name="resource_name",
                resource_uid="resource-id",
                status_extended="status extended",
            )
        ]

        expected_json_output = [
            {
                "message": "status extended",
                "metadata": {
                    "event_code": "test-check-id",
                    "product": {
                        "name": "Prowler",
                        "uid": "prowler",
                        "vendor_name": "Prowler",
                        "version": prowler_version,
                    },
                    "version": "1.3.0",
                    "profiles": ["cloud", "datetime"],
                    "tenant_uid": "test-organization-id",
                },
                "severity_id": 2,
                "severity": "Low",
                "status": "New",
                "status_code": "FAIL",
                "status_detail": "status extended",
                "status_id": 1,
                "unmapped": {
                    "related_url": "test-url",
                    "categories": ["test-category"],
                    "depends_on": ["test-dependency"],
                    "related_to": ["test-related-to"],
                    "notes": "test-notes",
                    "compliance": {"test-compliance": "test-compliance"},
                },
                "activity_name": "Create",
                "activity_id": 1,
                "finding_info": {
                    "created_time": int(datetime.now().timestamp()),
                    "created_time_dt": datetime.now().isoformat(),
                    "desc": "check description",
                    "product_uid": "prowler",
                    "title": "test-check-id",
                    "uid": "test-unique-finding",
                    "types": ["test-type"],
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
                "class_name": "Detection Finding",
                "class_uid": 2004,
                "cloud": {
                    "account": {
                        "name": "123456789012",
                        "type": "AWS Account",
                        "type_id": 10,
                        "uid": "123456789012",
                        "labels": ["test-tag:test-value"],
                    },
                    "org": {
                        "name": "test-organization",
                        "uid": "test-organization-id",
                    },
                    "provider": "aws",
                    "region": "eu-west-1",
                },
                "time": int(datetime.now().timestamp()),
                "time_dt": datetime.now().isoformat(),
                "remediation": {"desc": "", "references": []},
                "risk_details": "test-risk",
                "type_uid": 200401,
                "type_name": "Detection Finding: Create",
            }
        ]

        output = OCSF(findings)
        output._file_descriptor = mock_file

        with patch.object(mock_file, "close", return_value=None):
            output.batch_write_data_to_file()

        mock_file.seek(0)
        content = mock_file.read()
        assert json.loads(content) == expected_json_output

    def test_batch_write_data_to_file_without_findings(self):
        assert not hasattr(OCSF([]), "_file_descriptor")

    def test_finding_output_cloud_pass_low_muted(self):
        finding_output = generate_finding_output(
            status="PASS",
            severity="low",
            muted=True,
            region=AWS_REGION_EU_WEST_1,
            resource_tags={"Name": "test", "Environment": "dev"},
        )

        finding_ocsf = OCSF([finding_output])
        finding_ocsf = finding_ocsf.data[0]
        # Activity
        assert finding_ocsf.activity_id == ActivityID.Create.value
        assert finding_ocsf.activity_name == ActivityID.Create.name

        # Finding Information
        finding_information = finding_ocsf.finding_info

        assert isinstance(finding_information, FindingInformation)
        assert finding_information.created_time == int(
            finding_output.timestamp.timestamp()
        )
        assert finding_information.created_time_dt == finding_output.timestamp
        assert finding_information.desc == finding_output.metadata.Description
        assert finding_information.title == finding_output.metadata.CheckTitle
        assert finding_information.uid == finding_output.uid
        assert finding_information.product_uid == "prowler"

        # Event time
        assert finding_ocsf.time == int(finding_output.timestamp.timestamp())
        assert finding_ocsf.time_dt == finding_output.timestamp

        # Remediation
        remediation = finding_ocsf.remediation
        assert isinstance(remediation, Remediation)
        assert (
            remediation.desc == finding_output.metadata.Remediation.Recommendation.Text
        )
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
        assert finding_ocsf.risk_details == finding_output.metadata.Risk

        # Unmapped Data
        assert finding_ocsf.unmapped == {
            "related_url": finding_output.metadata.RelatedUrl,
            "categories": finding_output.metadata.Categories,
            "depends_on": finding_output.metadata.DependsOn,
            "related_to": finding_output.metadata.RelatedTo,
            "notes": finding_output.metadata.Notes,
            "compliance": finding_output.compliance,
        }

        # ResourceDetails
        resource_details = finding_ocsf.resources

        assert len(resource_details) == 1
        assert isinstance(resource_details, list)
        assert isinstance(resource_details[0], ResourceDetails)
        assert resource_details[0].labels == ["Name:test", "Environment:dev"]
        assert resource_details[0].name == finding_output.resource_name
        assert resource_details[0].uid == finding_output.resource_uid
        assert resource_details[0].type == finding_output.metadata.ResourceType
        assert resource_details[0].cloud_partition == finding_output.partition
        assert resource_details[0].region == finding_output.region
        assert resource_details[0].data == {"details": finding_output.resource_details}

        resource_details_group = resource_details[0].group
        assert isinstance(resource_details_group, Group)
        assert resource_details_group.name == finding_output.metadata.ServiceName

        # Metadata
        metadata = finding_ocsf.metadata
        assert isinstance(metadata, Metadata)
        assert metadata.event_code == finding_output.metadata.CheckID

        metadata_product = metadata.product
        assert isinstance(metadata_product, Product)
        assert metadata_product.name == "Prowler"
        assert metadata_product.vendor_name == "Prowler"
        assert metadata_product.version == prowler_version

        # Type
        assert finding_ocsf.type_uid == DetectionFindingTypeID.Create
        assert (
            finding_ocsf.type_name
            == f"Detection Finding: {DetectionFindingTypeID.Create.name}"
        )

        # Cloud
        cloud = finding_ocsf.cloud
        assert isinstance(cloud, Cloud)
        assert cloud.provider == "aws"
        assert cloud.region == finding_output.region

        cloud_account = cloud.account
        assert isinstance(cloud_account, Account)
        assert cloud_account.name == finding_output.account_name
        assert cloud_account.type_id == TypeID.AWS_Account
        assert cloud_account.type == TypeID.AWS_Account.name.replace("_", " ")
        assert cloud_account.uid == finding_output.account_uid
        assert cloud_account.labels == ["test-tag:test-value"]

        cloud_organization = cloud.org
        assert isinstance(cloud_organization, Organization)
        assert cloud_organization.uid == finding_output.account_organization_uid
        assert cloud_organization.name == finding_output.account_organization_name

    def test_finding_output_kubernetes(self):
        finding_output = generate_finding_output(
            status="PASS",
            severity="low",
            muted=True,
            region=AWS_REGION_EU_WEST_1,
            provider="kubernetes",
        )

        finding_ocsf = OCSF([finding_output])
        finding_ocsf = finding_ocsf.data[0]

        assert finding_ocsf.metadata.profiles == ["container", "datetime"]
        assert finding_ocsf.resources[0].namespace == finding_output.region.replace(
            "namespace: ", ""
        )

    def test_finding_output_cloud_fail_low_not_muted(self):
        finding_output = generate_finding_output(
            status="FAIL", severity="low", muted=False, region=AWS_REGION_EU_WEST_1
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
            status="PASS", severity="low", muted=False, region=AWS_REGION_EU_WEST_1
        )

        finding_ocsf = OCSF([finding_output])
        finding_ocsf = finding_ocsf.data[0]

        # Status
        assert finding_ocsf.status_id == StatusID.New.value
        assert finding_ocsf.status == StatusID.New.name
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

    # Returns StatusID.New when muted is False
    def test_new_when_not_muted(self):
        muted = False
        assert OCSF.get_finding_status_id(muted) == StatusID.New

    # Returns StatusID.Suppressed when muted is True
    def test_suppressed_when_muted(self):
        muted = True
        assert OCSF.get_finding_status_id(muted) == StatusID.Suppressed
