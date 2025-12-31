"""
Tests for scan import with real Prowler JSON output format.

This module tests the scan import functionality using realistic Prowler CLI
OCSF JSON output format, matching the structure found in actual Prowler scans.

These tests validate:
- Import of real Prowler OCSF JSON format
- Correct parsing of all OCSF fields
- Provider creation from scan data
- Finding and resource creation
- Compliance mapping preservation
"""

import io
import json
from pathlib import Path
from uuid import uuid4

import pytest
from django.urls import reverse
from rest_framework import status

from api.models import Finding, Provider, Resource, Scan, StateChoices
from api.parsers.ocsf_parser import parse_ocsf_json, validate_ocsf_structure


# Path to the test data file
TEST_DATA_DIR = Path(__file__).parent.parent.parent.parent.parent / "tests" / "manual"


def create_real_prowler_ocsf_data(
    account_uid: str = "123456789012",
    account_name: str = "Test AWS Account",
) -> list[dict]:
    """
    Create realistic Prowler OCSF JSON data matching actual CLI output format.
    
    This generates test data that matches the exact structure of real Prowler CLI
    output, including all required and optional OCSF fields.
    
    Args:
        account_uid: AWS account ID to use in the test data.
        account_name: AWS account name to use in the test data.
    
    Returns:
        List of OCSF finding dictionaries.
    """
    # Generate unique finding UIDs for this test run
    finding_uid_1 = f"prowler-aws-accessanalyzer_enabled-{account_uid}-us-east-1-{uuid4().hex[:8]}"
    finding_uid_2 = f"prowler-aws-s3_bucket_public_access-{account_uid}-us-west-2-{uuid4().hex[:8]}"
    finding_uid_3 = f"prowler-aws-ec2_imdsv2-{account_uid}-us-east-1-{uuid4().hex[:8]}"
    
    resource_uid_1 = f"arn:aws:iam::{account_uid}:root"
    resource_uid_2 = f"arn:aws:s3:::test-bucket-{uuid4().hex[:8]}"
    resource_uid_3 = f"arn:aws:ec2:us-east-1:{account_uid}:instance/i-{uuid4().hex[:12]}"
    
    return [
        {
            "message": f"IAM Access Analyzer in account {account_uid} is not enabled.",
            "metadata": {
                "event_code": "accessanalyzer_enabled",
                "product": {
                    "name": "Prowler",
                    "uid": "prowler",
                    "vendor_name": "Prowler",
                    "version": "5.0.0"
                },
                "profiles": ["cloud", "datetime"],
                "tenant_uid": "",
                "version": "1.4.0"
            },
            "severity_id": 2,
            "severity": "Low",
            "status": "New",
            "status_code": "FAIL",
            "status_detail": f"IAM Access Analyzer in account {account_uid} is not enabled.",
            "status_id": 1,
            "unmapped": {
                "related_url": "https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html",
                "categories": [],
                "depends_on": [],
                "related_to": [],
                "additional_urls": [],
                "notes": "",
                "compliance": {
                    "CIS-1.4": ["1.20"],
                    "CIS-1.5": ["1.20"],
                    "CIS-2.0": ["1.20"],
                    "CIS-3.0": ["1.20"],
                    "AWS-Account-Security-Onboarding": [
                        "Enabled security services",
                        "Create analyzers in each active regions"
                    ]
                }
            },
            "activity_name": "Create",
            "activity_id": 1,
            "finding_info": {
                "created_time": 1735570800,
                "created_time_dt": "2024-12-30T15:00:00.000000",
                "desc": "Check if IAM Access Analyzer is enabled",
                "product_uid": "prowler",
                "title": "Check if IAM Access Analyzer is enabled",
                "types": ["IAM"],
                "uid": finding_uid_1
            },
            "resources": [
                {
                    "cloud_partition": "aws",
                    "region": "us-east-1",
                    "data": {
                        "details": "",
                        "metadata": {
                            "arn": resource_uid_1,
                            "name": account_uid,
                            "status": "NOT_AVAILABLE",
                            "findings": [],
                            "tags": [],
                            "type": "",
                            "region": "us-east-1"
                        }
                    },
                    "group": {"name": "accessanalyzer"},
                    "labels": [],
                    "name": account_uid,
                    "type": "Other",
                    "uid": resource_uid_1
                }
            ],
            "category_name": "Findings",
            "category_uid": 2,
            "class_name": "Detection Finding",
            "class_uid": 2004,
            "cloud": {
                "account": {
                    "name": account_name,
                    "type": "AWS Account",
                    "type_id": 10,
                    "uid": account_uid,
                    "labels": []
                },
                "org": {"name": "", "uid": ""},
                "provider": "aws",
                "region": "us-east-1"
            },
            "remediation": {
                "desc": "Enable IAM Access Analyzer for all accounts.",
                "references": [
                    "aws accessanalyzer create-analyzer --analyzer-name <NAME> --type <ACCOUNT|ORGANIZATION>",
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html"
                ]
            },
            "risk_details": "AWS IAM Access Analyzer helps identify resources shared with external entities.",
            "time": 1735570800,
            "time_dt": "2024-12-30T15:00:00.000000",
            "type_uid": 200401,
            "type_name": "Detection Finding: Create"
        },
        {
            "message": "S3 bucket test-bucket has public access block enabled.",
            "metadata": {
                "event_code": "s3_bucket_public_access_block_enabled",
                "product": {
                    "name": "Prowler",
                    "uid": "prowler",
                    "vendor_name": "Prowler",
                    "version": "5.0.0"
                },
                "profiles": ["cloud", "datetime"],
                "tenant_uid": "",
                "version": "1.4.0"
            },
            "severity_id": 1,
            "severity": "Informational",
            "status": "New",
            "status_code": "PASS",
            "status_detail": "S3 bucket test-bucket has public access block enabled.",
            "status_id": 1,
            "unmapped": {
                "related_url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
                "categories": ["storage", "security"],
                "depends_on": [],
                "related_to": [],
                "additional_urls": [],
                "notes": "",
                "compliance": {
                    "CIS-1.4": ["2.1.5"],
                    "CIS-2.0": ["2.1.4"],
                    "PCI-DSS-3.2.1": ["1.2.1", "1.3.1"],
                    "SOC2": ["CC6.1"]
                }
            },
            "activity_name": "Create",
            "activity_id": 1,
            "finding_info": {
                "created_time": 1735570800,
                "created_time_dt": "2024-12-30T15:00:00.000000",
                "desc": "Check if S3 buckets have public access block enabled",
                "product_uid": "prowler",
                "title": "S3 Bucket Public Access Block Check",
                "types": ["S3"],
                "uid": finding_uid_2
            },
            "resources": [
                {
                    "cloud_partition": "aws",
                    "region": "us-west-2",
                    "data": {
                        "details": "",
                        "metadata": {
                            "arn": resource_uid_2,
                            "name": "test-bucket",
                            "status": "ENABLED",
                            "findings": [],
                            "tags": [{"Key": "Environment", "Value": "Test"}],
                            "type": "bucket",
                            "region": "us-west-2"
                        }
                    },
                    "group": {"name": "s3"},
                    "labels": [],
                    "name": "test-bucket",
                    "type": "bucket",
                    "uid": resource_uid_2
                }
            ],
            "category_name": "Findings",
            "category_uid": 2,
            "class_name": "Detection Finding",
            "class_uid": 2004,
            "cloud": {
                "account": {
                    "name": account_name,
                    "type": "AWS Account",
                    "type_id": 10,
                    "uid": account_uid,
                    "labels": []
                },
                "org": {"name": "", "uid": ""},
                "provider": "aws",
                "region": "us-west-2"
            },
            "remediation": {
                "desc": "S3 Block Public Access is already enabled. No action required.",
                "references": []
            },
            "risk_details": "Public S3 buckets can expose sensitive data to unauthorized users.",
            "time": 1735570800,
            "time_dt": "2024-12-30T15:00:00.000000",
            "type_uid": 200401,
            "type_name": "Detection Finding: Create"
        },
        {
            "message": "EC2 instance has IMDSv2 enabled.",
            "metadata": {
                "event_code": "ec2_instance_imdsv2_enabled",
                "product": {
                    "name": "Prowler",
                    "uid": "prowler",
                    "vendor_name": "Prowler",
                    "version": "5.0.0"
                },
                "profiles": ["cloud", "datetime"],
                "tenant_uid": "",
                "version": "1.4.0"
            },
            "severity_id": 1,
            "severity": "Informational",
            "status": "New",
            "status_code": "PASS",
            "status_detail": "EC2 instance has IMDSv2 enabled.",
            "status_id": 1,
            "unmapped": {
                "related_url": "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
                "categories": ["compute", "security"],
                "depends_on": [],
                "related_to": [],
                "additional_urls": [],
                "notes": "",
                "compliance": {
                    "CIS-1.4": ["5.6"],
                    "CIS-2.0": ["5.6"],
                    "AWS-Foundational-Security-Best-Practices": ["EC2.8"]
                }
            },
            "activity_name": "Create",
            "activity_id": 1,
            "finding_info": {
                "created_time": 1735570800,
                "created_time_dt": "2024-12-30T15:00:00.000000",
                "desc": "Check if EC2 instances have IMDSv2 enabled",
                "product_uid": "prowler",
                "title": "EC2 Instance IMDSv2 Check",
                "types": ["EC2"],
                "uid": finding_uid_3
            },
            "resources": [
                {
                    "cloud_partition": "aws",
                    "region": "us-east-1",
                    "data": {
                        "details": "",
                        "metadata": {
                            "arn": resource_uid_3,
                            "name": "test-instance",
                            "status": "running",
                            "findings": [],
                            "tags": [{"Key": "Name", "Value": "test-instance"}],
                            "type": "instance",
                            "region": "us-east-1"
                        }
                    },
                    "group": {"name": "ec2"},
                    "labels": [],
                    "name": "test-instance",
                    "type": "instance",
                    "uid": resource_uid_3
                }
            ],
            "category_name": "Findings",
            "category_uid": 2,
            "class_name": "Detection Finding",
            "class_uid": 2004,
            "cloud": {
                "account": {
                    "name": account_name,
                    "type": "AWS Account",
                    "type_id": 10,
                    "uid": account_uid,
                    "labels": []
                },
                "org": {"name": "", "uid": ""},
                "provider": "aws",
                "region": "us-east-1"
            },
            "remediation": {
                "desc": "IMDSv2 is already enabled. No action required.",
                "references": []
            },
            "risk_details": "IMDSv2 provides enhanced security for instance metadata access.",
            "time": 1735570800,
            "time_dt": "2024-12-30T15:00:00.000000",
            "type_uid": 200401,
            "type_name": "Detection Finding: Create"
        }
    ]


class TestOCSFParserWithRealData:
    """Tests for OCSF parser with real Prowler output format."""

    def test_parse_real_prowler_ocsf_format(self):
        """Test parsing real Prowler OCSF JSON format."""
        ocsf_data = create_real_prowler_ocsf_data()
        content = json.dumps(ocsf_data).encode("utf-8")
        
        # Validate structure
        is_valid, error = validate_ocsf_structure(content)
        assert is_valid, f"OCSF structure validation failed: {error}"
        
        # Parse content
        findings = parse_ocsf_json(content)
        
        # Verify parsing results
        assert len(findings) == 3
        
        # Verify first finding (FAIL - IAM Access Analyzer)
        finding_1 = findings[0]
        assert finding_1.check_id == "accessanalyzer_enabled"
        assert finding_1.severity == "low"
        assert finding_1.status == "FAIL"
        assert finding_1.provider_type == "aws"
        assert finding_1.account_uid == "123456789012"
        assert len(finding_1.resources) == 1
        assert "CIS-1.4" in finding_1.compliance
        assert finding_1.compliance["CIS-1.4"] == ["1.20"]
        
        # Verify second finding (PASS - S3)
        finding_2 = findings[1]
        assert finding_2.check_id == "s3_bucket_public_access_block_enabled"
        assert finding_2.severity == "informational"
        assert finding_2.status == "PASS"
        assert finding_2.resources[0].service == "s3"
        assert "PCI-DSS-3.2.1" in finding_2.compliance
        
        # Verify third finding (PASS - EC2)
        finding_3 = findings[2]
        assert finding_3.check_id == "ec2_instance_imdsv2_enabled"
        assert finding_3.status == "PASS"
        assert finding_3.resources[0].service == "ec2"

    def test_parse_ocsf_with_all_compliance_frameworks(self):
        """Test parsing OCSF data with multiple compliance frameworks."""
        ocsf_data = create_real_prowler_ocsf_data()
        content = json.dumps(ocsf_data).encode("utf-8")
        
        findings = parse_ocsf_json(content)
        
        # Check that compliance data is preserved
        finding_1 = findings[0]
        assert "CIS-1.4" in finding_1.compliance
        assert "CIS-1.5" in finding_1.compliance
        assert "CIS-2.0" in finding_1.compliance
        assert "CIS-3.0" in finding_1.compliance
        assert "AWS-Account-Security-Onboarding" in finding_1.compliance

    def test_parse_ocsf_resource_details(self):
        """Test that resource details are correctly parsed."""
        ocsf_data = create_real_prowler_ocsf_data()
        content = json.dumps(ocsf_data).encode("utf-8")
        
        findings = parse_ocsf_json(content)
        
        # Check S3 resource
        s3_finding = findings[1]
        s3_resource = s3_finding.resources[0]
        assert s3_resource.service == "s3"
        assert s3_resource.type == "bucket"
        assert s3_resource.region == "us-west-2"
        assert "arn:aws:s3:::" in s3_resource.uid


@pytest.mark.django_db
class TestScanImportWithRealProwlerJSON:
    """Tests for scan import API with real Prowler JSON output format."""

    def test_import_real_prowler_json_creates_scan_and_findings(
        self, authenticated_client, tenants_fixture
    ):
        """Test importing real Prowler OCSF JSON creates scan, findings, and resources."""
        url = reverse("scan-import")
        tenant = tenants_fixture[0]
        
        # Use unique account UID to avoid conflicts with other tests
        account_uid = f"real-json-{uuid4().hex[:8]}"
        ocsf_data = create_real_prowler_ocsf_data(
            account_uid=account_uid,
            account_name="Real JSON Test Account"
        )
        
        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )
        
        # Verify successful response
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        
        # Verify response structure
        assert "data" in response_data
        assert response_data["data"]["type"] == "scan-imports"
        assert "attributes" in response_data["data"]
        
        attributes = response_data["data"]["attributes"]
        assert "scan_id" in attributes
        assert "provider_id" in attributes
        assert attributes["findings_count"] == 3
        assert attributes["resources_count"] == 3
        assert attributes["status"] == "completed"
        
        # Verify scan was created
        scan_id = attributes["scan_id"]
        scan = Scan.objects.get(id=scan_id)
        assert str(scan.tenant_id) == str(tenant.id)
        assert scan.trigger == Scan.TriggerChoices.IMPORTED
        assert scan.state == StateChoices.COMPLETED
        
        # Verify provider was created
        provider_id = attributes["provider_id"]
        provider = Provider.objects.get(id=provider_id)
        assert provider.provider == "aws"
        assert provider.uid == account_uid

    def test_import_real_prowler_json_via_file_upload(
        self, authenticated_client, tenants_fixture
    ):
        """Test importing real Prowler OCSF JSON via file upload."""
        url = reverse("scan-import")
        
        account_uid = f"file-upload-{uuid4().hex[:8]}"
        ocsf_data = create_real_prowler_ocsf_data(account_uid=account_uid)
        
        file_content = json.dumps(ocsf_data).encode("utf-8")
        file_obj = io.BytesIO(file_content)
        file_obj.name = "prowler-output.ocsf.json"
        
        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        assert response_data["data"]["attributes"]["findings_count"] == 3

    def test_import_preserves_compliance_mappings(
        self, authenticated_client, tenants_fixture
    ):
        """Test that compliance mappings are preserved during import."""
        url = reverse("scan-import")
        
        account_uid = f"compliance-{uuid4().hex[:8]}"
        ocsf_data = create_real_prowler_ocsf_data(account_uid=account_uid)
        
        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        
        # Get the finding UIDs from the test data
        finding_uid_prefix = f"prowler-aws-accessanalyzer_enabled-{account_uid}"
        
        # Find the imported finding
        findings = Finding.objects.filter(uid__startswith=finding_uid_prefix)
        assert findings.exists()
        
        finding = findings.first()
        assert "CIS-1.4" in finding.compliance
        assert finding.compliance["CIS-1.4"] == ["1.20"]

    def test_import_creates_resources_with_correct_attributes(
        self, authenticated_client, tenants_fixture
    ):
        """Test that resources are created with correct attributes."""
        url = reverse("scan-import")
        
        account_uid = f"resources-{uuid4().hex[:8]}"
        ocsf_data = create_real_prowler_ocsf_data(account_uid=account_uid)
        
        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        
        provider_id = response_data["data"]["attributes"]["provider_id"]
        
        # Check that resources were created
        resources = Resource.objects.filter(provider_id=provider_id)
        assert resources.count() == 3
        
        # Check S3 resource
        s3_resources = resources.filter(service="s3")
        assert s3_resources.exists()
        s3_resource = s3_resources.first()
        assert s3_resource.type == "bucket"
        assert s3_resource.region == "us-west-2"
        
        # Check EC2 resource
        ec2_resources = resources.filter(service="ec2")
        assert ec2_resources.exists()
        ec2_resource = ec2_resources.first()
        assert ec2_resource.type == "instance"
        assert ec2_resource.region == "us-east-1"

    def test_import_with_mixed_pass_fail_findings(
        self, authenticated_client, tenants_fixture
    ):
        """Test importing data with both PASS and FAIL findings."""
        url = reverse("scan-import")
        
        account_uid = f"mixed-{uuid4().hex[:8]}"
        ocsf_data = create_real_prowler_ocsf_data(account_uid=account_uid)
        
        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        
        scan_id = response_data["data"]["attributes"]["scan_id"]
        
        # Check findings by status
        findings = Finding.objects.filter(scan_id=scan_id)
        fail_findings = findings.filter(status="FAIL")
        pass_findings = findings.filter(status="PASS")
        
        assert fail_findings.count() == 1  # accessanalyzer_enabled
        assert pass_findings.count() == 2  # s3 and ec2 checks

    def test_import_with_multiple_severity_levels(
        self, authenticated_client, tenants_fixture
    ):
        """Test importing data with different severity levels."""
        url = reverse("scan-import")
        
        account_uid = f"severity-{uuid4().hex[:8]}"
        ocsf_data = create_real_prowler_ocsf_data(account_uid=account_uid)
        
        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        
        scan_id = response_data["data"]["attributes"]["scan_id"]
        
        # Check findings by severity
        findings = Finding.objects.filter(scan_id=scan_id)
        low_findings = findings.filter(severity="low")
        informational_findings = findings.filter(severity="informational")
        
        assert low_findings.count() == 1  # accessanalyzer_enabled
        assert informational_findings.count() == 2  # s3 and ec2 checks
