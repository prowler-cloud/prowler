"""
Tests for scan import with real Prowler CSV output format.

This module tests the scan import functionality using realistic Prowler CLI
CSV output format, matching the structure found in actual Prowler scans.

These tests validate:
- Import of real Prowler CSV format (semicolon-delimited)
- Correct parsing of all CSV fields
- Provider creation from scan data
- Finding and resource creation
- Compliance mapping preservation
"""

import io
from datetime import datetime
from pathlib import Path
from uuid import uuid4

import pytest
from django.urls import reverse
from rest_framework import status

from api.models import Finding, Provider, Resource, Scan, StateChoices
from api.parsers.csv_parser import parse_csv, validate_csv_structure


# Path to the example output files
EXAMPLES_DIR = Path(__file__).parent.parent.parent.parent.parent.parent / "examples" / "output"


def create_real_prowler_csv_data(
    account_uid: str = "123456789012",
    account_name: str = "Test AWS Account",
) -> str:
    """
    Create realistic Prowler CSV data matching actual CLI output format.
    
    This generates test data that matches the exact structure of real Prowler CLI
    output, including all 42 columns in the correct order.
    
    Args:
        account_uid: AWS account ID to use in the test data.
        account_name: AWS account name to use in the test data.
    
    Returns:
        CSV content as string (semicolon-delimited).
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    
    # Generate unique finding UIDs for this test run
    finding_uid_1 = f"prowler-aws-accessanalyzer_enabled-{account_uid}-us-east-1-{uuid4().hex[:8]}"
    finding_uid_2 = f"prowler-aws-s3_bucket_public_access-{account_uid}-us-west-2-{uuid4().hex[:8]}"
    finding_uid_3 = f"prowler-aws-ec2_imdsv2-{account_uid}-us-east-1-{uuid4().hex[:8]}"
    
    resource_uid_1 = f"arn:aws:iam::{account_uid}:root"
    resource_uid_2 = f"arn:aws:s3:::test-bucket-{uuid4().hex[:8]}"
    resource_uid_3 = f"arn:aws:ec2:us-east-1:{account_uid}:instance/i-{uuid4().hex[:12]}"
    
    # CSV header (42 columns)
    header = "AUTH_METHOD;TIMESTAMP;ACCOUNT_UID;ACCOUNT_NAME;ACCOUNT_EMAIL;ACCOUNT_ORGANIZATION_UID;ACCOUNT_ORGANIZATION_NAME;ACCOUNT_TAGS;FINDING_UID;PROVIDER;CHECK_ID;CHECK_TITLE;CHECK_TYPE;STATUS;STATUS_EXTENDED;MUTED;SERVICE_NAME;SUBSERVICE_NAME;SEVERITY;RESOURCE_TYPE;RESOURCE_UID;RESOURCE_NAME;RESOURCE_DETAILS;RESOURCE_TAGS;PARTITION;REGION;DESCRIPTION;RISK;RELATED_URL;REMEDIATION_RECOMMENDATION_TEXT;REMEDIATION_RECOMMENDATION_URL;REMEDIATION_CODE_NATIVEIAC;REMEDIATION_CODE_TERRAFORM;REMEDIATION_CODE_CLI;REMEDIATION_CODE_OTHER;COMPLIANCE;CATEGORIES;DEPENDS_ON;RELATED_TO;NOTES;PROWLER_VERSION;ADDITIONAL_URLS"
    
    # Row 1: IAM Access Analyzer (FAIL)
    row1_fields = [
        "profile", timestamp, account_uid, account_name, "", "", "", "",
        finding_uid_1, "aws", "accessanalyzer_enabled",
        "Check if IAM Access Analyzer is enabled", "IAM", "FAIL",
        f"IAM Access Analyzer in account {account_uid} is not enabled.", "False",
        "accessanalyzer", "", "low", "Other", resource_uid_1, account_uid, "", "",
        "aws", "us-east-1", "Check if IAM Access Analyzer is enabled",
        "AWS IAM Access Analyzer helps identify resources shared with external entities.",
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html",
        "Enable IAM Access Analyzer for all accounts.",
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html",
        "", "", "aws accessanalyzer create-analyzer --analyzer-name <NAME> --type <ACCOUNT|ORGANIZATION>", "",
        "CIS-1.4: 1.20 | CIS-1.5: 1.20 | CIS-2.0: 1.20 | CIS-3.0: 1.20 | AWS-Account-Security-Onboarding: Enabled security services, Create analyzers in each active regions",
        "", "", "", "", "5.0.0",
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html",
    ]
    row1 = ";".join(row1_fields)
    
    # Row 2: S3 Bucket Public Access (PASS)
    row2_fields = [
        "profile", timestamp, account_uid, account_name, "", "", "", "",
        finding_uid_2, "aws", "s3_bucket_public_access_block_enabled",
        "S3 Bucket Public Access Block Check", "S3", "PASS",
        "S3 bucket test-bucket has public access block enabled.", "False",
        "s3", "", "informational", "bucket", resource_uid_2, "test-bucket", "", "",
        "aws", "us-west-2", "Check if S3 buckets have public access block enabled",
        "Public S3 buckets can expose sensitive data.",
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        "S3 Block Public Access is already enabled.",
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",
        "", "", "", "",
        "CIS-1.4: 2.1.5 | CIS-2.0: 2.1.4 | PCI-DSS-3.2.1: 1.2.1, 1.3.1 | SOC2: CC6.1",
        "", "", "", "", "5.0.0", "",
    ]
    row2 = ";".join(row2_fields)
    
    # Row 3: EC2 IMDSv2 (PASS)
    row3_fields = [
        "profile", timestamp, account_uid, account_name, "", "", "", "",
        finding_uid_3, "aws", "ec2_instance_imdsv2_enabled",
        "EC2 Instance IMDSv2 Check", "EC2", "PASS",
        "EC2 instance has IMDSv2 enabled.", "False",
        "ec2", "", "informational", "instance", resource_uid_3, "test-instance", "", "",
        "aws", "us-east-1", "Check if EC2 instances have IMDSv2 enabled",
        "IMDSv2 provides enhanced security for instance metadata access.",
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
        "IMDSv2 is already enabled.",
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",
        "", "", "", "",
        "CIS-1.4: 5.6 | CIS-2.0: 5.6 | AWS-Foundational-Security-Best-Practices: EC2.8",
        "", "", "", "", "5.0.0", "",
    ]
    row3 = ";".join(row3_fields)
    
    return "\n".join([header, row1, row2, row3])


class TestCSVParserWithRealData:
    """Tests for CSV parser with real Prowler output format."""

    def test_parse_real_prowler_csv_format(self):
        """Test parsing real Prowler CSV format."""
        csv_data = create_real_prowler_csv_data()
        content = csv_data.encode("utf-8")
        
        # Validate structure
        is_valid, error = validate_csv_structure(content)
        assert is_valid, f"CSV structure validation failed: {error}"
        
        # Parse content
        findings = parse_csv(content)
        
        # Verify parsing results
        assert len(findings) == 3
        
        # Verify first finding (FAIL - IAM Access Analyzer)
        finding_1 = findings[0]
        assert finding_1.check_id == "accessanalyzer_enabled"
        assert finding_1.severity == "low"
        assert finding_1.status == "FAIL"
        assert finding_1.provider_type == "aws"
        assert finding_1.account_uid == "123456789012"
        assert finding_1.resource.service == "accessanalyzer"
        assert "CIS-1.4" in finding_1.compliance
        assert finding_1.compliance["CIS-1.4"] == ["1.20"]
        
        # Verify second finding (PASS - S3)
        finding_2 = findings[1]
        assert finding_2.check_id == "s3_bucket_public_access_block_enabled"
        assert finding_2.severity == "informational"
        assert finding_2.status == "PASS"
        assert finding_2.resource.service == "s3"
        assert finding_2.resource.type == "bucket"
        assert "PCI-DSS-3.2.1" in finding_2.compliance
        
        # Verify third finding (PASS - EC2)
        finding_3 = findings[2]
        assert finding_3.check_id == "ec2_instance_imdsv2_enabled"
        assert finding_3.status == "PASS"
        assert finding_3.resource.service == "ec2"
        assert finding_3.resource.type == "instance"

    def test_parse_csv_with_all_compliance_frameworks(self):
        """Test parsing CSV data with multiple compliance frameworks."""
        csv_data = create_real_prowler_csv_data()
        content = csv_data.encode("utf-8")
        
        findings = parse_csv(content)
        
        # Check that compliance data is preserved
        finding_1 = findings[0]
        assert "CIS-1.4" in finding_1.compliance
        assert "CIS-1.5" in finding_1.compliance
        assert "CIS-2.0" in finding_1.compliance
        assert "CIS-3.0" in finding_1.compliance
        assert "AWS-Account-Security-Onboarding" in finding_1.compliance

    def test_parse_csv_resource_details(self):
        """Test that resource details are correctly parsed."""
        csv_data = create_real_prowler_csv_data()
        content = csv_data.encode("utf-8")
        
        findings = parse_csv(content)
        
        # Check S3 resource
        s3_finding = findings[1]
        s3_resource = s3_finding.resource
        assert s3_resource.service == "s3"
        assert s3_resource.type == "bucket"
        assert s3_resource.region == "us-west-2"
        assert "arn:aws:s3:::" in s3_resource.uid

    def test_parse_example_aws_csv_file(self):
        """Test parsing the actual example AWS CSV file."""
        example_file = EXAMPLES_DIR / "example_output_aws.csv"
        
        if not example_file.exists():
            pytest.skip(f"Example file not found: {example_file}")
        
        with open(example_file, "rb") as f:
            content = f.read()
        
        is_valid, error = validate_csv_structure(content)
        assert is_valid, f"Example file validation failed: {error}"
        
        findings = parse_csv(content)
        assert len(findings) > 0
        
        # Verify provider type
        assert all(f.provider_type == "aws" for f in findings)

    def test_parse_example_azure_csv_file(self):
        """Test parsing the actual example Azure CSV file."""
        example_file = EXAMPLES_DIR / "example_output_azure.csv"
        
        if not example_file.exists():
            pytest.skip(f"Example file not found: {example_file}")
        
        with open(example_file, "rb") as f:
            content = f.read()
        
        is_valid, error = validate_csv_structure(content)
        assert is_valid, f"Example file validation failed: {error}"
        
        findings = parse_csv(content)
        assert len(findings) > 0
        
        # Verify provider type
        assert all(f.provider_type == "azure" for f in findings)

    def test_parse_example_gcp_csv_file(self):
        """Test parsing the actual example GCP CSV file."""
        example_file = EXAMPLES_DIR / "example_output_gcp.csv"
        
        if not example_file.exists():
            pytest.skip(f"Example file not found: {example_file}")
        
        with open(example_file, "rb") as f:
            content = f.read()
        
        is_valid, error = validate_csv_structure(content)
        assert is_valid, f"Example file validation failed: {error}"
        
        findings = parse_csv(content)
        assert len(findings) > 0
        
        # Verify provider type
        assert all(f.provider_type == "gcp" for f in findings)


@pytest.mark.django_db
class TestScanImportWithRealProwlerCSV:
    """Tests for scan import API with real Prowler CSV output format."""

    def test_import_real_prowler_csv_creates_scan_and_findings(
        self, authenticated_client, tenants_fixture
    ):
        """Test importing real Prowler CSV creates scan, findings, and resources."""
        url = reverse("scan-import")
        tenant = tenants_fixture[0]
        
        # Use unique account UID to avoid conflicts with other tests
        account_uid = f"real-csv-{uuid4().hex[:8]}"
        csv_data = create_real_prowler_csv_data(
            account_uid=account_uid,
            account_name="Real CSV Test Account"
        )
        
        file_content = csv_data.encode("utf-8")
        file_obj = io.BytesIO(file_content)
        file_obj.name = "prowler-output.csv"
        
        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
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

    def test_import_csv_preserves_compliance_mappings(
        self, authenticated_client, tenants_fixture
    ):
        """Test that compliance mappings are preserved during CSV import."""
        url = reverse("scan-import")
        
        account_uid = f"compliance-csv-{uuid4().hex[:8]}"
        csv_data = create_real_prowler_csv_data(account_uid=account_uid)
        
        file_content = csv_data.encode("utf-8")
        file_obj = io.BytesIO(file_content)
        file_obj.name = "prowler-output.csv"
        
        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
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

    def test_import_csv_creates_resources_with_correct_attributes(
        self, authenticated_client, tenants_fixture
    ):
        """Test that resources are created with correct attributes from CSV."""
        url = reverse("scan-import")
        
        account_uid = f"resources-csv-{uuid4().hex[:8]}"
        csv_data = create_real_prowler_csv_data(account_uid=account_uid)
        
        file_content = csv_data.encode("utf-8")
        file_obj = io.BytesIO(file_content)
        file_obj.name = "prowler-output.csv"
        
        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
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

    def test_import_csv_with_mixed_pass_fail_findings(
        self, authenticated_client, tenants_fixture
    ):
        """Test importing CSV data with both PASS and FAIL findings."""
        url = reverse("scan-import")
        
        account_uid = f"mixed-csv-{uuid4().hex[:8]}"
        csv_data = create_real_prowler_csv_data(account_uid=account_uid)
        
        file_content = csv_data.encode("utf-8")
        file_obj = io.BytesIO(file_content)
        file_obj.name = "prowler-output.csv"
        
        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
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

    def test_import_csv_with_multiple_severity_levels(
        self, authenticated_client, tenants_fixture
    ):
        """Test importing CSV data with different severity levels."""
        url = reverse("scan-import")
        
        account_uid = f"severity-csv-{uuid4().hex[:8]}"
        csv_data = create_real_prowler_csv_data(account_uid=account_uid)
        
        file_content = csv_data.encode("utf-8")
        file_obj = io.BytesIO(file_content)
        file_obj.name = "prowler-output.csv"
        
        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
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

    def test_import_example_aws_csv_file(
        self, authenticated_client, tenants_fixture
    ):
        """Test importing the actual example AWS CSV file."""
        example_file = EXAMPLES_DIR / "example_output_aws.csv"
        
        if not example_file.exists():
            pytest.skip(f"Example file not found: {example_file}")
        
        url = reverse("scan-import")
        
        with open(example_file, "rb") as f:
            file_content = f.read()
        
        file_obj = io.BytesIO(file_content)
        file_obj.name = "example_output_aws.csv"
        
        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )
        
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        
        attributes = response_data["data"]["attributes"]
        assert attributes["findings_count"] > 0
        assert attributes["status"] == "completed"
        
        # Verify provider type
        provider_id = attributes["provider_id"]
        provider = Provider.objects.get(id=provider_id)
        assert provider.provider == "aws"
