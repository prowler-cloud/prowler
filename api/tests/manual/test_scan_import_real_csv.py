#!/usr/bin/env python3
"""
Manual test script for testing scan import with real Prowler CSV output.

This script tests the scan import functionality using real Prowler CSV output.
It validates that the CSV parser correctly handles real Prowler CLI output format.

Usage:
    # Run directly from the repository root:
    python api/tests/manual/test_scan_import_real_csv.py

    # Or with poetry:
    poetry run python api/tests/manual/test_scan_import_real_csv.py

Prerequisites:
    - Python 3.10+
    - api/src/backend in PYTHONPATH (handled automatically)

This script tests:
    - CSV structure validation
    - Parsing of real Prowler CSV format (semicolon-delimited)
    - Extraction of findings, resources, and compliance data
    - Provider information extraction
    - Comparison with example output files
"""

import os
import sys
from datetime import datetime
from pathlib import Path
from uuid import uuid4

# Add the API backend to the path for imports
PROJECT_ROOT = Path(__file__).parent.parent.parent
API_BACKEND = PROJECT_ROOT / "src" / "backend"
sys.path.insert(0, str(API_BACKEND))

# Path to example output files
EXAMPLES_DIR = PROJECT_ROOT.parent / "examples" / "output"


def create_real_csv_test_data(
    account_uid: str = "123456789012",
    account_name: str = "Test AWS Account",
) -> str:
    """
    Create realistic CSV test data based on actual Prowler output format.
    
    This generates test data that matches the structure of real Prowler CLI output
    as seen in examples/output/example_output_aws.csv.
    
    The CSV has 42 columns (semicolon-delimited):
    AUTH_METHOD, TIMESTAMP, ACCOUNT_UID, ACCOUNT_NAME, ACCOUNT_EMAIL,
    ACCOUNT_ORGANIZATION_UID, ACCOUNT_ORGANIZATION_NAME, ACCOUNT_TAGS,
    FINDING_UID, PROVIDER, CHECK_ID, CHECK_TITLE, CHECK_TYPE, STATUS,
    STATUS_EXTENDED, MUTED, SERVICE_NAME, SUBSERVICE_NAME, SEVERITY,
    RESOURCE_TYPE, RESOURCE_UID, RESOURCE_NAME, RESOURCE_DETAILS, RESOURCE_TAGS,
    PARTITION, REGION, DESCRIPTION, RISK, RELATED_URL, REMEDIATION_RECOMMENDATION_TEXT,
    REMEDIATION_RECOMMENDATION_URL, REMEDIATION_CODE_NATIVEIAC, REMEDIATION_CODE_TERRAFORM,
    REMEDIATION_CODE_CLI, REMEDIATION_CODE_OTHER, COMPLIANCE, CATEGORIES, DEPENDS_ON,
    RELATED_TO, NOTES, PROWLER_VERSION, ADDITIONAL_URLS
    
    Args:
        account_uid: AWS account ID to use in the test data.
        account_name: AWS account name to use in the test data.
    
    Returns:
        CSV content as string (semicolon-delimited).
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    
    # Generate unique IDs for this test run
    finding_uid_1 = f"prowler-aws-accessanalyzer_enabled-{account_uid}-us-east-1-{uuid4().hex[:8]}"
    finding_uid_2 = f"prowler-aws-s3_bucket_public_access-{account_uid}-us-west-2-{uuid4().hex[:8]}"
    finding_uid_3 = f"prowler-aws-ec2_imdsv2-{account_uid}-us-east-1-{uuid4().hex[:8]}"
    
    resource_uid_1 = f"arn:aws:iam::{account_uid}:root"
    resource_uid_2 = f"arn:aws:s3:::test-bucket-{uuid4().hex[:8]}"
    resource_uid_3 = f"arn:aws:ec2:us-east-1:{account_uid}:instance/i-{uuid4().hex[:12]}"
    
    # CSV header (matching real Prowler output - 42 columns)
    header = "AUTH_METHOD;TIMESTAMP;ACCOUNT_UID;ACCOUNT_NAME;ACCOUNT_EMAIL;ACCOUNT_ORGANIZATION_UID;ACCOUNT_ORGANIZATION_NAME;ACCOUNT_TAGS;FINDING_UID;PROVIDER;CHECK_ID;CHECK_TITLE;CHECK_TYPE;STATUS;STATUS_EXTENDED;MUTED;SERVICE_NAME;SUBSERVICE_NAME;SEVERITY;RESOURCE_TYPE;RESOURCE_UID;RESOURCE_NAME;RESOURCE_DETAILS;RESOURCE_TAGS;PARTITION;REGION;DESCRIPTION;RISK;RELATED_URL;REMEDIATION_RECOMMENDATION_TEXT;REMEDIATION_RECOMMENDATION_URL;REMEDIATION_CODE_NATIVEIAC;REMEDIATION_CODE_TERRAFORM;REMEDIATION_CODE_CLI;REMEDIATION_CODE_OTHER;COMPLIANCE;CATEGORIES;DEPENDS_ON;RELATED_TO;NOTES;PROWLER_VERSION;ADDITIONAL_URLS"
    
    # Row 1: IAM Access Analyzer (FAIL) - 42 fields
    # Fields: AUTH_METHOD(1), TIMESTAMP(2), ACCOUNT_UID(3), ACCOUNT_NAME(4), ACCOUNT_EMAIL(5),
    #         ACCOUNT_ORGANIZATION_UID(6), ACCOUNT_ORGANIZATION_NAME(7), ACCOUNT_TAGS(8),
    #         FINDING_UID(9), PROVIDER(10), CHECK_ID(11), CHECK_TITLE(12), CHECK_TYPE(13),
    #         STATUS(14), STATUS_EXTENDED(15), MUTED(16), SERVICE_NAME(17), SUBSERVICE_NAME(18),
    #         SEVERITY(19), RESOURCE_TYPE(20), RESOURCE_UID(21), RESOURCE_NAME(22),
    #         RESOURCE_DETAILS(23), RESOURCE_TAGS(24), PARTITION(25), REGION(26),
    #         DESCRIPTION(27), RISK(28), RELATED_URL(29), REMEDIATION_RECOMMENDATION_TEXT(30),
    #         REMEDIATION_RECOMMENDATION_URL(31), REMEDIATION_CODE_NATIVEIAC(32),
    #         REMEDIATION_CODE_TERRAFORM(33), REMEDIATION_CODE_CLI(34), REMEDIATION_CODE_OTHER(35),
    #         COMPLIANCE(36), CATEGORIES(37), DEPENDS_ON(38), RELATED_TO(39), NOTES(40),
    #         PROWLER_VERSION(41), ADDITIONAL_URLS(42)
    row1_fields = [
        "profile",  # AUTH_METHOD
        timestamp,  # TIMESTAMP
        account_uid,  # ACCOUNT_UID
        account_name,  # ACCOUNT_NAME
        "",  # ACCOUNT_EMAIL
        "",  # ACCOUNT_ORGANIZATION_UID
        "",  # ACCOUNT_ORGANIZATION_NAME
        "",  # ACCOUNT_TAGS
        finding_uid_1,  # FINDING_UID
        "aws",  # PROVIDER
        "accessanalyzer_enabled",  # CHECK_ID
        "Check if IAM Access Analyzer is enabled",  # CHECK_TITLE
        "IAM",  # CHECK_TYPE
        "FAIL",  # STATUS
        f"IAM Access Analyzer in account {account_uid} is not enabled.",  # STATUS_EXTENDED
        "False",  # MUTED
        "accessanalyzer",  # SERVICE_NAME
        "",  # SUBSERVICE_NAME
        "low",  # SEVERITY
        "Other",  # RESOURCE_TYPE
        resource_uid_1,  # RESOURCE_UID
        account_uid,  # RESOURCE_NAME
        "",  # RESOURCE_DETAILS
        "",  # RESOURCE_TAGS
        "aws",  # PARTITION
        "us-east-1",  # REGION
        "Check if IAM Access Analyzer is enabled",  # DESCRIPTION
        "AWS IAM Access Analyzer helps identify resources shared with external entities.",  # RISK
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html",  # RELATED_URL
        "Enable IAM Access Analyzer for all accounts.",  # REMEDIATION_RECOMMENDATION_TEXT
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html",  # REMEDIATION_RECOMMENDATION_URL
        "",  # REMEDIATION_CODE_NATIVEIAC
        "",  # REMEDIATION_CODE_TERRAFORM
        "aws accessanalyzer create-analyzer --analyzer-name <NAME> --type <ACCOUNT|ORGANIZATION>",  # REMEDIATION_CODE_CLI
        "",  # REMEDIATION_CODE_OTHER
        "CIS-1.4: 1.20 | CIS-1.5: 1.20 | CIS-2.0: 1.20 | CIS-3.0: 1.20 | AWS-Account-Security-Onboarding: Enabled security services, Create analyzers in each active regions",  # COMPLIANCE
        "",  # CATEGORIES
        "",  # DEPENDS_ON
        "",  # RELATED_TO
        "",  # NOTES
        "5.0.0",  # PROWLER_VERSION
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-getting-started.html",  # ADDITIONAL_URLS
    ]
    row1 = ";".join(row1_fields)
    
    # Row 2: S3 Bucket Public Access (PASS) - 42 fields
    row2_fields = [
        "profile",  # AUTH_METHOD
        timestamp,  # TIMESTAMP
        account_uid,  # ACCOUNT_UID
        account_name,  # ACCOUNT_NAME
        "",  # ACCOUNT_EMAIL
        "",  # ACCOUNT_ORGANIZATION_UID
        "",  # ACCOUNT_ORGANIZATION_NAME
        "",  # ACCOUNT_TAGS
        finding_uid_2,  # FINDING_UID
        "aws",  # PROVIDER
        "s3_bucket_public_access_block_enabled",  # CHECK_ID
        "S3 Bucket Public Access Block Check",  # CHECK_TITLE
        "S3",  # CHECK_TYPE
        "PASS",  # STATUS
        "S3 bucket test-bucket has public access block enabled.",  # STATUS_EXTENDED
        "False",  # MUTED
        "s3",  # SERVICE_NAME
        "",  # SUBSERVICE_NAME
        "informational",  # SEVERITY
        "bucket",  # RESOURCE_TYPE
        resource_uid_2,  # RESOURCE_UID
        "test-bucket",  # RESOURCE_NAME
        "",  # RESOURCE_DETAILS
        "",  # RESOURCE_TAGS
        "aws",  # PARTITION
        "us-west-2",  # REGION
        "Check if S3 buckets have public access block enabled",  # DESCRIPTION
        "Public S3 buckets can expose sensitive data.",  # RISK
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",  # RELATED_URL
        "S3 Block Public Access is already enabled.",  # REMEDIATION_RECOMMENDATION_TEXT
        "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html",  # REMEDIATION_RECOMMENDATION_URL
        "",  # REMEDIATION_CODE_NATIVEIAC
        "",  # REMEDIATION_CODE_TERRAFORM
        "",  # REMEDIATION_CODE_CLI
        "",  # REMEDIATION_CODE_OTHER
        "CIS-1.4: 2.1.5 | CIS-2.0: 2.1.4 | PCI-DSS-3.2.1: 1.2.1, 1.3.1 | SOC2: CC6.1",  # COMPLIANCE
        "",  # CATEGORIES
        "",  # DEPENDS_ON
        "",  # RELATED_TO
        "",  # NOTES
        "5.0.0",  # PROWLER_VERSION
        "",  # ADDITIONAL_URLS
    ]
    row2 = ";".join(row2_fields)
    
    # Row 3: EC2 IMDSv2 (PASS) - 42 fields
    row3_fields = [
        "profile",  # AUTH_METHOD
        timestamp,  # TIMESTAMP
        account_uid,  # ACCOUNT_UID
        account_name,  # ACCOUNT_NAME
        "",  # ACCOUNT_EMAIL
        "",  # ACCOUNT_ORGANIZATION_UID
        "",  # ACCOUNT_ORGANIZATION_NAME
        "",  # ACCOUNT_TAGS
        finding_uid_3,  # FINDING_UID
        "aws",  # PROVIDER
        "ec2_instance_imdsv2_enabled",  # CHECK_ID
        "EC2 Instance IMDSv2 Check",  # CHECK_TITLE
        "EC2",  # CHECK_TYPE
        "PASS",  # STATUS
        "EC2 instance has IMDSv2 enabled.",  # STATUS_EXTENDED
        "False",  # MUTED
        "ec2",  # SERVICE_NAME
        "",  # SUBSERVICE_NAME
        "informational",  # SEVERITY
        "instance",  # RESOURCE_TYPE
        resource_uid_3,  # RESOURCE_UID
        "test-instance",  # RESOURCE_NAME
        "",  # RESOURCE_DETAILS
        "",  # RESOURCE_TAGS
        "aws",  # PARTITION
        "us-east-1",  # REGION
        "Check if EC2 instances have IMDSv2 enabled",  # DESCRIPTION
        "IMDSv2 provides enhanced security for instance metadata access.",  # RISK
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",  # RELATED_URL
        "IMDSv2 is already enabled.",  # REMEDIATION_RECOMMENDATION_TEXT
        "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html",  # REMEDIATION_RECOMMENDATION_URL
        "",  # REMEDIATION_CODE_NATIVEIAC
        "",  # REMEDIATION_CODE_TERRAFORM
        "",  # REMEDIATION_CODE_CLI
        "",  # REMEDIATION_CODE_OTHER
        "CIS-1.4: 5.6 | CIS-2.0: 5.6 | AWS-Foundational-Security-Best-Practices: EC2.8",  # COMPLIANCE
        "",  # CATEGORIES
        "",  # DEPENDS_ON
        "",  # RELATED_TO
        "",  # NOTES
        "5.0.0",  # PROWLER_VERSION
        "",  # ADDITIONAL_URLS
    ]
    row3 = ";".join(row3_fields)
    
    return "\n".join([header, row1, row2, row3])


def test_csv_parser_with_real_data():
    """Test the CSV parser with realistic Prowler output data."""
    from api.parsers.csv_parser import parse_csv, validate_csv_structure
    
    # Create test data
    test_data = create_real_csv_test_data()
    content = test_data.encode('utf-8')
    
    # Validate structure
    is_valid, error = validate_csv_structure(content)
    assert is_valid, f"CSV structure validation failed: {error}"
    print(f"✓ CSV structure validation passed")
    
    # Parse the content
    findings = parse_csv(content)
    
    # Verify parsing results
    assert len(findings) == 3, f"Expected 3 findings, got {len(findings)}"
    print(f"✓ Parsed {len(findings)} findings successfully")
    
    # Verify first finding (FAIL - IAM Access Analyzer)
    finding_1 = findings[0]
    assert finding_1.check_id == "accessanalyzer_enabled"
    assert finding_1.severity == "low"
    assert finding_1.status == "FAIL"
    assert finding_1.provider_type == "aws"
    assert finding_1.account_uid == "123456789012"
    assert finding_1.resource.service == "accessanalyzer"
    assert "CIS-1.4" in finding_1.compliance
    print(f"✓ Finding 1 (accessanalyzer_enabled) parsed correctly")
    
    # Verify second finding (PASS - S3 public access)
    finding_2 = findings[1]
    assert finding_2.check_id == "s3_bucket_public_access_block_enabled"
    assert finding_2.severity == "informational"
    assert finding_2.status == "PASS"
    assert finding_2.resource.service == "s3"
    assert finding_2.resource.type == "bucket"
    assert "PCI-DSS-3.2.1" in finding_2.compliance
    print(f"✓ Finding 2 (s3_bucket_public_access_block_enabled) parsed correctly")
    
    # Verify third finding (PASS - EC2 IMDSv2)
    finding_3 = findings[2]
    assert finding_3.check_id == "ec2_instance_imdsv2_enabled"
    assert finding_3.severity == "informational"
    assert finding_3.status == "PASS"
    assert finding_3.resource.service == "ec2"
    assert finding_3.resource.type == "instance"
    print(f"✓ Finding 3 (ec2_instance_imdsv2_enabled) parsed correctly")
    
    print("\n✓ All CSV parser tests passed!")
    return findings


def test_csv_parser_with_example_file():
    """Test the CSV parser with the actual example output file."""
    from api.parsers.csv_parser import parse_csv, validate_csv_structure
    
    example_file = EXAMPLES_DIR / "example_output_aws.csv"
    
    if not example_file.exists():
        print(f"⚠ Example file not found: {example_file}")
        print("  Skipping example file test")
        return None
    
    print(f"Testing with example file: {example_file}")
    
    # Read the example file
    with open(example_file, 'rb') as f:
        content = f.read()
    
    # Validate structure
    is_valid, error = validate_csv_structure(content)
    assert is_valid, f"CSV structure validation failed: {error}"
    print(f"✓ Example file structure validation passed")
    
    # Parse the content
    findings = parse_csv(content)
    
    print(f"✓ Parsed {len(findings)} findings from example file")
    
    # Verify basic parsing
    assert len(findings) > 0, "Expected at least one finding"
    
    # Check first finding
    first_finding = findings[0]
    assert first_finding.provider_type == "aws"
    assert first_finding.check_id  # Should have a check_id
    assert first_finding.status in ("PASS", "FAIL", "MANUAL")
    print(f"✓ First finding: {first_finding.check_id} ({first_finding.status})")
    
    # Check compliance parsing
    has_compliance = any(f.compliance for f in findings)
    if has_compliance:
        print(f"✓ Compliance data parsed successfully")
    
    return findings


def test_csv_parser_with_azure_example():
    """Test the CSV parser with Azure example output."""
    from api.parsers.csv_parser import parse_csv, validate_csv_structure
    
    example_file = EXAMPLES_DIR / "example_output_azure.csv"
    
    if not example_file.exists():
        print(f"⚠ Azure example file not found: {example_file}")
        print("  Skipping Azure example test")
        return None
    
    print(f"Testing with Azure example file: {example_file}")
    
    with open(example_file, 'rb') as f:
        content = f.read()
    
    is_valid, error = validate_csv_structure(content)
    assert is_valid, f"Azure CSV structure validation failed: {error}"
    print(f"✓ Azure example file structure validation passed")
    
    findings = parse_csv(content)
    print(f"✓ Parsed {len(findings)} findings from Azure example")
    
    if findings:
        first_finding = findings[0]
        assert first_finding.provider_type == "azure"
        print(f"✓ Azure provider type detected correctly")
    
    return findings


def test_csv_parser_with_gcp_example():
    """Test the CSV parser with GCP example output."""
    from api.parsers.csv_parser import parse_csv, validate_csv_structure
    
    example_file = EXAMPLES_DIR / "example_output_gcp.csv"
    
    if not example_file.exists():
        print(f"⚠ GCP example file not found: {example_file}")
        print("  Skipping GCP example test")
        return None
    
    print(f"Testing with GCP example file: {example_file}")
    
    with open(example_file, 'rb') as f:
        content = f.read()
    
    is_valid, error = validate_csv_structure(content)
    assert is_valid, f"GCP CSV structure validation failed: {error}"
    print(f"✓ GCP example file structure validation passed")
    
    findings = parse_csv(content)
    print(f"✓ Parsed {len(findings)} findings from GCP example")
    
    if findings:
        first_finding = findings[0]
        assert first_finding.provider_type == "gcp"
        print(f"✓ GCP provider type detected correctly")
    
    return findings


def save_test_data_to_file():
    """Save test data to a CSV file for manual testing."""
    test_data = create_real_csv_test_data()
    output_path = Path(__file__).parent / "test_prowler_output.csv"
    
    with open(output_path, 'w') as f:
        f.write(test_data)
    
    print(f"✓ Test data saved to: {output_path}")
    print(f"  - 3 findings")
    print(f"  - Provider: aws")
    print(f"  - Account: 123456789012")
    return output_path


if __name__ == "__main__":
    print("=" * 60)
    print("Manual Test: Scan Import with Real Prowler CSV Output")
    print("=" * 60)
    
    # Test 1: Parser with generated realistic data
    print("\n[Test 1] Testing CSV Parser with generated realistic data...")
    try:
        findings = test_csv_parser_with_real_data()
        print("SUCCESS: Parser works with realistic CSV format!")
    except Exception as e:
        print(f"FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # Test 2: Parser with actual example file
    print("\n[Test 2] Testing CSV Parser with example_output_aws.csv...")
    try:
        findings = test_csv_parser_with_example_file()
        if findings:
            print("SUCCESS: Parser works with real example file!")
    except Exception as e:
        print(f"FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # Test 3: Parser with Azure example
    print("\n[Test 3] Testing CSV Parser with Azure example...")
    try:
        findings = test_csv_parser_with_azure_example()
        if findings:
            print("SUCCESS: Parser works with Azure example!")
    except Exception as e:
        print(f"FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # Test 4: Parser with GCP example
    print("\n[Test 4] Testing CSV Parser with GCP example...")
    try:
        findings = test_csv_parser_with_gcp_example()
        if findings:
            print("SUCCESS: Parser works with GCP example!")
    except Exception as e:
        print(f"FAILED: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # Save test data for manual API testing
    print("\n[Test 5] Saving test data for manual API testing...")
    output_file = save_test_data_to_file()
    
    print("\n" + "=" * 60)
    print("Manual API Testing Instructions")
    print("=" * 60)
    print(f"""
To test the scan import API endpoint manually with CSV:

1. Start the development environment:
   docker-compose -f docker-compose-dev.yml up -d

2. Get an authentication token (login via UI or API)

3. Import the test CSV file using curl:
   curl -X POST http://localhost:8080/api/v1/scans/import \\
     -H "Authorization: Bearer <YOUR_TOKEN>" \\
     -H "Content-Type: multipart/form-data" \\
     -F "file=@{output_file}"

4. Or import the real example file:
   curl -X POST http://localhost:8080/api/v1/scans/import \\
     -H "Authorization: Bearer <YOUR_TOKEN>" \\
     -H "Content-Type: multipart/form-data" \\
     -F "file=@examples/output/example_output_aws.csv"

5. Verify the import in the UI at http://localhost:3000/scans
""")
    
    print("✓ Manual test setup complete!")
