#!/usr/bin/env python3
"""
Manual test script for testing scan import with real Prowler JSON output.

This script tests the scan import functionality using real Prowler OCSF JSON output.
It validates that the OCSF parser correctly handles real Prowler CLI output format.

Usage:
    # Run directly from the repository root:
    python api/tests/manual/test_scan_import_real_json.py

    # Or with poetry:
    poetry run python api/tests/manual/test_scan_import_real_json.py

Prerequisites:
    - Python 3.10+
    - api/src/backend in PYTHONPATH (handled automatically)

This script tests:
    - OCSF structure validation
    - Parsing of real Prowler JSON format
    - Extraction of findings, resources, and compliance data
    - Provider information extraction
"""

import json
import sys
from datetime import datetime
from pathlib import Path
from uuid import uuid4

# Add the API backend to the path for imports
PROJECT_ROOT = Path(__file__).parent.parent.parent
API_BACKEND = PROJECT_ROOT / "src" / "backend"
sys.path.insert(0, str(API_BACKEND))


def create_real_ocsf_test_data() -> list[dict]:
    """
    Create realistic OCSF test data based on actual Prowler output format.

    This generates test data that matches the structure of real Prowler CLI output
    as seen in examples/output/example_output_aws.ocsf.json.

    Returns:
        List of OCSF finding dictionaries.
    """
    timestamp = datetime.now().isoformat()
    unix_timestamp = int(datetime.now().timestamp())

    # Generate unique IDs for this test run
    finding_uid_1 = str(uuid4())
    finding_uid_2 = str(uuid4())
    finding_uid_3 = str(uuid4())
    resource_uid_1 = "arn:aws:iam::123456789012:root"
    resource_uid_2 = f"arn:aws:s3:::test-bucket-{uuid4().hex[:8]}"
    resource_uid_3 = f"arn:aws:ec2:us-east-1:123456789012:instance/i-{uuid4().hex[:17]}"

    return [
        {
            "message": "IAM Access Analyzer in account 123456789012 is not enabled.",
            "metadata": {
                "event_code": "accessanalyzer_enabled",
                "product": {
                    "name": "Prowler",
                    "uid": "prowler",
                    "vendor_name": "Prowler",
                    "version": "5.0.0",
                },
                "profiles": ["cloud", "datetime"],
                "tenant_uid": "",
                "version": "1.4.0",
            },
            "severity_id": 2,
            "severity": "Low",
            "status": "New",
            "status_code": "FAIL",
            "status_detail": "IAM Access Analyzer in account 123456789012 is not enabled.",
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
                        "Create analyzers in each active regions",
                    ],
                },
            },
            "activity_name": "Create",
            "activity_id": 1,
            "finding_info": {
                "created_time": unix_timestamp,
                "created_time_dt": timestamp,
                "desc": "Check if IAM Access Analyzer is enabled",
                "product_uid": "prowler",
                "title": "Check if IAM Access Analyzer is enabled",
                "types": ["IAM"],
                "uid": finding_uid_1,
            },
            "resources": [
                {
                    "cloud_partition": "aws",
                    "region": "us-east-1",
                    "data": {
                        "details": "",
                        "metadata": {
                            "arn": resource_uid_1,
                            "name": "123456789012",
                            "status": "NOT_AVAILABLE",
                            "findings": [],
                            "tags": [],
                            "type": "",
                            "region": "us-east-1",
                        },
                    },
                    "group": {"name": "accessanalyzer"},
                    "labels": [],
                    "name": "123456789012",
                    "type": "Other",
                    "uid": resource_uid_1,
                }
            ],
            "category_name": "Findings",
            "category_uid": 2,
            "class_name": "Detection Finding",
            "class_uid": 2004,
            "cloud": {
                "account": {
                    "name": "Test AWS Account",
                    "type": "AWS Account",
                    "type_id": 10,
                    "uid": "123456789012",
                    "labels": [],
                },
                "org": {"name": "", "uid": ""},
                "provider": "aws",
                "region": "us-east-1",
            },
            "remediation": {
                "desc": "Enable IAM Access Analyzer for all accounts.",
                "references": [
                    "aws accessanalyzer create-analyzer --analyzer-name <NAME> --type <ACCOUNT|ORGANIZATION>",
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html",
                ],
            },
            "risk_details": "AWS IAM Access Analyzer helps identify resources shared with external entities.",
            "time": unix_timestamp,
            "time_dt": timestamp,
            "type_uid": 200401,
            "type_name": "Detection Finding: Create",
        },
        {
            "message": "S3 bucket test-bucket has public access enabled.",
            "metadata": {
                "event_code": "s3_bucket_public_access_block_enabled",
                "product": {
                    "name": "Prowler",
                    "uid": "prowler",
                    "vendor_name": "Prowler",
                    "version": "5.0.0",
                },
                "profiles": ["cloud", "datetime"],
                "tenant_uid": "",
                "version": "1.4.0",
            },
            "severity_id": 4,
            "severity": "High",
            "status": "New",
            "status_code": "FAIL",
            "status_detail": "S3 bucket test-bucket has public access enabled.",
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
                    "SOC2": ["CC6.1"],
                },
            },
            "activity_name": "Create",
            "activity_id": 1,
            "finding_info": {
                "created_time": unix_timestamp,
                "created_time_dt": timestamp,
                "desc": "Check if S3 buckets have public access block enabled",
                "product_uid": "prowler",
                "title": "S3 Bucket Public Access Block Check",
                "types": ["S3"],
                "uid": finding_uid_2,
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
                            "status": "PUBLIC",
                            "findings": [],
                            "tags": [{"Key": "Environment", "Value": "Test"}],
                            "type": "bucket",
                            "region": "us-west-2",
                        },
                    },
                    "group": {"name": "s3"},
                    "labels": [],
                    "name": "test-bucket",
                    "type": "bucket",
                    "uid": resource_uid_2,
                }
            ],
            "category_name": "Findings",
            "category_uid": 2,
            "class_name": "Detection Finding",
            "class_uid": 2004,
            "cloud": {
                "account": {
                    "name": "Test AWS Account",
                    "type": "AWS Account",
                    "type_id": 10,
                    "uid": "123456789012",
                    "labels": [],
                },
                "org": {"name": "", "uid": ""},
                "provider": "aws",
                "region": "us-west-2",
            },
            "remediation": {
                "desc": "Enable S3 Block Public Access settings.",
                "references": [
                    "aws s3api put-public-access-block --bucket <bucket-name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
                ],
            },
            "risk_details": "Public S3 buckets can expose sensitive data to unauthorized users.",
            "time": unix_timestamp,
            "time_dt": timestamp,
            "type_uid": 200401,
            "type_name": "Detection Finding: Create",
        },
        {
            "message": "EC2 instance i-1234567890abcdef0 has IMDSv2 enabled.",
            "metadata": {
                "event_code": "ec2_instance_imdsv2_enabled",
                "product": {
                    "name": "Prowler",
                    "uid": "prowler",
                    "vendor_name": "Prowler",
                    "version": "5.0.0",
                },
                "profiles": ["cloud", "datetime"],
                "tenant_uid": "",
                "version": "1.4.0",
            },
            "severity_id": 1,
            "severity": "Informational",
            "status": "New",
            "status_code": "PASS",
            "status_detail": "EC2 instance i-1234567890abcdef0 has IMDSv2 enabled.",
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
                    "AWS-Foundational-Security-Best-Practices": ["EC2.8"],
                },
            },
            "activity_name": "Create",
            "activity_id": 1,
            "finding_info": {
                "created_time": unix_timestamp,
                "created_time_dt": timestamp,
                "desc": "Check if EC2 instances have IMDSv2 enabled",
                "product_uid": "prowler",
                "title": "EC2 Instance IMDSv2 Check",
                "types": ["EC2"],
                "uid": finding_uid_3,
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
                            "region": "us-east-1",
                        },
                    },
                    "group": {"name": "ec2"},
                    "labels": [],
                    "name": "test-instance",
                    "type": "instance",
                    "uid": resource_uid_3,
                }
            ],
            "category_name": "Findings",
            "category_uid": 2,
            "class_name": "Detection Finding",
            "class_uid": 2004,
            "cloud": {
                "account": {
                    "name": "Test AWS Account",
                    "type": "AWS Account",
                    "type_id": 10,
                    "uid": "123456789012",
                    "labels": [],
                },
                "org": {"name": "", "uid": ""},
                "provider": "aws",
                "region": "us-east-1",
            },
            "remediation": {
                "desc": "IMDSv2 is already enabled. No action required.",
                "references": [],
            },
            "risk_details": "IMDSv2 provides enhanced security for instance metadata access.",
            "time": unix_timestamp,
            "time_dt": timestamp,
            "type_uid": 200401,
            "type_name": "Detection Finding: Create",
        },
    ]


def test_ocsf_parser_with_real_data():
    """Test the OCSF parser with realistic Prowler output data."""
    from api.parsers.ocsf_parser import parse_ocsf_json, validate_ocsf_structure

    # Create test data
    test_data = create_real_ocsf_test_data()
    content = json.dumps(test_data).encode("utf-8")

    # Validate structure
    is_valid, error = validate_ocsf_structure(content)
    assert is_valid, f"OCSF structure validation failed: {error}"
    print("✓ OCSF structure validation passed")

    # Parse the content
    findings = parse_ocsf_json(content)

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
    assert len(finding_1.resources) == 1
    assert "CIS-1.4" in finding_1.compliance
    print("✓ Finding 1 (accessanalyzer_enabled) parsed correctly")

    # Verify second finding (FAIL - S3 public access)
    finding_2 = findings[1]
    assert finding_2.check_id == "s3_bucket_public_access_block_enabled"
    assert finding_2.severity == "high"
    assert finding_2.status == "FAIL"
    assert len(finding_2.resources) == 1
    assert finding_2.resources[0].service == "s3"
    assert "PCI-DSS-3.2.1" in finding_2.compliance
    print("✓ Finding 2 (s3_bucket_public_access_block_enabled) parsed correctly")

    # Verify third finding (PASS - EC2 IMDSv2)
    finding_3 = findings[2]
    assert finding_3.check_id == "ec2_instance_imdsv2_enabled"
    assert finding_3.severity == "informational"
    assert finding_3.status == "PASS"
    assert len(finding_3.resources) == 1
    assert finding_3.resources[0].service == "ec2"
    print("✓ Finding 3 (ec2_instance_imdsv2_enabled) parsed correctly")

    print("\n✓ All OCSF parser tests passed!")
    return findings


def test_ocsf_parser_with_single_finding():
    """Test the OCSF parser with a single finding (simpler test case)."""
    from api.parsers.ocsf_parser import parse_ocsf_json, validate_ocsf_structure

    # Create minimal test data with one finding
    test_data = [
        {
            "message": "IAM Access Analyzer in account 123456789012 is not enabled.",
            "metadata": {
                "event_code": "accessanalyzer_enabled",
                "product": {
                    "name": "Prowler",
                    "uid": "prowler",
                    "vendor_name": "Prowler",
                    "version": "5.0.0",
                },
                "profiles": ["cloud", "datetime"],
                "tenant_uid": "",
                "version": "1.4.0",
            },
            "severity": "Low",
            "status_code": "FAIL",
            "status_detail": "IAM Access Analyzer in account 123456789012 is not enabled.",
            "unmapped": {"compliance": {"CIS-1.4": ["1.20"], "CIS-2.0": ["1.20"]}},
            "finding_info": {
                "created_time": 1735570800,
                "created_time_dt": "2024-12-30T15:00:00.000000",
                "desc": "Check if IAM Access Analyzer is enabled",
                "product_uid": "prowler",
                "title": "Check if IAM Access Analyzer is enabled",
                "types": ["IAM"],
                "uid": "prowler-aws-accessanalyzer_enabled-123456789012-us-east-1",
            },
            "resources": [
                {
                    "cloud_partition": "aws",
                    "region": "us-east-1",
                    "group": {"name": "accessanalyzer"},
                    "name": "123456789012",
                    "type": "Other",
                    "uid": "arn:aws:iam::123456789012:root",
                }
            ],
            "cloud": {
                "account": {"name": "Test AWS Account", "uid": "123456789012"},
                "provider": "aws",
                "region": "us-east-1",
            },
            "time": 1735570800,
            "time_dt": "2024-12-30T15:00:00.000000",
        }
    ]

    content = json.dumps(test_data).encode("utf-8")

    # Validate structure
    is_valid, error = validate_ocsf_structure(content)
    print(f"Structure valid: {is_valid}")
    if not is_valid:
        print(f"Error: {error}")
        return None

    # Parse the content
    findings = parse_ocsf_json(content)
    print(f"Parsed {len(findings)} findings")

    if findings:
        f = findings[0]
        print(f"Check ID: {f.check_id}")
        print(f"Severity: {f.severity}")
        print(f"Status: {f.status}")
        print(f"Provider: {f.provider_type}")
        print(f"Account: {f.account_uid}")
        print(f"Resources: {len(f.resources)}")
        print(f"Compliance: {list(f.compliance.keys())}")

    return findings


def save_test_data_to_file():
    """Save test data to a JSON file for manual testing."""
    test_data = create_real_ocsf_test_data()
    output_path = Path(__file__).parent / "test_prowler_output.ocsf.json"

    with open(output_path, "w") as f:
        json.dump(test_data, f, indent=2)

    print(f"✓ Test data saved to: {output_path}")
    print(f"  - {len(test_data)} findings")
    print("  - Provider: aws")
    print("  - Account: 123456789012")
    return output_path


if __name__ == "__main__":
    print("=" * 60)
    print("Manual Test: Scan Import with Real Prowler JSON Output")
    print("=" * 60)

    # Test 1: Simple single-finding test
    print("\n[Test 1] Testing OCSF Parser with single finding...")
    try:
        findings = test_ocsf_parser_with_single_finding()
        if findings:
            print("SUCCESS: Parser works with real Prowler JSON format!")
        else:
            print("FAILED: No findings parsed")
            sys.exit(1)
    except Exception as e:
        print(f"FAILED: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

    # Test 2: Full test with multiple findings
    print("\n[Test 2] Testing OCSF Parser with multiple findings...")
    try:
        findings = test_ocsf_parser_with_real_data()
        print("SUCCESS: All parser tests passed!")
    except Exception as e:
        print(f"FAILED: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)

    # Save test data for manual API testing
    print("\n[Test 3] Saving test data for manual API testing...")
    output_file = save_test_data_to_file()

    print("\n" + "=" * 60)
    print("Manual API Testing Instructions")
    print("=" * 60)
    print(
        f"""
To test the scan import API endpoint manually:

1. Start the development environment:
   docker-compose -f docker-compose-dev.yml up -d

2. Get an authentication token (login via UI or API)

3. Import the test file using curl:
   curl -X POST http://localhost:8080/api/v1/scans/import \\
     -H "Authorization: Bearer <YOUR_TOKEN>" \\
     -H "Content-Type: multipart/form-data" \\
     -F "file=@{output_file}"

4. Or import inline JSON:
   curl -X POST http://localhost:8080/api/v1/scans/import \\
     -H "Authorization: Bearer <YOUR_TOKEN>" \\
     -H "Content-Type: application/json" \\
     -d '{{"data": <contents of test file>}}'

5. Verify the import in the UI at http://localhost:3000/scans
"""
    )

    print("✓ Manual test setup complete!")
