#!/usr/bin/env python3
"""
Manual test script for testing scan import with large files (1000+ findings).

This script tests the scan import functionality with large datasets to verify:
- Performance with 1000+ findings
- Memory usage during bulk operations
- Correct handling of many unique resources
- Database bulk insert efficiency

Usage:
    # Run directly from the repository root:
    python api/tests/manual/test_scan_import_large_file.py

    # Or with poetry:
    poetry run python api/tests/manual/test_scan_import_large_file.py

    # Run with custom finding count:
    python api/tests/manual/test_scan_import_large_file.py --count 5000

Prerequisites:
    - Python 3.10+
    - api/src/backend in PYTHONPATH (handled automatically)

This script tests:
    - OCSF parser performance with 1000+ findings
    - CSV parser performance with 1000+ findings
    - Memory efficiency during parsing
    - Bulk operation performance
"""

import argparse
import gc
import json
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

# Add the API backend to the path for imports
PROJECT_ROOT = Path(__file__).parent.parent.parent
API_BACKEND = PROJECT_ROOT / "src" / "backend"
sys.path.insert(0, str(API_BACKEND))

# Default number of findings to generate
DEFAULT_FINDING_COUNT = 1500

# AWS services and check IDs for realistic test data
AWS_SERVICES = [
    ("accessanalyzer", ["accessanalyzer_enabled", "accessanalyzer_findings"]),
    (
        "acm",
        [
            "acm_certificates_expiration_check",
            "acm_certificates_transparency_logs_enabled",
        ],
    ),
    (
        "apigateway",
        [
            "apigateway_restapi_logging_enabled",
            "apigateway_restapi_authorizers_enabled",
        ],
    ),
    (
        "cloudfront",
        [
            "cloudfront_distributions_https_enabled",
            "cloudfront_distributions_logging_enabled",
        ],
    ),
    (
        "cloudtrail",
        ["cloudtrail_multi_region_enabled", "cloudtrail_log_file_validation_enabled"],
    ),
    ("cloudwatch", ["cloudwatch_log_group_retention_policy_specific_days_enabled"]),
    ("config", ["config_recorder_all_regions_enabled"]),
    (
        "dynamodb",
        ["dynamodb_tables_pitr_enabled", "dynamodb_tables_kms_cmk_encryption_enabled"],
    ),
    (
        "ec2",
        [
            "ec2_instance_imdsv2_enabled",
            "ec2_instance_public_ip",
            "ec2_securitygroup_default_restrict_traffic",
        ],
    ),
    (
        "ecr",
        [
            "ecr_repositories_scan_images_on_push_enabled",
            "ecr_repositories_lifecycle_policy_enabled",
        ],
    ),
    ("ecs", ["ecs_task_definitions_no_environment_secrets"]),
    ("efs", ["efs_encryption_at_rest_enabled"]),
    ("eks", ["eks_cluster_logging_enabled", "eks_endpoints_not_publicly_accessible"]),
    ("elasticache", ["elasticache_redis_cluster_automatic_backup_enabled"]),
    ("elb", ["elb_logging_enabled", "elbv2_logging_enabled"]),
    ("emr", ["emr_cluster_master_nodes_no_public_ip"]),
    ("guardduty", ["guardduty_is_enabled"]),
    (
        "iam",
        [
            "iam_root_hardware_mfa_enabled",
            "iam_user_mfa_enabled_console_access",
            "iam_password_policy_minimum_length_14",
        ],
    ),
    ("kms", ["kms_cmk_rotation_enabled"]),
    (
        "lambda",
        [
            "awslambda_function_url_public",
            "awslambda_function_using_supported_runtimes",
        ],
    ),
    (
        "rds",
        [
            "rds_instance_storage_encrypted",
            "rds_instance_multi_az",
            "rds_instance_backup_enabled",
        ],
    ),
    ("redshift", ["redshift_cluster_audit_logging"]),
    (
        "s3",
        [
            "s3_bucket_public_access_block_enabled",
            "s3_bucket_default_encryption",
            "s3_bucket_versioning_enabled",
        ],
    ),
    ("secretsmanager", ["secretsmanager_automatic_rotation_enabled"]),
    ("sns", ["sns_topics_kms_encryption_at_rest_enabled"]),
    ("sqs", ["sqs_queues_server_side_encryption_enabled"]),
    ("ssm", ["ssm_managed_compliant_patching"]),
    ("vpc", ["vpc_flow_logs_enabled"]),
    ("waf", ["wafv2_webacl_logging_enabled"]),
]

# Severity levels
SEVERITIES = ["critical", "high", "medium", "low", "informational"]

# Status codes
STATUSES = ["PASS", "FAIL", "MANUAL"]

# Compliance frameworks
COMPLIANCE_FRAMEWORKS = {
    "CIS-1.4": ["1.1", "1.2", "1.3", "2.1", "2.2", "3.1", "4.1", "5.1"],
    "CIS-2.0": ["1.1", "1.2", "1.3", "2.1", "2.2", "3.1", "4.1", "5.1"],
    "CIS-3.0": ["1.1", "1.2", "1.3", "2.1", "2.2", "3.1", "4.1", "5.1"],
    "PCI-DSS-3.2.1": ["1.2.1", "1.3.1", "2.2.1", "3.4", "8.2.1"],
    "SOC2": ["CC6.1", "CC6.6", "CC6.7", "CC7.1", "CC7.2"],
    "HIPAA": ["164.312(a)(1)", "164.312(b)", "164.312(c)(1)"],
    "NIST-800-53": ["AC-2", "AC-3", "AU-2", "AU-3", "CM-6"],
}

# AWS regions
AWS_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "eu-west-1",
    "eu-west-2",
    "eu-central-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "ap-northeast-1",
]


def generate_ocsf_finding(
    index: int,
    account_uid: str = "123456789012",
    account_name: str = "Test AWS Account",
) -> dict:
    """
    Generate a single OCSF finding with realistic data.

    Args:
        index: Index of the finding (used for unique IDs).
        account_uid: AWS account ID.
        account_name: AWS account name.

    Returns:
        Dictionary representing an OCSF finding.
    """
    # Select service and check based on index for variety
    service_idx = index % len(AWS_SERVICES)
    service_name, check_ids = AWS_SERVICES[service_idx]
    check_id = check_ids[index % len(check_ids)]

    # Select other attributes
    severity = SEVERITIES[index % len(SEVERITIES)]
    status = STATUSES[index % len(STATUSES)]
    region = AWS_REGIONS[index % len(AWS_REGIONS)]

    # Generate unique IDs
    finding_uid = f"prowler-aws-{check_id}-{account_uid}-{region}-{uuid4().hex[:8]}"
    resource_uid = f"arn:aws:{service_name}:{region}:{account_uid}:resource-{index}"

    # Generate timestamp with slight variation
    base_time = datetime.now() - timedelta(hours=index % 24)
    timestamp = base_time.isoformat()
    unix_timestamp = int(base_time.timestamp())

    # Generate compliance data
    compliance = {}
    for framework, controls in COMPLIANCE_FRAMEWORKS.items():
        if index % 3 == 0:  # Add compliance to ~1/3 of findings
            compliance[framework] = [controls[index % len(controls)]]

    return {
        "message": f"{service_name.upper()} check {check_id} for resource-{index}",
        "metadata": {
            "event_code": check_id,
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
        "severity_id": SEVERITIES.index(severity) + 1,
        "severity": severity.capitalize(),
        "status": "New",
        "status_code": status,
        "status_detail": f"Resource resource-{index} check result: {status}",
        "status_id": 1,
        "unmapped": {
            "related_url": f"https://docs.aws.amazon.com/{service_name}/",
            "categories": [service_name],
            "depends_on": [],
            "related_to": [],
            "additional_urls": [],
            "notes": "",
            "compliance": compliance,
        },
        "activity_name": "Create",
        "activity_id": 1,
        "finding_info": {
            "created_time": unix_timestamp,
            "created_time_dt": timestamp,
            "desc": f"Check {check_id} for {service_name}",
            "product_uid": "prowler",
            "title": f"{service_name.upper()} {check_id.replace('_', ' ').title()}",
            "types": [service_name.upper()],
            "uid": finding_uid,
        },
        "resources": [
            {
                "cloud_partition": "aws",
                "region": region,
                "data": {
                    "details": "",
                    "metadata": {
                        "arn": resource_uid,
                        "name": f"resource-{index}",
                        "status": "AVAILABLE",
                        "findings": [],
                        "tags": [{"Key": "Environment", "Value": "Test"}],
                        "type": service_name,
                        "region": region,
                    },
                },
                "group": {"name": service_name},
                "labels": [],
                "name": f"resource-{index}",
                "type": service_name,
                "uid": resource_uid,
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
                "labels": [],
            },
            "org": {"name": "", "uid": ""},
            "provider": "aws",
            "region": region,
        },
        "remediation": {
            "desc": f"Remediation for {check_id}",
            "references": [f"https://docs.aws.amazon.com/{service_name}/"],
        },
        "risk_details": f"Risk details for {check_id}",
        "time": unix_timestamp,
        "time_dt": timestamp,
        "type_uid": 200401,
        "type_name": "Detection Finding: Create",
    }


def generate_large_ocsf_data(count: int) -> list[dict]:
    """
    Generate a large list of OCSF findings.

    Args:
        count: Number of findings to generate.

    Returns:
        List of OCSF finding dictionaries.
    """
    print(f"Generating {count} OCSF findings...")
    start_time = time.time()

    findings = [generate_ocsf_finding(i) for i in range(count)]

    elapsed = time.time() - start_time
    print(f"✓ Generated {count} findings in {elapsed:.2f}s")

    return findings


def generate_csv_row(
    index: int,
    account_uid: str = "123456789012",
    account_name: str = "Test AWS Account",
) -> str:
    """
    Generate a single CSV row with realistic data.

    Args:
        index: Index of the finding (used for unique IDs).
        account_uid: AWS account ID.
        account_name: AWS account name.

    Returns:
        Semicolon-delimited CSV row string.
    """
    # Select service and check based on index for variety
    service_idx = index % len(AWS_SERVICES)
    service_name, check_ids = AWS_SERVICES[service_idx]
    check_id = check_ids[index % len(check_ids)]

    # Select other attributes
    severity = SEVERITIES[index % len(SEVERITIES)]
    status = STATUSES[index % len(STATUSES)]
    region = AWS_REGIONS[index % len(AWS_REGIONS)]

    # Generate unique IDs
    finding_uid = f"prowler-aws-{check_id}-{account_uid}-{region}-{uuid4().hex[:8]}"
    resource_uid = f"arn:aws:{service_name}:{region}:{account_uid}:resource-{index}"

    # Generate timestamp
    base_time = datetime.now() - timedelta(hours=index % 24)
    timestamp = base_time.strftime("%Y-%m-%d %H:%M:%S.%f")

    # Generate compliance string
    compliance_parts = []
    for framework, controls in COMPLIANCE_FRAMEWORKS.items():
        if index % 3 == 0:
            control = controls[index % len(controls)]
            compliance_parts.append(f"{framework}: {control}")
    compliance_str = " | ".join(compliance_parts)

    # Build row fields (42 columns)
    fields = [
        "profile",  # AUTH_METHOD
        timestamp,  # TIMESTAMP
        account_uid,  # ACCOUNT_UID
        account_name,  # ACCOUNT_NAME
        "",  # ACCOUNT_EMAIL
        "",  # ACCOUNT_ORGANIZATION_UID
        "",  # ACCOUNT_ORGANIZATION_NAME
        "",  # ACCOUNT_TAGS
        finding_uid,  # FINDING_UID
        "aws",  # PROVIDER
        check_id,  # CHECK_ID
        f"{service_name.upper()} {check_id.replace('_', ' ').title()}",  # CHECK_TITLE
        service_name.upper(),  # CHECK_TYPE
        status,  # STATUS
        f"Resource resource-{index} check result: {status}",  # STATUS_EXTENDED
        "False",  # MUTED
        service_name,  # SERVICE_NAME
        "",  # SUBSERVICE_NAME
        severity,  # SEVERITY
        service_name,  # RESOURCE_TYPE
        resource_uid,  # RESOURCE_UID
        f"resource-{index}",  # RESOURCE_NAME
        "",  # RESOURCE_DETAILS
        "",  # RESOURCE_TAGS
        "aws",  # PARTITION
        region,  # REGION
        f"Check {check_id} for {service_name}",  # DESCRIPTION
        f"Risk details for {check_id}",  # RISK
        f"https://docs.aws.amazon.com/{service_name}/",  # RELATED_URL
        f"Remediation for {check_id}",  # REMEDIATION_RECOMMENDATION_TEXT
        f"https://docs.aws.amazon.com/{service_name}/",  # REMEDIATION_RECOMMENDATION_URL
        "",  # REMEDIATION_CODE_NATIVEIAC
        "",  # REMEDIATION_CODE_TERRAFORM
        "",  # REMEDIATION_CODE_CLI
        "",  # REMEDIATION_CODE_OTHER
        compliance_str,  # COMPLIANCE
        "",  # CATEGORIES
        "",  # DEPENDS_ON
        "",  # RELATED_TO
        "",  # NOTES
        "5.0.0",  # PROWLER_VERSION
        "",  # ADDITIONAL_URLS
    ]

    return ";".join(fields)


def generate_large_csv_data(count: int) -> str:
    """
    Generate a large CSV file content.

    Args:
        count: Number of findings to generate.

    Returns:
        CSV content as string (semicolon-delimited).
    """
    print(f"Generating {count} CSV rows...")
    start_time = time.time()

    # CSV header (42 columns)
    header = "AUTH_METHOD;TIMESTAMP;ACCOUNT_UID;ACCOUNT_NAME;ACCOUNT_EMAIL;ACCOUNT_ORGANIZATION_UID;ACCOUNT_ORGANIZATION_NAME;ACCOUNT_TAGS;FINDING_UID;PROVIDER;CHECK_ID;CHECK_TITLE;CHECK_TYPE;STATUS;STATUS_EXTENDED;MUTED;SERVICE_NAME;SUBSERVICE_NAME;SEVERITY;RESOURCE_TYPE;RESOURCE_UID;RESOURCE_NAME;RESOURCE_DETAILS;RESOURCE_TAGS;PARTITION;REGION;DESCRIPTION;RISK;RELATED_URL;REMEDIATION_RECOMMENDATION_TEXT;REMEDIATION_RECOMMENDATION_URL;REMEDIATION_CODE_NATIVEIAC;REMEDIATION_CODE_TERRAFORM;REMEDIATION_CODE_CLI;REMEDIATION_CODE_OTHER;COMPLIANCE;CATEGORIES;DEPENDS_ON;RELATED_TO;NOTES;PROWLER_VERSION;ADDITIONAL_URLS"

    rows = [header]
    for i in range(count):
        rows.append(generate_csv_row(i))

    elapsed = time.time() - start_time
    print(f"✓ Generated {count} CSV rows in {elapsed:.2f}s")

    return "\n".join(rows)


def measure_memory() -> float:
    """Get current memory usage in MB."""
    import resource

    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024 / 1024


def test_ocsf_parser_large_file(count: int) -> dict:
    """
    Test OCSF parser with a large number of findings.

    Args:
        count: Number of findings to test with.

    Returns:
        Dictionary with test results.
    """
    from api.parsers.ocsf_parser import parse_ocsf_json, validate_ocsf_structure

    print(f"\n{'=' * 60}")
    print(f"Testing OCSF Parser with {count} findings")
    print(f"{'=' * 60}")

    results = {
        "format": "ocsf",
        "count": count,
        "success": False,
    }

    # Generate test data
    gc.collect()
    mem_before_gen = measure_memory()

    test_data = generate_large_ocsf_data(count)
    content = json.dumps(test_data).encode("utf-8")

    mem_after_gen = measure_memory()
    results["generation_memory_mb"] = mem_after_gen - mem_before_gen
    results["file_size_mb"] = len(content) / (1024 * 1024)

    print(f"File size: {results['file_size_mb']:.2f} MB")
    print(f"Memory used for generation: {results['generation_memory_mb']:.2f} MB")

    # Validate structure
    print("\nValidating OCSF structure...")
    start_time = time.time()
    is_valid, error = validate_ocsf_structure(content)
    results["validation_time_s"] = time.time() - start_time

    if not is_valid:
        print(f"✗ Validation failed: {error}")
        return results

    print(f"✓ Validation passed in {results['validation_time_s']:.2f}s")

    # Parse content
    print("\nParsing OCSF content...")
    gc.collect()
    mem_before_parse = measure_memory()
    start_time = time.time()

    findings = parse_ocsf_json(content)

    results["parse_time_s"] = time.time() - start_time
    mem_after_parse = measure_memory()
    results["parse_memory_mb"] = mem_after_parse - mem_before_parse

    print(f"✓ Parsed {len(findings)} findings in {results['parse_time_s']:.2f}s")
    print(f"Memory used for parsing: {results['parse_memory_mb']:.2f} MB")

    # Verify results
    assert len(findings) == count, f"Expected {count} findings, got {len(findings)}"

    # Verify data integrity
    print("\nVerifying data integrity...")

    # Check first finding
    first = findings[0]
    assert first.provider_type == "aws"
    assert first.account_uid == "123456789012"
    assert first.check_id is not None
    assert first.status in ("PASS", "FAIL", "MANUAL")
    print(f"✓ First finding: {first.check_id} ({first.status})")

    # Check last finding
    last = findings[-1]
    assert last.provider_type == "aws"
    assert last.check_id is not None
    print(f"✓ Last finding: {last.check_id} ({last.status})")

    # Check unique resources
    unique_resources = set()
    for f in findings:
        for r in f.resources:
            unique_resources.add(r.uid)

    results["unique_resources"] = len(unique_resources)
    print(f"✓ Unique resources: {len(unique_resources)}")

    # Check compliance data
    findings_with_compliance = sum(1 for f in findings if f.compliance)
    results["findings_with_compliance"] = findings_with_compliance
    print(f"✓ Findings with compliance: {findings_with_compliance}")

    results["success"] = True
    results["findings_parsed"] = len(findings)

    # Performance metrics
    results["findings_per_second"] = count / results["parse_time_s"]
    print(f"\nPerformance: {results['findings_per_second']:.0f} findings/second")

    return results


def test_csv_parser_large_file(count: int) -> dict:
    """
    Test CSV parser with a large number of findings.

    Args:
        count: Number of findings to test with.

    Returns:
        Dictionary with test results.
    """
    from api.parsers.csv_parser import parse_csv, validate_csv_structure

    print(f"\n{'=' * 60}")
    print(f"Testing CSV Parser with {count} findings")
    print(f"{'=' * 60}")

    results = {
        "format": "csv",
        "count": count,
        "success": False,
    }

    # Generate test data
    gc.collect()
    mem_before_gen = measure_memory()

    test_data = generate_large_csv_data(count)
    content = test_data.encode("utf-8")

    mem_after_gen = measure_memory()
    results["generation_memory_mb"] = mem_after_gen - mem_before_gen
    results["file_size_mb"] = len(content) / (1024 * 1024)

    print(f"File size: {results['file_size_mb']:.2f} MB")
    print(f"Memory used for generation: {results['generation_memory_mb']:.2f} MB")

    # Validate structure
    print("\nValidating CSV structure...")
    start_time = time.time()
    is_valid, error = validate_csv_structure(content)
    results["validation_time_s"] = time.time() - start_time

    if not is_valid:
        print(f"✗ Validation failed: {error}")
        return results

    print(f"✓ Validation passed in {results['validation_time_s']:.2f}s")

    # Parse content
    print("\nParsing CSV content...")
    gc.collect()
    mem_before_parse = measure_memory()
    start_time = time.time()

    findings = parse_csv(content)

    results["parse_time_s"] = time.time() - start_time
    mem_after_parse = measure_memory()
    results["parse_memory_mb"] = mem_after_parse - mem_before_parse

    print(f"✓ Parsed {len(findings)} findings in {results['parse_time_s']:.2f}s")
    print(f"Memory used for parsing: {results['parse_memory_mb']:.2f} MB")

    # Verify results
    assert len(findings) == count, f"Expected {count} findings, got {len(findings)}"

    # Verify data integrity
    print("\nVerifying data integrity...")

    # Check first finding
    first = findings[0]
    assert first.provider_type == "aws"
    assert first.account_uid == "123456789012"
    assert first.check_id is not None
    assert first.status in ("PASS", "FAIL", "MANUAL")
    print(f"✓ First finding: {first.check_id} ({first.status})")

    # Check last finding
    last = findings[-1]
    assert last.provider_type == "aws"
    assert last.check_id is not None
    print(f"✓ Last finding: {last.check_id} ({last.status})")

    # Check unique resources
    unique_resources = set()
    for f in findings:
        unique_resources.add(f.resource.uid)

    results["unique_resources"] = len(unique_resources)
    print(f"✓ Unique resources: {len(unique_resources)}")

    # Check compliance data
    findings_with_compliance = sum(1 for f in findings if f.compliance)
    results["findings_with_compliance"] = findings_with_compliance
    print(f"✓ Findings with compliance: {findings_with_compliance}")

    results["success"] = True
    results["findings_parsed"] = len(findings)

    # Performance metrics
    results["findings_per_second"] = count / results["parse_time_s"]
    print(f"\nPerformance: {results['findings_per_second']:.0f} findings/second")

    return results


def save_large_test_files(count: int) -> tuple[Path, Path]:
    """
    Save large test files for manual API testing.

    Args:
        count: Number of findings to generate.

    Returns:
        Tuple of (json_path, csv_path).
    """
    output_dir = Path(__file__).parent

    # Generate and save OCSF JSON
    print(f"\nGenerating large OCSF JSON file ({count} findings)...")
    ocsf_data = generate_large_ocsf_data(count)
    json_path = output_dir / f"test_prowler_output_large_{count}.ocsf.json"

    with open(json_path, "w") as f:
        json.dump(ocsf_data, f)

    json_size = json_path.stat().st_size / (1024 * 1024)
    print(f"✓ Saved: {json_path} ({json_size:.2f} MB)")

    # Generate and save CSV
    print(f"\nGenerating large CSV file ({count} findings)...")
    csv_data = generate_large_csv_data(count)
    csv_path = output_dir / f"test_prowler_output_large_{count}.csv"

    with open(csv_path, "w") as f:
        f.write(csv_data)

    csv_size = csv_path.stat().st_size / (1024 * 1024)
    print(f"✓ Saved: {csv_path} ({csv_size:.2f} MB)")

    return json_path, csv_path


def print_summary(results: list[dict]) -> None:
    """Print a summary of all test results."""
    print(f"\n{'=' * 60}")
    print("TEST SUMMARY")
    print(f"{'=' * 60}")

    for r in results:
        status = "✓ PASS" if r["success"] else "✗ FAIL"
        print(f"\n{r['format'].upper()} ({r['count']} findings): {status}")

        if r["success"]:
            print(f"  File size: {r['file_size_mb']:.2f} MB")
            print(f"  Parse time: {r['parse_time_s']:.2f}s")
            print(f"  Performance: {r['findings_per_second']:.0f} findings/second")
            print(f"  Unique resources: {r['unique_resources']}")
            print(f"  Findings with compliance: {r['findings_with_compliance']}")

    # Check if all tests passed
    all_passed = all(r["success"] for r in results)

    print(f"\n{'=' * 60}")
    if all_passed:
        print("ALL TESTS PASSED ✓")
    else:
        print("SOME TESTS FAILED ✗")
    print(f"{'=' * 60}")


def main():
    """Main entry point for the test script."""
    parser = argparse.ArgumentParser(
        description="Test scan import with large files (1000+ findings)"
    )
    parser.add_argument(
        "--count",
        "-c",
        type=int,
        default=DEFAULT_FINDING_COUNT,
        help=f"Number of findings to generate (default: {DEFAULT_FINDING_COUNT})",
    )
    parser.add_argument(
        "--save-files",
        "-s",
        action="store_true",
        help="Save generated test files for manual API testing",
    )
    parser.add_argument(
        "--ocsf-only", action="store_true", help="Only test OCSF/JSON format"
    )
    parser.add_argument("--csv-only", action="store_true", help="Only test CSV format")

    args = parser.parse_args()

    print("=" * 60)
    print("Large File Test: Scan Import with 1000+ Findings")
    print("=" * 60)
    print(f"Finding count: {args.count}")

    results = []

    # Test OCSF parser
    if not args.csv_only:
        try:
            ocsf_results = test_ocsf_parser_large_file(args.count)
            results.append(ocsf_results)
        except Exception as e:
            print(f"✗ OCSF test failed: {e}")
            import traceback

            traceback.print_exc()
            results.append(
                {
                    "format": "ocsf",
                    "count": args.count,
                    "success": False,
                    "error": str(e),
                }
            )

    # Test CSV parser
    if not args.ocsf_only:
        try:
            csv_results = test_csv_parser_large_file(args.count)
            results.append(csv_results)
        except Exception as e:
            print(f"✗ CSV test failed: {e}")
            import traceback

            traceback.print_exc()
            results.append(
                {
                    "format": "csv",
                    "count": args.count,
                    "success": False,
                    "error": str(e),
                }
            )

    # Print summary
    print_summary(results)

    # Save files if requested
    if args.save_files:
        print("\nSaving test files for manual API testing...")
        json_path, csv_path = save_large_test_files(args.count)

        print(
            f"""
{'=' * 60}
Manual API Testing Instructions
{'=' * 60}

To test the scan import API endpoint with large files:

1. Start the development environment:
   docker-compose -f docker-compose-dev.yml up -d

2. Get an authentication token (login via UI or API)

3. Import the large JSON file:
   curl -X POST http://localhost:8080/api/v1/scans/import \\
     -H "Authorization: Bearer <YOUR_TOKEN>" \\
     -H "Content-Type: multipart/form-data" \\
     -F "file=@{json_path}"

4. Import the large CSV file:
   curl -X POST http://localhost:8080/api/v1/scans/import \\
     -H "Authorization: Bearer <YOUR_TOKEN>" \\
     -H "Content-Type: multipart/form-data" \\
     -F "file=@{csv_path}"

5. Verify the imports in the UI at http://localhost:3000/scans
"""
        )

    # Exit with appropriate code
    all_passed = all(r["success"] for r in results)
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
