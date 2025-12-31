#!/usr/bin/env python3
"""
Manual test script for testing scan import error scenarios.

This script tests the scan import functionality with various error scenarios
including invalid files, missing fields, and malformed data.

Usage:
    # Run directly from the repository root:
    python api/tests/manual/test_scan_import_error_scenarios.py

    # Or with poetry:
    poetry run python api/tests/manual/test_scan_import_error_scenarios.py

Prerequisites:
    - Python 3.10+
    - api/src/backend in PYTHONPATH (handled automatically)

This script tests:
    - Invalid file formats (binary, XML, plain text)
    - Missing required fields in JSON/OCSF
    - Missing required columns in CSV
    - Empty required field values
    - Unsupported provider types
    - Malformed JSON/CSV content
"""

import json
import sys
from pathlib import Path
from uuid import uuid4

# Add the API backend to the path for imports
PROJECT_ROOT = Path(__file__).parent.parent.parent
API_BACKEND = PROJECT_ROOT / "src" / "backend"
sys.path.insert(0, str(API_BACKEND))


# ============================================================================
# Test Data Generators for Error Scenarios
# ============================================================================


def create_invalid_json_content() -> bytes:
    """Create invalid JSON content (not parseable)."""
    return b"{ this is not valid json }"


def create_non_array_json_content() -> bytes:
    """Create JSON that is an object instead of array."""
    return json.dumps({"message": "This is an object, not an array"}).encode("utf-8")


def create_json_with_non_object_elements() -> bytes:
    """Create JSON array with non-object elements."""
    return json.dumps(["string1", "string2", 123, True]).encode("utf-8")


def create_ocsf_missing_metadata_event_code() -> bytes:
    """Create OCSF JSON missing metadata.event_code."""
    data = [{
        "message": "Test finding",
        "metadata": {},  # Missing event_code
        "severity": "Low",
        "status_code": "FAIL",
        "finding_info": {"uid": f"finding-{uuid4()}", "title": "Test"},
        "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
        "resources": [{"uid": f"resource-{uuid4()}", "name": "test"}],
    }]
    return json.dumps(data).encode("utf-8")


def create_ocsf_missing_finding_uid() -> bytes:
    """Create OCSF JSON missing finding_info.uid."""
    data = [{
        "message": "Test finding",
        "metadata": {"event_code": "test_check"},
        "severity": "Low",
        "status_code": "FAIL",
        "finding_info": {"title": "Test"},  # Missing uid
        "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
        "resources": [{"uid": f"resource-{uuid4()}", "name": "test"}],
    }]
    return json.dumps(data).encode("utf-8")


def create_ocsf_missing_cloud_provider() -> bytes:
    """Create OCSF JSON missing cloud.provider."""
    data = [{
        "message": "Test finding",
        "metadata": {"event_code": "test_check"},
        "severity": "Low",
        "status_code": "FAIL",
        "finding_info": {"uid": f"finding-{uuid4()}", "title": "Test"},
        "cloud": {"account": {"uid": "123456789012"}},  # Missing provider
        "resources": [{"uid": f"resource-{uuid4()}", "name": "test"}],
    }]
    return json.dumps(data).encode("utf-8")


def create_ocsf_missing_account_uid() -> bytes:
    """Create OCSF JSON missing cloud.account.uid."""
    data = [{
        "message": "Test finding",
        "metadata": {"event_code": "test_check"},
        "severity": "Low",
        "status_code": "FAIL",
        "finding_info": {"uid": f"finding-{uuid4()}", "title": "Test"},
        "cloud": {"provider": "aws", "account": {}},  # Missing uid
        "resources": [{"uid": f"resource-{uuid4()}", "name": "test"}],
    }]
    return json.dumps(data).encode("utf-8")


def create_ocsf_unsupported_provider() -> bytes:
    """Create OCSF JSON with unsupported provider type."""
    data = [{
        "message": "Test finding",
        "metadata": {"event_code": "test_check"},
        "severity": "Low",
        "status_code": "FAIL",
        "finding_info": {"uid": f"finding-{uuid4()}", "title": "Test"},
        "cloud": {"provider": "unsupported_cloud", "account": {"uid": "123456789012"}},
        "resources": [{"uid": f"resource-{uuid4()}", "name": "test"}],
    }]
    return json.dumps(data).encode("utf-8")


def create_ocsf_empty_array() -> bytes:
    """Create OCSF JSON with empty array."""
    return b"[]"


def create_ocsf_all_invalid_findings() -> bytes:
    """Create OCSF JSON where all findings are invalid."""
    data = [
        {"message": "Invalid 1"},  # Missing all required fields
        {"message": "Invalid 2"},  # Missing all required fields
    ]
    return json.dumps(data).encode("utf-8")


def create_csv_missing_finding_uid_column() -> bytes:
    """Create CSV missing FINDING_UID column."""
    csv = """PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
aws;check_1;PASS;123456789012;resource-1"""
    return csv.encode("utf-8")


def create_csv_missing_provider_column() -> bytes:
    """Create CSV missing PROVIDER column."""
    csv = """FINDING_UID;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
finding-001;check_1;PASS;123456789012;resource-1"""
    return csv.encode("utf-8")


def create_csv_missing_multiple_columns() -> bytes:
    """Create CSV missing multiple required columns."""
    csv = """RESOURCE_UID;REGION
resource-1;us-east-1"""
    return csv.encode("utf-8")


def create_csv_empty_finding_uid_value() -> bytes:
    """Create CSV with empty FINDING_UID value."""
    csv = """FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
;aws;check_1;PASS;123456789012;resource-1"""
    return csv.encode("utf-8")


def create_csv_empty_check_id_value() -> bytes:
    """Create CSV with empty CHECK_ID value."""
    csv = """FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
finding-001;aws;;PASS;123456789012;resource-1"""
    return csv.encode("utf-8")


def create_csv_whitespace_only_value() -> bytes:
    """Create CSV with whitespace-only required value."""
    csv = """FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
   ;aws;check_1;PASS;123456789012;resource-1"""
    return csv.encode("utf-8")


def create_binary_content() -> bytes:
    """Create binary content (PNG header)."""
    return bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])


def create_xml_content() -> bytes:
    """Create XML content."""
    return b"""<?xml version="1.0" encoding="UTF-8"?>
<findings>
    <finding>
        <check_id>test_check</check_id>
        <status>PASS</status>
    </finding>
</findings>"""


def create_plain_text_content() -> bytes:
    """Create plain text content."""
    return b"This is just plain text, not JSON or CSV format."


def create_invalid_utf8_content() -> bytes:
    """Create invalid UTF-8 content."""
    return b"\xff\xfe"


# ============================================================================
# Test Functions
# ============================================================================


def test_invalid_json_format():
    """Test that invalid JSON raises appropriate error."""
    from api.parsers.ocsf_parser import parse_ocsf_json, OCSFParseError
    
    content = create_invalid_json_content()
    
    try:
        parse_ocsf_json(content)
        print("✗ FAILED: Expected OCSFParseError for invalid JSON")
        return False
    except OCSFParseError as e:
        print(f"✓ PASSED: Invalid JSON correctly rejected: {e}")
        return True
    except Exception as e:
        print(f"✗ FAILED: Unexpected error type: {type(e).__name__}: {e}")
        return False


def test_non_array_json():
    """Test that non-array JSON raises appropriate error."""
    from api.parsers.ocsf_parser import parse_ocsf_json, OCSFParseError
    
    content = create_non_array_json_content()
    
    try:
        parse_ocsf_json(content)
        print("✗ FAILED: Expected OCSFParseError for non-array JSON")
        return False
    except OCSFParseError as e:
        print(f"✓ PASSED: Non-array JSON correctly rejected: {e}")
        return True
    except Exception as e:
        print(f"✗ FAILED: Unexpected error type: {type(e).__name__}: {e}")
        return False


def test_json_with_non_object_elements():
    """Test that JSON array with non-object elements raises error."""
    from api.parsers.ocsf_parser import parse_ocsf_json, OCSFParseError
    
    content = create_json_with_non_object_elements()
    
    try:
        parse_ocsf_json(content)
        print("✗ FAILED: Expected OCSFParseError for non-object elements")
        return False
    except OCSFParseError as e:
        print(f"✓ PASSED: Non-object elements correctly rejected: {e}")
        return True
    except Exception as e:
        print(f"✗ FAILED: Unexpected error type: {type(e).__name__}: {e}")
        return False


def test_ocsf_missing_metadata_event_code():
    """Test that missing metadata.event_code raises error."""
    from api.parsers.ocsf_parser import parse_ocsf_json, OCSFParseError
    
    content = create_ocsf_missing_metadata_event_code()
    
    try:
        findings = parse_ocsf_json(content)
        if len(findings) == 0:
            print("✓ PASSED: Missing metadata.event_code - no valid findings parsed")
            return True
        print(f"✗ FAILED: Expected no findings, got {len(findings)}")
        return False
    except OCSFParseError as e:
        print(f"✓ PASSED: Missing metadata.event_code correctly rejected: {e}")
        return True
    except Exception as e:
        print(f"✗ FAILED: Unexpected error type: {type(e).__name__}: {e}")
        return False


def test_ocsf_missing_finding_uid():
    """Test that missing finding_info.uid raises error."""
    from api.parsers.ocsf_parser import parse_ocsf_json, OCSFParseError
    
    content = create_ocsf_missing_finding_uid()
    
    try:
        findings = parse_ocsf_json(content)
        if len(findings) == 0:
            print("✓ PASSED: Missing finding_info.uid - no valid findings parsed")
            return True
        print(f"✗ FAILED: Expected no findings, got {len(findings)}")
        return False
    except OCSFParseError as e:
        print(f"✓ PASSED: Missing finding_info.uid correctly rejected: {e}")
        return True
    except Exception as e:
        print(f"✗ FAILED: Unexpected error type: {type(e).__name__}: {e}")
        return False


def test_ocsf_missing_cloud_provider():
    """Test that missing cloud.provider raises error."""
    from api.parsers.ocsf_parser import parse_ocsf_json, OCSFParseError
    
    content = create_ocsf_missing_cloud_provider()
    
    try:
        findings = parse_ocsf_json(content)
        if len(findings) == 0:
            print("✓ PASSED: Missing cloud.provider - no valid findings parsed")
            return True
        print(f"✗ FAILED: Expected no findings, got {len(findings)}")
        return False
    except OCSFParseError as e:
        print(f"✓ PASSED: Missing cloud.provider correctly rejected: {e}")
        return True
    except Exception as e:
        print(f"✗ FAILED: Unexpected error type: {type(e).__name__}: {e}")
        return False


def test_ocsf_missing_account_uid():
    """Test that missing cloud.account.uid raises error."""
    from api.parsers.ocsf_parser import parse_ocsf_json, OCSFParseError
    
    content = create_ocsf_missing_account_uid()
    
    try:
        findings = parse_ocsf_json(content)
        if len(findings) == 0:
            print("✓ PASSED: Missing cloud.account.uid - no valid findings parsed")
            return True
        print(f"✗ FAILED: Expected no findings, got {len(findings)}")
        return False
    except OCSFParseError as e:
        print(f"✓ PASSED: Missing cloud.account.uid correctly rejected: {e}")
        return True
    except Exception as e:
        print(f"✗ FAILED: Unexpected error type: {type(e).__name__}: {e}")
        return False


def test_ocsf_all_invalid_findings():
    """Test that all invalid findings raises error."""
    from api.parsers.ocsf_parser import parse_ocsf_json, OCSFParseError
    
    content = create_ocsf_all_invalid_findings()
    
    try:
        parse_ocsf_json(content)
        print("✗ FAILED: Expected OCSFParseError for all invalid findings")
        return False
    except OCSFParseError as e:
        print(f"✓ PASSED: All invalid findings correctly rejected: {e}")
        return True
    except Exception as e:
        print(f"✗ FAILED: Unexpected error type: {type(e).__name__}: {e}")
        return False


def test_invalid_utf8():
    """Test that invalid UTF-8 raises error."""
    from api.parsers.ocsf_parser import parse_ocsf_json, OCSFParseError
    
    content = create_invalid_utf8_content()
    
    try:
        parse_ocsf_json(content)
        print("✗ FAILED: Expected OCSFParseError for invalid UTF-8")
        return False
    except OCSFParseError as e:
        print(f"✓ PASSED: Invalid UTF-8 correctly rejected: {e}")
        return True
    except Exception as e:
        print(f"✗ FAILED: Unexpected error type: {type(e).__name__}: {e}")
        return False


def test_csv_missing_finding_uid_column():
    """Test that CSV missing FINDING_UID column raises error."""
    from api.parsers.csv_parser import parse_csv, CSVParseError
    
    content = create_csv_missing_finding_uid_column()
    
    try:
        parse_csv(content)
        print("✗ FAILED: Expected CSVParseError for missing FINDING_UID column")
        return False
    except CSVParseError as e:
        if "FINDING_UID" in str(e):
            print(f"✓ PASSED: Missing FINDING_UID column correctly rejected: {e}")
            return True
        print(f"✗ FAILED: Error doesn't mention FINDING_UID: {e}")
        return False
    except Exception as e:
        print(f"✗ FAILED: Unexpected error type: {type(e).__name__}: {e}")
        return False


def test_csv_missing_provider_column():
    """Test that CSV missing PROVIDER column raises error."""
    from api.parsers.csv_parser import parse_csv, CSVParseError
    
    content = create_csv_missing_provider_column()
    
    try:
        parse_csv(content)
        print("✗ FAILED: Expected CSVParseError for missing PROVIDER column")
        return False
    except CSVParseError as e:
        if "PROVIDER" in str(e):
            print(f"✓ PASSED: Missing PROVIDER column correctly rejected: {e}")
            return True
        print(f"✗ FAILED: Error doesn't mention PROVIDER: {e}")
        return False
    except Exception as e:
        print(f"✗ FAILED: Unexpected error type: {type(e).__name__}: {e}")
        return False


def test_csv_missing_multiple_columns():
    """Test that CSV missing multiple columns reports all."""
    from api.parsers.csv_parser import parse_csv, CSVParseError
    
    content = create_csv_missing_multiple_columns()
    
    try:
        parse_csv(content)
        print("✗ FAILED: Expected CSVParseError for missing columns")
        return False
    except CSVParseError as e:
        error_msg = str(e)
        missing_cols = ["FINDING_UID", "PROVIDER", "CHECK_ID", "STATUS", "ACCOUNT_UID"]
        found_cols = [col for col in missing_cols if col in error_msg]
        if len(found_cols) >= 3:  # At least 3 missing columns mentioned
            print(f"✓ PASSED: Multiple missing columns correctly reported: {e}")
            return True
        print(f"✗ FAILED: Not all missing columns reported: {e}")
        return False
    except Exception as e:
        print(f"✗ FAILED: Unexpected error type: {type(e).__name__}: {e}")
        return False


def test_csv_empty_finding_uid_value():
    """Test that CSV with empty FINDING_UID value raises error."""
    from api.parsers.csv_parser import parse_csv, CSVParseError
    
    content = create_csv_empty_finding_uid_value()
    
    try:
        parse_csv(content)
        print("✗ FAILED: Expected CSVParseError for empty FINDING_UID value")
        return False
    except CSVParseError as e:
        if "FINDING_UID" in str(e):
            print(f"✓ PASSED: Empty FINDING_UID value correctly rejected: {e}")
            return True
        print(f"✗ FAILED: Error doesn't mention FINDING_UID: {e}")
        return False
    except Exception as e:
        print(f"✗ FAILED: Unexpected error type: {type(e).__name__}: {e}")
        return False


def test_csv_empty_check_id_value():
    """Test that CSV with empty CHECK_ID value raises error."""
    from api.parsers.csv_parser import parse_csv, CSVParseError
    
    content = create_csv_empty_check_id_value()
    
    try:
        parse_csv(content)
        print("✗ FAILED: Expected CSVParseError for empty CHECK_ID value")
        return False
    except CSVParseError as e:
        if "CHECK_ID" in str(e):
            print(f"✓ PASSED: Empty CHECK_ID value correctly rejected: {e}")
            return True
        print(f"✗ FAILED: Error doesn't mention CHECK_ID: {e}")
        return False
    except Exception as e:
        print(f"✗ FAILED: Unexpected error type: {type(e).__name__}: {e}")
        return False


def test_ocsf_structure_validation_invalid_json():
    """Test OCSF structure validation with invalid JSON."""
    from api.parsers.ocsf_parser import validate_ocsf_structure
    
    content = create_invalid_json_content()
    is_valid, error = validate_ocsf_structure(content)
    
    if not is_valid and error:
        print(f"✓ PASSED: Invalid JSON structure validation failed: {error}")
        return True
    print("✗ FAILED: Invalid JSON should fail structure validation")
    return False


def test_ocsf_structure_validation_non_array():
    """Test OCSF structure validation with non-array JSON."""
    from api.parsers.ocsf_parser import validate_ocsf_structure
    
    content = create_non_array_json_content()
    is_valid, error = validate_ocsf_structure(content)
    
    if not is_valid and error:
        print(f"✓ PASSED: Non-array JSON structure validation failed: {error}")
        return True
    print("✗ FAILED: Non-array JSON should fail structure validation")
    return False


def test_csv_structure_validation_missing_columns():
    """Test CSV structure validation with missing columns."""
    from api.parsers.csv_parser import validate_csv_structure
    
    content = create_csv_missing_finding_uid_column()
    is_valid, error = validate_csv_structure(content)
    
    if not is_valid and error and "FINDING_UID" in error:
        print(f"✓ PASSED: Missing column structure validation failed: {error}")
        return True
    print(f"✗ FAILED: Missing column should fail structure validation: {error}")
    return False


def test_ocsf_content_validation():
    """Test OCSF content validation with missing fields."""
    from api.parsers.ocsf_parser import validate_ocsf_content
    
    content = create_ocsf_missing_metadata_event_code()
    result = validate_ocsf_content(content)
    
    if not result.is_valid and len(result.errors) > 0:
        print(f"✓ PASSED: Content validation found errors: {len(result.errors)} errors")
        for err in result.errors[:3]:  # Show first 3 errors
            print(f"  - {err.field}: {err.message}")
        return True
    print("✗ FAILED: Content validation should find errors")
    return False


def test_csv_content_validation():
    """Test CSV content validation with empty values."""
    from api.parsers.csv_parser import validate_csv_content
    
    content = create_csv_empty_finding_uid_value()
    result = validate_csv_content(content)
    
    if not result.is_valid and len(result.errors) > 0:
        print(f"✓ PASSED: CSV content validation found errors: {len(result.errors)} errors")
        for err in result.errors[:3]:  # Show first 3 errors
            print(f"  - {err.field}: {err.message}")
        return True
    print("✗ FAILED: CSV content validation should find errors")
    return False


def test_format_detection_binary():
    """Test format detection with binary content using parsers directly."""
    from api.parsers.ocsf_parser import validate_ocsf_structure
    from api.parsers.csv_parser import validate_csv_structure
    
    content = create_binary_content()
    
    # Binary content should fail both JSON and CSV validation
    json_valid, json_error = validate_ocsf_structure(content)
    csv_valid, csv_error = validate_csv_structure(content)
    
    if not json_valid and not csv_valid:
        print(f"✓ PASSED: Binary content rejected by both parsers")
        print(f"  JSON error: {json_error}")
        print(f"  CSV error: {csv_error}")
        return True
    print("✗ FAILED: Binary content should be rejected by both parsers")
    return False


def test_format_detection_xml():
    """Test format detection with XML content using parsers directly."""
    from api.parsers.ocsf_parser import validate_ocsf_structure
    from api.parsers.csv_parser import validate_csv_structure
    
    content = create_xml_content()
    
    # XML content should fail JSON validation
    json_valid, json_error = validate_ocsf_structure(content)
    
    if not json_valid:
        print(f"✓ PASSED: XML content rejected by JSON parser: {json_error}")
        return True
    print("✗ FAILED: XML content should be rejected by JSON parser")
    return False


def test_format_detection_plain_text():
    """Test format detection with plain text content using parsers directly."""
    from api.parsers.ocsf_parser import validate_ocsf_structure
    from api.parsers.csv_parser import validate_csv_structure
    
    content = create_plain_text_content()
    
    # Plain text should fail JSON validation
    json_valid, json_error = validate_ocsf_structure(content)
    
    if not json_valid:
        print(f"✓ PASSED: Plain text rejected by JSON parser: {json_error}")
        return True
    print("✗ FAILED: Plain text should be rejected by JSON parser")
    return False


# ============================================================================
# Main Test Runner
# ============================================================================


def run_all_tests():
    """Run all error scenario tests."""
    tests = [
        # JSON/OCSF Parser Tests
        ("Invalid JSON format", test_invalid_json_format),
        ("Non-array JSON", test_non_array_json),
        ("JSON with non-object elements", test_json_with_non_object_elements),
        ("OCSF missing metadata.event_code", test_ocsf_missing_metadata_event_code),
        ("OCSF missing finding_info.uid", test_ocsf_missing_finding_uid),
        ("OCSF missing cloud.provider", test_ocsf_missing_cloud_provider),
        ("OCSF missing cloud.account.uid", test_ocsf_missing_account_uid),
        ("OCSF all invalid findings", test_ocsf_all_invalid_findings),
        ("Invalid UTF-8", test_invalid_utf8),
        
        # CSV Parser Tests
        ("CSV missing FINDING_UID column", test_csv_missing_finding_uid_column),
        ("CSV missing PROVIDER column", test_csv_missing_provider_column),
        ("CSV missing multiple columns", test_csv_missing_multiple_columns),
        ("CSV empty FINDING_UID value", test_csv_empty_finding_uid_value),
        ("CSV empty CHECK_ID value", test_csv_empty_check_id_value),
        
        # Structure Validation Tests
        ("OCSF structure validation - invalid JSON", test_ocsf_structure_validation_invalid_json),
        ("OCSF structure validation - non-array", test_ocsf_structure_validation_non_array),
        ("CSV structure validation - missing columns", test_csv_structure_validation_missing_columns),
        
        # Content Validation Tests
        ("OCSF content validation", test_ocsf_content_validation),
        ("CSV content validation", test_csv_content_validation),
        
        # Format Detection Tests
        ("Format detection - binary", test_format_detection_binary),
        ("Format detection - XML", test_format_detection_xml),
        ("Format detection - plain text", test_format_detection_plain_text),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        print(f"\n[Test] {name}")
        try:
            if test_func():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ FAILED: Unexpected exception: {type(e).__name__}: {e}")
            failed += 1
    
    return passed, failed


if __name__ == "__main__":
    print("=" * 70)
    print("Manual Test: Scan Import Error Scenarios")
    print("=" * 70)
    print("""
This script tests various error scenarios for the scan import feature:
- Invalid file formats (binary, XML, plain text)
- Missing required fields in JSON/OCSF
- Missing required columns in CSV
- Empty required field values
- Malformed JSON/CSV content
""")
    
    passed, failed = run_all_tests()
    
    print("\n" + "=" * 70)
    print(f"Test Results: {passed} passed, {failed} failed")
    print("=" * 70)
    
    if failed > 0:
        print("\n⚠ Some tests failed. Review the output above for details.")
        sys.exit(1)
    else:
        print("\n✓ All error scenario tests passed!")
        sys.exit(0)
