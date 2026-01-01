# Manual Tests for Scan Import Feature

This directory contains manual test scripts for validating the scan import functionality.
These tests are designed to be run independently of the automated test suite and provide
comprehensive validation of the OCSF and CSV parsers.

## Overview

The manual tests complement the automated unit tests by providing:

- Real-world data validation using actual Prowler CLI output formats
- Error scenario testing with various malformed inputs
- Large file performance testing
- Interactive debugging capabilities

## Test Scripts

### test_scan_import_error_scenarios.py

Comprehensive error scenario testing for the scan import parsers.

**Purpose**: Validates that the OCSF and CSV parsers correctly reject invalid inputs.

**Test Categories**:

- JSON/OCSF Parser Errors (invalid syntax, missing fields, unsupported providers)
- CSV Parser Errors (missing columns, empty values)
- Format Detection Errors (binary, XML, plain text rejection)

**Usage**:

```bash
# From repository root
python api/tests/manual/test_scan_import_error_scenarios.py

# Or with poetry
poetry run python api/tests/manual/test_scan_import_error_scenarios.py
```

**Exit Codes**:

- `0`: All tests passed
- `1`: One or more tests failed

#### Test Data Generator Functions

These functions create various invalid inputs for testing error handling:

| Function | Return Type | Description |
|----------|-------------|-------------|
| `create_invalid_json_content()` | `bytes` | Malformed JSON with syntax errors |
| `create_non_array_json_content()` | `bytes` | Valid JSON object (not array) |
| `create_json_with_non_object_elements()` | `bytes` | JSON array with primitive values |
| `create_ocsf_missing_metadata_event_code()` | `bytes` | OCSF JSON missing `metadata.event_code` |
| `create_ocsf_missing_finding_uid()` | `bytes` | OCSF JSON missing `finding_info.uid` |
| `create_ocsf_missing_cloud_provider()` | `bytes` | OCSF JSON missing `cloud.provider` |
| `create_ocsf_missing_account_uid()` | `bytes` | OCSF JSON missing `cloud.account.uid` |
| `create_ocsf_unsupported_provider()` | `bytes` | OCSF JSON with invalid provider type |
| `create_ocsf_empty_array()` | `bytes` | Empty JSON array `[]` |
| `create_ocsf_all_invalid_findings()` | `bytes` | OCSF JSON where all findings are invalid |
| `create_csv_missing_finding_uid_column()` | `bytes` | CSV without FINDING_UID column |
| `create_csv_missing_provider_column()` | `bytes` | CSV without PROVIDER column |
| `create_csv_missing_multiple_columns()` | `bytes` | CSV missing multiple required columns |
| `create_csv_empty_finding_uid_value()` | `bytes` | CSV with empty FINDING_UID value |
| `create_csv_empty_check_id_value()` | `bytes` | CSV with empty CHECK_ID value |
| `create_csv_whitespace_only_value()` | `bytes` | CSV with whitespace-only required value |
| `create_binary_content()` | `bytes` | PNG file header (binary content) |
| `create_xml_content()` | `bytes` | Valid XML document |
| `create_plain_text_content()` | `bytes` | Plain text string |
| `create_invalid_utf8_content()` | `bytes` | Invalid UTF-8 byte sequence |

#### Test Functions

Each test function returns `bool` (True=pass, False=fail):

**JSON/OCSF Parser Tests**:

| Function | Description |
|----------|-------------|
| `test_invalid_json_format()` | Validates rejection of unparseable JSON |
| `test_non_array_json()` | Validates rejection of non-array JSON root |
| `test_json_with_non_object_elements()` | Validates array element types |
| `test_ocsf_missing_metadata_event_code()` | Required field validation |
| `test_ocsf_missing_finding_uid()` | Required field validation |
| `test_ocsf_missing_cloud_provider()` | Required field validation |
| `test_ocsf_missing_account_uid()` | Required field validation |
| `test_ocsf_all_invalid_findings()` | Bulk validation failure |
| `test_invalid_utf8()` | Encoding validation |

**CSV Parser Tests**:

| Function | Description |
|----------|-------------|
| `test_csv_missing_finding_uid_column()` | Required column validation |
| `test_csv_missing_provider_column()` | Required column validation |
| `test_csv_missing_multiple_columns()` | Multiple missing columns |
| `test_csv_empty_finding_uid_value()` | Empty value validation |
| `test_csv_empty_check_id_value()` | Empty value validation |

**Structure Validation Tests**:

| Function | Description |
|----------|-------------|
| `test_ocsf_structure_validation_invalid_json()` | Lightweight JSON validation |
| `test_ocsf_structure_validation_non_array()` | Structure checks |
| `test_csv_structure_validation_missing_columns()` | Column validation |

**Content Validation Tests**:

| Function | Description |
|----------|-------------|
| `test_ocsf_content_validation()` | Comprehensive OCSF validation |
| `test_csv_content_validation()` | Comprehensive CSV validation |

**Format Detection Tests**:

| Function | Description |
|----------|-------------|
| `test_format_detection_binary()` | Binary file rejection |
| `test_format_detection_xml()` | XML content rejection |
| `test_format_detection_plain_text()` | Plain text rejection |

#### Main Entry Point

```python
def run_all_tests() -> tuple[int, int]:
    """
    Run all error scenario tests and return results.

    Returns:
        tuple[int, int]: A tuple of (passed_count, failed_count).

    Example:
        >>> passed, failed = run_all_tests()
        >>> print(f"Results: {passed} passed, {failed} failed")
    """
```

#### Error Scenarios Example Output

```text
======================================================================
Manual Test: Scan Import Error Scenarios
======================================================================

[Test] Invalid JSON format
✓ PASSED: Invalid JSON correctly rejected: Invalid JSON: ...

[Test] Non-array JSON
✓ PASSED: Non-array JSON correctly rejected: ...

...

======================================================================
Test Results: 22 passed, 0 failed
======================================================================

✓ All error scenario tests passed!
```

### test_scan_import_real_json.py

Tests the OCSF parser with realistic Prowler JSON output.

**Purpose**: Validates parsing of real Prowler CLI JSON/OCSF format.

**Features**:

- Creates realistic test data matching actual Prowler output structure
- Tests compliance data extraction
- Tests resource parsing
- Generates test files for manual API testing

**Usage**:

```bash
python api/tests/manual/test_scan_import_real_json.py
```

#### OCSF Test Functions

| Function | Parameters | Return Type | Description |
|----------|------------|-------------|-------------|
| `create_real_ocsf_test_data()` | None | `list[dict]` | Creates realistic OCSF test data with 3 findings |
| `test_ocsf_parser_with_real_data()` | None | `list[OCSFFinding]` | Tests parser with generated realistic data |
| `test_ocsf_parser_with_single_finding()` | None | `list[OCSFFinding] \| None` | Tests parser with minimal single finding |
| `save_test_data_to_file()` | None | `Path` | Saves test data to `test_prowler_output.ocsf.json` |

#### OCSF Structure

The generated OCSF JSON follows the standard Prowler output format with these key fields:

```json
{
  "message": "Finding description",
  "metadata": {
    "event_code": "check_id",
    "product": { "name": "Prowler", "version": "5.0.0" }
  },
  "severity": "Low|Medium|High|Critical|Informational",
  "status_code": "PASS|FAIL|MANUAL",
  "finding_info": { "uid": "unique-finding-id", "title": "..." },
  "resources": [{ "uid": "resource-arn", "type": "...", "group": {"name": "service"} }],
  "cloud": {
    "provider": "aws|azure|gcp|kubernetes",
    "account": { "uid": "account-id" },
    "region": "region-name"
  },
  "unmapped": {
    "compliance": { "CIS-1.4": ["1.20"], "PCI-DSS-3.2.1": ["1.2.1"] }
  }
}
```

#### OCSF Example Usage

```python
from api.parsers.ocsf_parser import parse_ocsf_json, validate_ocsf_structure
import json

# Create test data
test_data = create_real_ocsf_test_data()
content = json.dumps(test_data).encode("utf-8")

# Validate and parse
is_valid, error = validate_ocsf_structure(content)
if is_valid:
    findings = parse_ocsf_json(content)
    for f in findings:
        print(f"{f.check_id}: {f.status} ({f.severity})")
```

### test_scan_import_real_csv.py

Tests the CSV parser with realistic Prowler CSV output.

**Purpose**: Validates parsing of real Prowler CLI CSV format (semicolon-delimited).

**Features**:

- Creates realistic test data with all 42 CSV columns
- Tests with example files from `examples/output/`
- Tests multi-provider support (AWS, Azure, GCP)
- Generates test files for manual API testing

**Usage**:

```bash
python api/tests/manual/test_scan_import_real_csv.py
```

#### CSV Test Functions

| Function | Parameters | Return Type | Description |
|----------|------------|-------------|-------------|
| `create_real_csv_test_data()` | `account_uid: str = "123456789012"`, `account_name: str = "Test AWS Account"` | `str` | Creates realistic CSV test data with 3 findings |
| `test_csv_parser_with_real_data()` | None | `list[CSVFinding]` | Tests parser with generated realistic data |
| `test_csv_parser_with_example_file()` | None | `list[CSVFinding] \| None` | Tests parser with `examples/output/example_output_aws.csv` |
| `test_csv_parser_with_azure_example()` | None | `list[CSVFinding] \| None` | Tests parser with Azure example output |
| `test_csv_parser_with_gcp_example()` | None | `list[CSVFinding] \| None` | Tests parser with GCP example output |
| `save_test_data_to_file()` | None | `Path` | Saves test data to `test_prowler_output.csv` |

#### CSV Column Structure (42 columns)

The generated CSV follows the exact Prowler output format:

```text
AUTH_METHOD, TIMESTAMP, ACCOUNT_UID, ACCOUNT_NAME, ACCOUNT_EMAIL,
ACCOUNT_ORGANIZATION_UID, ACCOUNT_ORGANIZATION_NAME, ACCOUNT_TAGS,
FINDING_UID, PROVIDER, CHECK_ID, CHECK_TITLE, CHECK_TYPE, STATUS,
STATUS_EXTENDED, MUTED, SERVICE_NAME, SUBSERVICE_NAME, SEVERITY,
RESOURCE_TYPE, RESOURCE_UID, RESOURCE_NAME, RESOURCE_DETAILS, RESOURCE_TAGS,
PARTITION, REGION, DESCRIPTION, RISK, RELATED_URL, REMEDIATION_RECOMMENDATION_TEXT,
REMEDIATION_RECOMMENDATION_URL, REMEDIATION_CODE_NATIVEIAC, REMEDIATION_CODE_TERRAFORM,
REMEDIATION_CODE_CLI, REMEDIATION_CODE_OTHER, COMPLIANCE, CATEGORIES, DEPENDS_ON,
RELATED_TO, NOTES, PROWLER_VERSION, ADDITIONAL_URLS
```

#### CSV Example Usage

```python
from api.parsers.csv_parser import parse_csv, validate_csv_structure

# Create test data
test_data = create_real_csv_test_data(
    account_uid="123456789012",
    account_name="My AWS Account"
)
content = test_data.encode("utf-8")

# Validate and parse
is_valid, error = validate_csv_structure(content)
if is_valid:
    findings = parse_csv(content)
    print(f"Parsed {len(findings)} findings")
```

### test_scan_import_large_file.py

Performance testing with large scan result files.

**Purpose**: Validates parser performance with files containing 1000+ findings.

**Features**:

- Tests memory efficiency
- Measures parsing time
- Validates bulk import handling

**Usage**:

```bash
python api/tests/manual/test_scan_import_large_file.py

# With custom finding count
python api/tests/manual/test_scan_import_large_file.py --count 5000

# Save test files for manual API testing
python api/tests/manual/test_scan_import_large_file.py --save-files

# Test only OCSF or CSV format
python api/tests/manual/test_scan_import_large_file.py --ocsf-only
python api/tests/manual/test_scan_import_large_file.py --csv-only
```

#### Command Line Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| `--count` | `-c` | 1500 | Number of findings to generate |
| `--save-files` | `-s` | False | Save generated test files |
| `--ocsf-only` | - | False | Only test OCSF/JSON format |
| `--csv-only` | - | False | Only test CSV format |

#### Large File Test Functions

| Function | Parameters | Return Type | Description |
|----------|------------|-------------|-------------|
| `generate_ocsf_finding()` | `index: int`, `account_uid: str`, `account_name: str` | `dict` | Generate single OCSF finding |
| `generate_large_ocsf_data()` | `count: int` | `list[dict]` | Generate list of OCSF findings |
| `generate_csv_row()` | `index: int`, `account_uid: str`, `account_name: str` | `str` | Generate single CSV row |
| `generate_large_csv_data()` | `count: int` | `str` | Generate CSV content |
| `measure_memory()` | None | `float` | Get current memory usage in MB |
| `test_ocsf_parser_large_file()` | `count: int` | `dict` | Test OCSF parser performance |
| `test_csv_parser_large_file()` | `count: int` | `dict` | Test CSV parser performance |
| `save_large_test_files()` | `count: int` | `tuple[Path, Path]` | Save test files to disk |
| `print_summary()` | `results: list[dict]` | `None` | Print test results summary |

#### Test Results Dictionary

Each test returns a dictionary with these metrics:

```python
{
    "format": "ocsf" | "csv",
    "count": int,                    # Number of findings
    "success": bool,                 # Test passed/failed
    "file_size_mb": float,           # Generated file size
    "generation_memory_mb": float,   # Memory for generation
    "validation_time_s": float,      # Structure validation time
    "parse_time_s": float,           # Parsing time
    "parse_memory_mb": float,        # Memory for parsing
    "findings_parsed": int,          # Actual findings parsed
    "unique_resources": int,         # Unique resource count
    "findings_with_compliance": int, # Findings with compliance data
    "findings_per_second": float,    # Performance metric
}
```

#### Large File Test Example Output

```text
============================================================
Testing OCSF Parser with 1500 findings
============================================================
Generating 1500 OCSF findings...
✓ Generated 1500 findings in 0.45s
File size: 8.23 MB
Memory used for generation: 12.50 MB

Validating OCSF structure...
✓ Validation passed in 0.02s

Parsing OCSF content...
✓ Parsed 1500 findings in 1.23s
Memory used for parsing: 45.00 MB

Performance: 1219 findings/second
```

## Test Data Files

### test_prowler_output.ocsf.json

Sample OCSF JSON output generated by `test_scan_import_real_json.py`.

**Contents**:

- 3 sample findings (AWS provider)
- Compliance mappings (CIS, PCI-DSS, SOC2)
- Resource metadata

### test_prowler_output.csv

Sample CSV output generated by `test_scan_import_real_csv.py`.

**Contents**:

- 3 sample findings (AWS provider)
- All 42 Prowler CSV columns
- Semicolon-delimited format

### test_prowler_output_large_1500.ocsf.json

Large OCSF JSON file for performance testing.

**Contents**:

- 1500 findings
- Various check types and severities

### test_prowler_output_large_1500.csv

Large CSV file for performance testing.

**Contents**:

- 1500 findings
- Full column set

## API Integration Testing

After running the test scripts, you can test the API endpoint manually:

### Prerequisites

1. Start the development environment:

   ```bash
   docker-compose -f docker-compose-dev.yml up -d
   ```

2. Obtain an authentication token (login via UI or API)

### Import JSON File

```bash
curl -X POST http://localhost:8080/api/v1/scans/import \
  -H "Authorization: Bearer <YOUR_TOKEN>" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@api/tests/manual/test_prowler_output.ocsf.json"
```

### Import CSV File

```bash
curl -X POST http://localhost:8080/api/v1/scans/import \
  -H "Authorization: Bearer <YOUR_TOKEN>" \
  -H "Content-Type: multipart/form-data" \
  -F "file=@api/tests/manual/test_prowler_output.csv"
```

### Import Inline JSON

```bash
curl -X POST http://localhost:8080/api/v1/scans/import \
  -H "Authorization: Bearer <YOUR_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"data": [<OCSF findings array>]}'
```

## Module Dependencies

The test scripts import from the following modules:

- `api.parsers.ocsf_parser`: OCSF JSON parser
  - `parse_ocsf_json(content: bytes) -> list[OCSFFinding]`
  - `validate_ocsf_structure(content: bytes) -> tuple[bool, str | None]`
  - `validate_ocsf_content(content: bytes) -> OCSFValidationResult`
  - `OCSFParseError`: Exception for parse failures

- `api.parsers.csv_parser`: CSV parser
  - `parse_csv(content: bytes) -> list[CSVFinding]`
  - `validate_csv_structure(content: bytes) -> tuple[bool, str | None]`
  - `validate_csv_content(content: bytes) -> CSVValidationResult`
  - `CSVParseError`: Exception for parse failures

## Adding New Tests

When adding new manual tests:

1. Follow the existing naming convention: `test_scan_import_*.py`
2. Include a module docstring with usage instructions
3. Add the script to this README
4. Use the standard path setup pattern:

   ```python
   PROJECT_ROOT = Path(__file__).parent.parent.parent
   API_BACKEND = PROJECT_ROOT / "src" / "backend"
   sys.path.insert(0, str(API_BACKEND))
   ```

## Related Documentation

- [Parsers README](../../src/backend/api/parsers/README.md): Parser API documentation
- [Services README](../../src/backend/api/services/README.md): Import service documentation
- [Scan Import User Guide](../../../docs/user-guide/tutorials/prowler-app-scan-import.mdx): End-user documentation
