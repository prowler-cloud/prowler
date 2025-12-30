# Prowler API Parsers Module

This module provides parsing functionality for importing external scan results into the Prowler platform. It supports various output formats from the Prowler CLI and other security scanning tools.

## Overview

The parsers module enables the "Scan Results Import" feature, allowing users to upload scan results from Prowler CLI executions and have them processed and stored in the Prowler platform database.

## Supported Formats

| Format | Status | Parser | Description |
|--------|--------|--------|-------------|
| JSON/OCSF | ✅ Implemented | `ocsf_parser` | Open Cybersecurity Schema Framework format (Prowler's default JSON output) |
| CSV | ✅ Implemented | `csv_parser` | Semicolon/comma-separated values format (Prowler's CSV output) |

## Installation

The parsers module is part of the Prowler API package. No additional installation is required.

```python
# OCSF Parser
from api.parsers import parse_ocsf_json, OCSFFinding

# CSV Parser
from api.parsers import parse_csv, CSVFinding
```

## Quick Start

### Parsing OCSF JSON Content

```python
from api.parsers import parse_ocsf_json, OCSFParseError

# Read Prowler CLI JSON output
with open("prowler_output.ocsf.json", "rb") as f:
    content = f.read()

try:
    findings = parse_ocsf_json(content)
    print(f"Parsed {len(findings)} findings")
    
    for finding in findings:
        print(f"- {finding.check_id}: {finding.status} ({finding.severity})")
except OCSFParseError as e:
    print(f"Failed to parse: {e}")
```

### Validating OCSF Content

```python
from api.parsers import validate_ocsf_content

result = validate_ocsf_content(content)

if result.is_valid:
    print("Content is valid OCSF format")
else:
    for error in result.errors:
        print(f"Error: {error.message} (field: {error.field})")
```

### Extracting Provider Information

```python
from api.parsers import parse_ocsf_json, extract_provider_info

findings = parse_ocsf_json(content)
provider_info = extract_provider_info(findings)

if provider_info:
    provider_type, account_uid = provider_info
    print(f"Provider: {provider_type}, Account: {account_uid}")
```

### Parsing CSV Content

```python
from api.parsers import parse_csv, CSVParseError

# Read Prowler CLI CSV output
with open("prowler_output.csv", "rb") as f:
    content = f.read()

try:
    findings = parse_csv(content)
    print(f"Parsed {len(findings)} findings")
    
    for finding in findings:
        print(f"- {finding.check_id}: {finding.status} ({finding.severity})")
except CSVParseError as e:
    print(f"Failed to parse: {e}")
```

### Validating CSV Content

```python
from api.parsers import validate_csv_content

result = validate_csv_content(content)

if result.is_valid:
    print("Content is valid CSV format")
else:
    for error in result.errors:
        print(f"Error: {error.message} (field: {error.field})")
```

### Extracting Provider Information from CSV

```python
from api.parsers import parse_csv, extract_provider_info_csv

findings = parse_csv(content)
provider_info = extract_provider_info_csv(findings)

if provider_info:
    provider_type, account_uid = provider_info
    print(f"Provider: {provider_type}, Account: {account_uid}")
```

## API Reference

### Data Classes

#### `OCSFFinding`

Represents a parsed security finding from OCSF JSON.

```python
@dataclass
class OCSFFinding:
    uid: str                           # Unique finding identifier
    check_id: str                      # Check/event code (e.g., "accessanalyzer_enabled")
    severity: str                      # Normalized severity (lowercase): critical, high, medium, low, informational
    status: str                        # Normalized status (uppercase): PASS, FAIL, MANUAL
    status_extended: str               # Detailed status message
    message: str                       # Finding message
    impact_extended: str               # Impact description
    check_metadata: OCSFCheckMetadata  # Check metadata (title, description, remediation)
    compliance: dict[str, list[str]]   # Compliance framework mappings
    resources: list[OCSFResource]      # Associated cloud resources
    provider_type: str                 # Cloud provider (aws, azure, gcp, etc.)
    account_uid: str                   # Cloud account identifier
    account_name: str                  # Cloud account display name
    timestamp: datetime | None         # Finding timestamp
    raw_result: dict[str, Any]         # Original OCSF data
```

**Class Methods:**

- `from_dict(data: dict, index: int = 0) -> OCSFFinding`: Parse from dictionary

#### `OCSFResource`

Represents a cloud resource associated with a finding.

```python
@dataclass
class OCSFResource:
    uid: str              # Resource unique identifier (e.g., ARN)
    name: str             # Resource display name
    region: str           # Cloud region
    service: str          # Cloud service (e.g., "s3", "ec2")
    type: str             # Resource type
    cloud_partition: str  # Cloud partition (e.g., "aws")
    labels: list[str]     # Resource labels/tags
    data: dict[str, Any]  # Additional resource data
```

**Class Methods:**

- `from_dict(data: dict, index: int = 0) -> OCSFResource`: Parse from dictionary

#### `OCSFCheckMetadata`

Metadata about the security check that generated the finding.

```python
@dataclass
class OCSFCheckMetadata:
    title: str                          # Check title
    description: str                    # Check description
    risk: str                           # Risk description
    remediation_description: str        # How to remediate
    remediation_references: list[str]   # Reference URLs
    categories: list[str]               # Check categories
    related_url: str                    # Related documentation URL
```

#### `OCSFValidationResult`

Result of OCSF content validation.

```python
@dataclass
class OCSFValidationResult:
    is_valid: bool                       # Overall validation status
    errors: list[OCSFValidationError]    # Validation errors (fatal)
    warnings: list[OCSFValidationError]  # Validation warnings (non-fatal)
```

**Methods:**

- `add_error(message, field_path, index=None, value=None)`: Add a validation error
- `add_warning(message, field_path, index=None, value=None)`: Add a validation warning

#### `OCSFValidationError`

Represents a single validation error or warning.

```python
@dataclass
class OCSFValidationError:
    message: str          # Error message
    field: str            # Field path (e.g., "cloud.account.uid")
    index: int | None     # Finding index (if applicable)
    value: Any            # Invalid value (if applicable)
```

**Methods:**

- `to_dict() -> dict[str, Any]`: Convert to dictionary for API responses

### CSV Data Classes

#### `CSVFinding`

Represents a parsed security finding from CSV.

```python
@dataclass
class CSVFinding:
    uid: str                           # Unique finding identifier (FINDING_UID)
    check_id: str                      # Check identifier (CHECK_ID)
    severity: str                      # Normalized severity (lowercase): critical, high, medium, low, informational
    status: str                        # Normalized status (uppercase): PASS, FAIL, MANUAL
    status_extended: str               # Detailed status message (STATUS_EXTENDED)
    muted: bool                        # Whether finding is muted
    check_metadata: CSVCheckMetadata   # Check metadata (title, description, remediation)
    compliance: dict[str, list[str]]   # Compliance framework mappings (pipe-separated format)
    resource: CSVResource              # Associated cloud resource
    provider_type: str                 # Cloud provider (aws, azure, gcp, etc.)
    account_uid: str                   # Cloud account identifier
    account_name: str                  # Cloud account display name
    account_email: str                 # Cloud account email
    account_organization_uid: str      # Organization identifier
    account_organization_name: str     # Organization name
    account_tags: str                  # Account tags
    auth_method: str                   # Authentication method used
    timestamp: datetime | None         # Finding timestamp
    raw_row: dict[str, str]            # Original CSV row data
```

**Class Methods:**

- `from_row(row: dict[str, str], row_num: int = 0) -> CSVFinding`: Parse from CSV row dictionary

#### `CSVResource`

Represents a cloud resource associated with a CSV finding.

```python
@dataclass
class CSVResource:
    uid: str        # Resource unique identifier (RESOURCE_UID)
    name: str       # Resource display name (RESOURCE_NAME)
    region: str     # Cloud region (REGION)
    service: str    # Cloud service (SERVICE_NAME)
    type: str       # Resource type (RESOURCE_TYPE)
    partition: str  # Cloud partition (PARTITION)
    tags: str       # Resource tags (RESOURCE_TAGS)
    details: str    # Additional details (RESOURCE_DETAILS)
```

**Class Methods:**

- `from_row(row: dict[str, str], row_num: int = 0) -> CSVResource`: Parse from CSV row dictionary

#### `CSVCheckMetadata`

Metadata about the security check from CSV.

```python
@dataclass
class CSVCheckMetadata:
    title: str                    # Check title (CHECK_TITLE)
    description: str              # Check description (DESCRIPTION)
    risk: str                     # Risk description (RISK)
    remediation_description: str  # Remediation text (REMEDIATION_RECOMMENDATION_TEXT)
    remediation_url: str          # Remediation URL (REMEDIATION_RECOMMENDATION_URL)
    remediation_cli: str          # CLI remediation (REMEDIATION_CODE_CLI)
    remediation_terraform: str    # Terraform remediation (REMEDIATION_CODE_TERRAFORM)
    remediation_nativeiac: str    # Native IaC remediation (REMEDIATION_CODE_NATIVEIAC)
    remediation_other: str        # Other remediation (REMEDIATION_CODE_OTHER)
    categories: list[str]         # Check categories (CATEGORIES)
    related_url: str              # Related URL (RELATED_URL)
    additional_urls: list[str]    # Additional URLs (ADDITIONAL_URLS)
    notes: str                    # Notes (NOTES)
```

#### `CSVValidationResult`

Result of CSV content validation.

```python
@dataclass
class CSVValidationResult:
    is_valid: bool                       # Overall validation status
    errors: list[CSVValidationError]     # Validation errors (fatal)
    warnings: list[CSVValidationError]   # Validation warnings (non-fatal)
```

**Methods:**

- `add_error(message, field_path, row=None, value=None)`: Add a validation error
- `add_warning(message, field_path, row=None, value=None)`: Add a validation warning

#### `CSVValidationError`

Represents a single CSV validation error or warning.

```python
@dataclass
class CSVValidationError:
    message: str          # Error message
    field: str            # Column name
    row: int | None       # Row number (if applicable)
    value: Any            # Invalid value (if applicable)
```

**Methods:**

- `to_dict() -> dict[str, Any]`: Convert to dictionary for API responses

### Exceptions

#### `OCSFParseError`

Raised when OCSF parsing fails.

```python
class OCSFParseError(Exception):
    message: str          # Error message
    index: int | None     # Finding index where error occurred
    field: str | None     # Field that caused the error
```

#### `CSVParseError`

Raised when CSV parsing fails.

```python
class CSVParseError(Exception):
    message: str          # Error message
    row: int | None       # Row number where error occurred
    column: str | None    # Column name that caused the error
```

### Functions

#### `parse_ocsf_json(content: bytes) -> list[OCSFFinding]`

Parse OCSF JSON content into a list of findings.

**Parameters:**
- `content`: Raw bytes containing OCSF JSON data (array of findings)

**Returns:**
- List of `OCSFFinding` objects

**Raises:**
- `OCSFParseError`: If content is not valid JSON or doesn't match OCSF format

**Example:**
```python
findings = parse_ocsf_json(b'[{"metadata": {"event_code": "check_1"}, ...}]')
```

#### `validate_ocsf_structure(content: bytes) -> tuple[bool, str | None]`

Lightweight validation for quick format detection.

**Parameters:**
- `content`: Raw bytes to validate

**Returns:**
- Tuple of `(is_valid, error_message)`. If valid, `error_message` is `None`.

**Example:**
```python
is_valid, error = validate_ocsf_structure(content)
if not is_valid:
    print(f"Invalid format: {error}")
```

#### `validate_ocsf_content(content: bytes, strict: bool = False, max_errors: int = 100) -> OCSFValidationResult`

Comprehensive validation of OCSF content.

**Parameters:**
- `content`: Raw bytes containing OCSF JSON data
- `strict`: If `True`, treat warnings as errors
- `max_errors`: Maximum errors to collect before stopping

**Returns:**
- `OCSFValidationResult` with validation status, errors, and warnings

**Example:**
```python
result = validate_ocsf_content(content, strict=True)
if not result.is_valid:
    for error in result.errors:
        print(f"{error.field}: {error.message}")
```

#### `validate_ocsf_finding(data: dict, index: int = 0, strict: bool = False) -> OCSFValidationResult`

Validate a single OCSF finding dictionary.

**Parameters:**
- `data`: Dictionary containing finding data
- `index`: Finding index for error reporting
- `strict`: If `True`, treat warnings as errors

**Returns:**
- `OCSFValidationResult` for the single finding

#### `extract_provider_info(findings: list[OCSFFinding]) -> tuple[str, str] | None`

Extract provider type and account UID from parsed findings.

**Parameters:**
- `findings`: List of parsed OCSF findings

**Returns:**
- Tuple of `(provider_type, account_uid)` or `None` if no findings

### CSV Functions

#### `parse_csv(content: bytes) -> list[CSVFinding]`

Parse CSV content into a list of findings. Automatically detects semicolon or comma delimiter.

**Parameters:**
- `content`: Raw bytes containing CSV data

**Returns:**
- List of `CSVFinding` objects

**Raises:**
- `CSVParseError`: If content is not valid CSV or doesn't match expected Prowler format

**Example:**
```python
csv_data = b"FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID\nfinding-1;aws;check_1;PASS;123456789012"
findings = parse_csv(csv_data)
```

#### `validate_csv_structure(content: bytes) -> tuple[bool, str | None]`

Lightweight validation for quick format detection.

**Parameters:**
- `content`: Raw bytes to validate

**Returns:**
- Tuple of `(is_valid, error_message)`. If valid, `error_message` is `None`.

**Example:**
```python
is_valid, error = validate_csv_structure(content)
if not is_valid:
    print(f"Invalid format: {error}")
```

#### `validate_csv_content(content: bytes, strict: bool = False, max_errors: int = 100) -> CSVValidationResult`

Comprehensive validation of CSV content.

**Parameters:**
- `content`: Raw bytes containing CSV data
- `strict`: If `True`, treat warnings as errors
- `max_errors`: Maximum errors to collect before stopping

**Returns:**
- `CSVValidationResult` with validation status, errors, and warnings

**Example:**
```python
result = validate_csv_content(content, strict=True)
if not result.is_valid:
    for error in result.errors:
        print(f"Row {error.row}: {error.field} - {error.message}")
```

#### `extract_provider_info_csv(findings: list[CSVFinding]) -> tuple[str, str] | None`

Extract provider type and account UID from parsed CSV findings.

**Parameters:**
- `findings`: List of parsed CSV findings

**Returns:**
- Tuple of `(provider_type, account_uid)` or `None` if no findings

### Helper Functions

#### `get_supported_provider_types() -> list[str]`

Get sorted list of supported cloud provider types.

**Returns:**
- `["alibabacloud", "aws", "azure", "gcp", "github", "kubernetes", "m365", "mongodbatlas", "nhn", "oraclecloud"]`

#### `get_valid_severity_levels() -> list[str]`

Get sorted list of valid severity levels.

**Returns:**
- `["critical", "high", "informational", "low", "medium"]`

#### `get_valid_status_codes() -> list[str]`

Get sorted list of valid status codes.

**Returns:**
- `["FAIL", "MANUAL", "PASS"]`

### CSV Helper Functions

#### `get_required_csv_columns() -> list[str]`

Get sorted list of required CSV columns.

**Returns:**
- `["ACCOUNT_UID", "CHECK_ID", "FINDING_UID", "PROVIDER", "STATUS"]`

#### `get_expected_csv_columns() -> list[str]`

Get sorted list of all expected CSV columns.

**Returns:**
- Complete list of 42 expected Prowler CSV columns

### Constants

| Constant | Type | Description |
|----------|------|-------------|
| `SUPPORTED_PROVIDER_TYPES` | `frozenset[str]` | Valid cloud provider types |
| `VALID_SEVERITY_LEVELS` | `frozenset[str]` | Valid severity levels (lowercase) |
| `VALID_STATUS_CODES` | `frozenset[str]` | Valid status codes (uppercase) |
| `REQUIRED_OCSF_TOP_LEVEL_FIELDS` | `frozenset[str]` | Required top-level OCSF fields |
| `REQUIRED_OCSF_NESTED_FIELDS` | `dict[str, str]` | Required nested fields with descriptions |
| `REQUIRED_CSV_COLUMNS` | `frozenset[str]` | Required CSV columns |
| `EXPECTED_CSV_COLUMNS` | `frozenset[str]` | All expected CSV columns |

## OCSF Format Reference

### Required Fields

Every OCSF finding must contain:

```json
{
  "metadata": {
    "event_code": "check_id"        // Required: Check identifier
  },
  "finding_info": {
    "uid": "finding-uuid"           // Required: Unique finding ID
  },
  "cloud": {
    "provider": "aws",              // Required: Provider type
    "account": {
      "uid": "123456789012"         // Required: Account identifier
    }
  }
}
```

### Complete Example

```json
{
  "message": "IAM Access Analyzer is not enabled.",
  "metadata": {
    "event_code": "accessanalyzer_enabled",
    "product": {"name": "Prowler", "version": "5.0.0"}
  },
  "severity": "Low",
  "status_code": "FAIL",
  "status_detail": "IAM Access Analyzer is not enabled in us-east-1.",
  "finding_info": {
    "uid": "prowler-aws-accessanalyzer_enabled-123456789012-us-east-1",
    "title": "Check if IAM Access Analyzer is enabled",
    "desc": "Ensure IAM Access Analyzer is enabled for all regions."
  },
  "cloud": {
    "provider": "aws",
    "account": {"uid": "123456789012", "name": "Production"},
    "region": "us-east-1"
  },
  "resources": [
    {
      "uid": "arn:aws:accessanalyzer:us-east-1:123456789012:analyzer",
      "name": "analyzer",
      "region": "us-east-1",
      "group": {"name": "accessanalyzer"},
      "type": "Other"
    }
  ],
  "remediation": {
    "desc": "Enable IAM Access Analyzer in all regions.",
    "references": ["https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer.html"]
  },
  "risk_details": "Without Access Analyzer, you may miss unintended resource access.",
  "unmapped": {
    "compliance": {"CIS-1.4": ["1.20"], "CIS-1.5": ["1.20"]},
    "categories": ["security", "iam"],
    "related_url": "https://docs.aws.amazon.com/"
  },
  "time": 1739539623,
  "time_dt": "2025-02-14T14:27:03.913874"
}
```

## CSV Format Reference

### Delimiter Detection

The CSV parser automatically detects the delimiter by analyzing the first line:
- **Semicolon (`;`)**: Prowler's default CSV delimiter
- **Comma (`,`)**: Standard CSV delimiter

When delimiter counts are equal, semicolon is preferred (Prowler default).

### Required Columns

Every CSV file must contain these columns:

| Column | Description |
|--------|-------------|
| `FINDING_UID` | Unique finding identifier |
| `PROVIDER` | Cloud provider type (aws, azure, gcp, etc.) |
| `CHECK_ID` | Check identifier |
| `STATUS` | Finding status (PASS, FAIL, MANUAL) |
| `ACCOUNT_UID` | Cloud account identifier |

### Compliance Column Format

The `COMPLIANCE` column uses a pipe-separated format for multiple frameworks:

```
FRAMEWORK1: control1, control2 | FRAMEWORK2: control3, control4
```

**Example:**
```
CIS-1.4: 1.20, 1.21 | CIS-1.5: 1.20 | NIST: AC-1, AC-2
```

### Complete CSV Example

```csv
FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;SEVERITY;STATUS_EXTENDED;RESOURCE_UID;RESOURCE_NAME;REGION;SERVICE_NAME;RESOURCE_TYPE;COMPLIANCE
finding-001;aws;accessanalyzer_enabled;FAIL;123456789012;low;IAM Access Analyzer is not enabled;arn:aws:accessanalyzer:us-east-1:123456789012:analyzer;analyzer;us-east-1;accessanalyzer;Other;CIS-1.4: 1.20 | CIS-1.5: 1.20
finding-002;aws;s3_bucket_public_access;PASS;123456789012;high;S3 bucket has public access blocked;arn:aws:s3:::my-bucket;my-bucket;us-east-1;s3;bucket;CIS-1.4: 2.1.1
```

### All Expected Columns

The parser recognizes these 42 columns (all optional except required columns):

| Category | Columns |
|----------|---------|
| **Identity** | `FINDING_UID`, `PROVIDER`, `CHECK_ID`, `CHECK_TITLE`, `CHECK_TYPE` |
| **Status** | `STATUS`, `STATUS_EXTENDED`, `MUTED`, `SEVERITY` |
| **Account** | `ACCOUNT_UID`, `ACCOUNT_NAME`, `ACCOUNT_EMAIL`, `ACCOUNT_ORGANIZATION_UID`, `ACCOUNT_ORGANIZATION_NAME`, `ACCOUNT_TAGS` |
| **Resource** | `RESOURCE_UID`, `RESOURCE_NAME`, `RESOURCE_TYPE`, `RESOURCE_DETAILS`, `RESOURCE_TAGS` |
| **Location** | `REGION`, `PARTITION`, `SERVICE_NAME`, `SUBSERVICE_NAME` |
| **Metadata** | `DESCRIPTION`, `RISK`, `RELATED_URL`, `CATEGORIES`, `DEPENDS_ON`, `RELATED_TO`, `NOTES` |
| **Remediation** | `REMEDIATION_RECOMMENDATION_TEXT`, `REMEDIATION_RECOMMENDATION_URL`, `REMEDIATION_CODE_CLI`, `REMEDIATION_CODE_TERRAFORM`, `REMEDIATION_CODE_NATIVEIAC`, `REMEDIATION_CODE_OTHER` |
| **Other** | `AUTH_METHOD`, `TIMESTAMP`, `COMPLIANCE`, `PROWLER_VERSION`, `ADDITIONAL_URLS` |

## Error Handling

### OCSF Parse Errors

```python
from api.parsers import parse_ocsf_json, OCSFParseError

try:
    findings = parse_ocsf_json(content)
except OCSFParseError as e:
    # e.message - Error description
    # e.index - Finding index (if applicable)
    # e.field - Field path (if applicable)
    logger.error(f"Parse error: {e}")
```

### CSV Parse Errors

```python
from api.parsers import parse_csv, CSVParseError

try:
    findings = parse_csv(content)
except CSVParseError as e:
    # e.message - Error description
    # e.row - Row number (if applicable)
    # e.column - Column name (if applicable)
    logger.error(f"Parse error: {e}")
```

### OCSF Validation Errors

```python
from api.parsers import validate_ocsf_content

result = validate_ocsf_content(content)

for error in result.errors:
    logger.error(f"[{error.index}] {error.field}: {error.message}")

for warning in result.warnings:
    logger.warning(f"[{warning.index}] {warning.field}: {warning.message}")
```

### CSV Validation Errors

```python
from api.parsers import validate_csv_content

result = validate_csv_content(content)

for error in result.errors:
    logger.error(f"Row {error.row}: {error.field} - {error.message}")

for warning in result.warnings:
    logger.warning(f"Row {warning.row}: {warning.field} - {warning.message}")
```

## Testing

Run the parser tests:

```bash
cd api/src/backend

# Run OCSF parser tests
poetry run pytest api/tests/test_ocsf_parser.py -v

# Run CSV parser tests
poetry run pytest api/tests/test_csv_parser.py -v

# Run all parser tests
poetry run pytest api/tests/test_ocsf_parser.py api/tests/test_csv_parser.py -v
```

## Related Documentation

- [Scan Results Import Feature Spec](/.kiro/specs/scan-results-import/)
- [API Models Documentation](/api/docs/models.md)
- [OCSF Specification](https://schema.ocsf.io/)

## Changelog

### v1.1.0 (CSV Parser)

- Added CSV parser with semicolon/comma delimiter auto-detection
- Support for Prowler CLI CSV output format (42 columns)
- Pipe-separated compliance column parsing
- Comprehensive validation with row-level error reporting
- Helper functions for column introspection

### v1.0.0 (Initial Release)

- Added OCSF parser with full validation support
- Support for all Prowler-supported cloud providers
- Comprehensive error handling and reporting
- Validation functions for format detection and content verification
