"""
Parsers module for importing scan results from various formats.

This package provides parsing functionality for Prowler CLI output files,
enabling the import of external scan results into the Prowler platform.

Supported Formats
-----------------
- **JSON/OCSF**: Open Cybersecurity Schema Framework format (Prowler's default JSON output)
- **CSV**: Semicolon-separated values format (Prowler's CSV output)

Quick Start
-----------
Parse OCSF JSON content::

    from api.parsers import parse_ocsf_json, OCSFParseError

    try:
        findings = parse_ocsf_json(json_content)
        for finding in findings:
            print(f"{finding.check_id}: {finding.status}")
    except OCSFParseError as e:
        print(f"Parse error: {e}")

Parse CSV content::

    from api.parsers import parse_csv, CSVParseError

    try:
        findings = parse_csv(csv_content)
        for finding in findings:
            print(f"{finding.check_id}: {finding.status}")
    except CSVParseError as e:
        print(f"Parse error: {e}")

Validate content before parsing::

    from api.parsers import validate_ocsf_content, validate_csv_content

    result = validate_ocsf_content(content)
    if result.is_valid:
        findings = parse_ocsf_json(content)

    result = validate_csv_content(content)
    if result.is_valid:
        findings = parse_csv(content)

Extract provider information::

    from api.parsers import extract_provider_info

    provider_info = extract_provider_info(findings)
    if provider_info:
        provider_type, account_uid = provider_info

Exports
-------
OCSF Data Classes:
    OCSFFinding : Parsed security finding from OCSF JSON
    OCSFResource : Cloud resource associated with a finding
    OCSFCheckMetadata : Metadata about the security check
    OCSFValidationResult : Result of OCSF validation
    OCSFValidationError : Single validation error or warning

CSV Data Classes:
    CSVFinding : Parsed security finding from CSV
    CSVResource : Cloud resource associated with a finding
    CSVCheckMetadata : Metadata about the security check
    CSVValidationResult : Result of CSV validation
    CSVValidationError : Single validation error or warning

Exceptions:
    OCSFParseError : Raised when OCSF parsing fails
    CSVParseError : Raised when CSV parsing fails

OCSF Functions:
    parse_ocsf_json : Parse OCSF JSON content into findings
    validate_ocsf_structure : Lightweight format validation
    validate_ocsf_content : Comprehensive content validation
    validate_ocsf_finding : Validate a single finding
    extract_provider_info : Extract provider type and account UID (OCSF)

CSV Functions:
    parse_csv : Parse CSV content into findings
    validate_csv_structure : Lightweight format validation
    validate_csv_content : Comprehensive content validation
    extract_provider_info_csv : Extract provider type and account UID (CSV)

Helper Functions:
    get_supported_provider_types : Get list of supported providers
    get_valid_severity_levels : Get list of valid severities
    get_valid_status_codes : Get list of valid status codes
    get_required_csv_columns : Get list of required CSV columns
    get_expected_csv_columns : Get list of all expected CSV columns

Constants:
    SUPPORTED_PROVIDER_TYPES : Valid cloud provider types (frozenset)
    VALID_SEVERITY_LEVELS : Valid severity levels (frozenset)
    VALID_STATUS_CODES : Valid status codes (frozenset)
    REQUIRED_OCSF_TOP_LEVEL_FIELDS : Required top-level fields (frozenset)
    REQUIRED_OCSF_NESTED_FIELDS : Required nested fields (dict)
    REQUIRED_CSV_COLUMNS : Required CSV columns (frozenset)
    EXPECTED_CSV_COLUMNS : All expected CSV columns (frozenset)

See Also
--------
- README.md in this directory for full API documentation
- api/docs/models.md for database model documentation
- .kiro/specs/scan-results-import/ for feature specification

Note
----
Uses relative imports (e.g., `from .ocsf_parser`) to ensure proper
package resolution regardless of how the module is imported.
"""

# OCSF Parser - Handles JSON/OCSF format from Prowler CLI
# Uses relative import for package-internal module resolution
from .ocsf_parser import (
    # Data Classes
    OCSFCheckMetadata,
    OCSFFinding,
    OCSFResource,
    OCSFValidationError,
    OCSFValidationResult,
    # Exception
    OCSFParseError,
    # Constants
    REQUIRED_OCSF_NESTED_FIELDS,
    REQUIRED_OCSF_TOP_LEVEL_FIELDS,
    SUPPORTED_PROVIDER_TYPES,
    VALID_SEVERITY_LEVELS,
    VALID_STATUS_CODES,
    # Core Functions
    extract_provider_info,
    parse_ocsf_json,
    validate_ocsf_content,
    validate_ocsf_finding,
    validate_ocsf_structure,
    # Helper Functions
    get_supported_provider_types,
    get_valid_severity_levels,
    get_valid_status_codes,
)

# CSV Parser - Handles CSV format from Prowler CLI
from .csv_parser import (
    # Data Classes
    CSVCheckMetadata,
    CSVFinding,
    CSVResource,
    CSVValidationError,
    CSVValidationResult,
    # Exception
    CSVParseError,
    # Constants
    EXPECTED_CSV_COLUMNS,
    REQUIRED_CSV_COLUMNS,
    # Core Functions
    parse_csv,
    validate_csv_content,
    validate_csv_structure,
)
from .csv_parser import extract_provider_info as extract_provider_info_csv
from .csv_parser import get_expected_csv_columns, get_required_csv_columns

# Public API - All symbols exported for external use
__all__ = [
    # OCSF Data Classes
    "OCSFCheckMetadata",
    "OCSFFinding",
    "OCSFResource",
    "OCSFValidationError",
    "OCSFValidationResult",
    # CSV Data Classes
    "CSVCheckMetadata",
    "CSVFinding",
    "CSVResource",
    "CSVValidationError",
    "CSVValidationResult",
    # Exceptions
    "OCSFParseError",
    "CSVParseError",
    # OCSF Constants
    "REQUIRED_OCSF_NESTED_FIELDS",
    "REQUIRED_OCSF_TOP_LEVEL_FIELDS",
    "SUPPORTED_PROVIDER_TYPES",
    "VALID_SEVERITY_LEVELS",
    "VALID_STATUS_CODES",
    # CSV Constants
    "REQUIRED_CSV_COLUMNS",
    "EXPECTED_CSV_COLUMNS",
    # OCSF Core Functions
    "extract_provider_info",
    "parse_ocsf_json",
    "validate_ocsf_content",
    "validate_ocsf_finding",
    "validate_ocsf_structure",
    # CSV Core Functions
    "extract_provider_info_csv",
    "parse_csv",
    "validate_csv_content",
    "validate_csv_structure",
    # Helper Functions
    "get_supported_provider_types",
    "get_valid_severity_levels",
    "get_valid_status_codes",
    "get_required_csv_columns",
    "get_expected_csv_columns",
]
