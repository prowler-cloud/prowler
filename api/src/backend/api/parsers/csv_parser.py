"""
CSV Parser for Prowler scan results.

This module provides parsing functionality for Prowler CLI CSV output format.
It extracts findings, resources, and provider information from semicolon-delimited CSV.
"""

import csv
import io
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

# Supported provider types for validation (same as OCSF parser)
SUPPORTED_PROVIDER_TYPES = frozenset(
    {
        "aws",
        "azure",
        "gcp",
        "kubernetes",
        "github",
        "m365",
        "alibabacloud",
        "nhn",
        "oraclecloud",
        "mongodbatlas",
    }
)

# Valid severity levels (normalized to lowercase)
VALID_SEVERITY_LEVELS = frozenset(
    {
        "critical",
        "high",
        "medium",
        "low",
        "informational",
    }
)

# Valid status codes (normalized to uppercase)
VALID_STATUS_CODES = frozenset(
    {
        "PASS",
        "FAIL",
        "MANUAL",
    }
)

# Required CSV columns for validation
REQUIRED_CSV_COLUMNS = frozenset(
    {
        "FINDING_UID",
        "PROVIDER",
        "CHECK_ID",
        "STATUS",
        "ACCOUNT_UID",
    }
)

# All expected CSV columns (for reference and validation)
EXPECTED_CSV_COLUMNS = frozenset(
    {
        "AUTH_METHOD",
        "TIMESTAMP",
        "ACCOUNT_UID",
        "ACCOUNT_NAME",
        "ACCOUNT_EMAIL",
        "ACCOUNT_ORGANIZATION_UID",
        "ACCOUNT_ORGANIZATION_NAME",
        "ACCOUNT_TAGS",
        "FINDING_UID",
        "PROVIDER",
        "CHECK_ID",
        "CHECK_TITLE",
        "CHECK_TYPE",
        "STATUS",
        "STATUS_EXTENDED",
        "MUTED",
        "SERVICE_NAME",
        "SUBSERVICE_NAME",
        "SEVERITY",
        "RESOURCE_TYPE",
        "RESOURCE_UID",
        "RESOURCE_NAME",
        "RESOURCE_DETAILS",
        "RESOURCE_TAGS",
        "PARTITION",
        "REGION",
        "DESCRIPTION",
        "RISK",
        "RELATED_URL",
        "REMEDIATION_RECOMMENDATION_TEXT",
        "REMEDIATION_RECOMMENDATION_URL",
        "REMEDIATION_CODE_NATIVEIAC",
        "REMEDIATION_CODE_TERRAFORM",
        "REMEDIATION_CODE_CLI",
        "REMEDIATION_CODE_OTHER",
        "COMPLIANCE",
        "CATEGORIES",
        "DEPENDS_ON",
        "RELATED_TO",
        "NOTES",
        "PROWLER_VERSION",
        "ADDITIONAL_URLS",
    }
)


class CSVParseError(Exception):
    """Exception raised when CSV parsing fails."""

    def __init__(
        self,
        message: str,
        row: int | None = None,
        column: str | None = None,
    ):
        self.message = message
        self.row = row
        self.column = column
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        parts = [self.message]
        if self.row is not None:
            parts.append(f"at row {self.row}")
        if self.column:
            parts.append(f"(column: {self.column})")
        return " ".join(parts)


@dataclass
class CSVValidationError:
    """Represents a single CSV validation error."""

    message: str
    field: str
    row: int | None = None
    value: Any = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        result = {
            "message": self.message,
            "field": self.field,
        }
        if self.row is not None:
            result["row"] = self.row
        if self.value is not None:
            result["value"] = str(self.value)[:100]  # Truncate long values
        return result


@dataclass
class CSVValidationResult:
    """Result of CSV validation."""

    is_valid: bool
    errors: list[CSVValidationError] = field(default_factory=list)
    warnings: list[CSVValidationError] = field(default_factory=list)

    def add_error(
        self,
        message: str,
        field_path: str,
        row: int | None = None,
        value: Any = None,
    ) -> None:
        """Add a validation error."""
        self.errors.append(
            CSVValidationError(
                message=message,
                field=field_path,
                row=row,
                value=value,
            )
        )
        self.is_valid = False

    def add_warning(
        self,
        message: str,
        field_path: str,
        row: int | None = None,
        value: Any = None,
    ) -> None:
        """Add a validation warning (non-fatal)."""
        self.warnings.append(
            CSVValidationError(
                message=message,
                field=field_path,
                row=row,
                value=value,
            )
        )


@dataclass
class CSVResource:
    """Parsed CSV resource structure."""

    uid: str
    name: str
    region: str
    service: str
    type: str
    partition: str = ""
    tags: str = ""
    details: str = ""

    @classmethod
    def from_row(cls, row: dict[str, str], row_num: int = 0) -> "CSVResource":
        """
        Create a CSVResource from a CSV row dictionary.

        Args:
            row: Dictionary containing CSV row data.
            row_num: Row number for error reporting.

        Returns:
            CSVResource instance.

        Raises:
            CSVParseError: If required fields are missing.
        """
        uid = row.get("RESOURCE_UID", "").strip()
        if not uid:
            raise CSVParseError(
                "Missing required field 'RESOURCE_UID'",
                row=row_num,
                column="RESOURCE_UID",
            )

        return cls(
            uid=uid,
            name=row.get("RESOURCE_NAME", uid).strip() or uid,
            region=row.get("REGION", "").strip(),
            service=row.get("SERVICE_NAME", "").strip(),
            type=row.get("RESOURCE_TYPE", "").strip(),
            partition=row.get("PARTITION", "").strip(),
            tags=row.get("RESOURCE_TAGS", "").strip(),
            details=row.get("RESOURCE_DETAILS", "").strip(),
        )


@dataclass
class CSVCheckMetadata:
    """Check metadata extracted from CSV row."""

    title: str = ""
    description: str = ""
    risk: str = ""
    remediation_description: str = ""
    remediation_url: str = ""
    remediation_cli: str = ""
    remediation_terraform: str = ""
    remediation_nativeiac: str = ""
    remediation_other: str = ""
    categories: list[str] = field(default_factory=list)
    related_url: str = ""
    additional_urls: list[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class CSVFinding:
    """Parsed CSV finding structure."""

    # Core finding identifiers
    uid: str
    check_id: str

    # Status and severity
    severity: str
    status: str
    status_extended: str

    # Muted flag
    muted: bool

    # Check metadata
    check_metadata: CSVCheckMetadata

    # Compliance mappings
    compliance: dict[str, list[str]]

    # Associated resource
    resource: CSVResource

    # Provider information
    provider_type: str
    account_uid: str
    account_name: str
    account_email: str
    account_organization_uid: str
    account_organization_name: str
    account_tags: str

    # Authentication method
    auth_method: str

    # Timestamps
    timestamp: datetime | None = None

    # Raw data for reference
    raw_row: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_row(cls, row: dict[str, str], row_num: int = 0) -> "CSVFinding":
        """
        Create a CSVFinding from a CSV row dictionary.

        Args:
            row: Dictionary containing CSV row data.
            row_num: Row number for error reporting.

        Returns:
            CSVFinding instance.

        Raises:
            CSVParseError: If required fields are missing or invalid.
        """
        # Extract and validate required fields
        finding_uid = row.get("FINDING_UID", "").strip()
        if not finding_uid:
            raise CSVParseError(
                "Missing required field 'FINDING_UID'",
                row=row_num,
                column="FINDING_UID",
            )

        check_id = row.get("CHECK_ID", "").strip()
        if not check_id:
            raise CSVParseError(
                "Missing required field 'CHECK_ID'",
                row=row_num,
                column="CHECK_ID",
            )

        provider_type = row.get("PROVIDER", "").strip()
        if not provider_type:
            raise CSVParseError(
                "Missing required field 'PROVIDER'",
                row=row_num,
                column="PROVIDER",
            )

        # Normalize and validate provider type
        provider_type_normalized = provider_type.lower()
        if provider_type_normalized not in SUPPORTED_PROVIDER_TYPES:
            logger.warning(
                f"Unknown provider type '{provider_type}' at row {row_num}. "
                f"Supported types: {', '.join(sorted(SUPPORTED_PROVIDER_TYPES))}"
            )
            # Don't fail - allow unknown providers but log warning

        account_uid = row.get("ACCOUNT_UID", "").strip()
        if not account_uid:
            raise CSVParseError(
                "Missing required field 'ACCOUNT_UID'",
                row=row_num,
                column="ACCOUNT_UID",
            )

        # Extract severity (normalize to lowercase)
        severity = row.get("SEVERITY", "informational").strip().lower()
        if severity not in VALID_SEVERITY_LEVELS:
            logger.warning(
                f"Unknown severity '{severity}' at row {row_num}, "
                "defaulting to 'informational'"
            )
            severity = "informational"

        # Extract status (normalize to uppercase)
        status = row.get("STATUS", "").strip().upper()
        if status not in VALID_STATUS_CODES:
            logger.warning(
                f"Unknown status '{status}' at row {row_num}, defaulting to 'MANUAL'"
            )
            status = "MANUAL"

        # Extract status extended
        status_extended = row.get("STATUS_EXTENDED", "").strip()

        # Extract muted flag
        muted_str = row.get("MUTED", "").strip().lower()
        muted = muted_str in ("true", "1", "yes")

        # Parse compliance column (pipe-separated frameworks)
        compliance = _parse_compliance(row.get("COMPLIANCE", ""))

        # Parse categories
        categories_str = row.get("CATEGORIES", "").strip()
        categories = [c.strip() for c in categories_str.split(",") if c.strip()]

        # Parse additional URLs
        additional_urls_str = row.get("ADDITIONAL_URLS", "").strip()
        additional_urls = [
            u.strip() for u in additional_urls_str.split("|") if u.strip()
        ]

        # Build check metadata
        check_metadata = CSVCheckMetadata(
            title=row.get("CHECK_TITLE", "").strip(),
            description=row.get("DESCRIPTION", "").strip(),
            risk=row.get("RISK", "").strip(),
            remediation_description=row.get(
                "REMEDIATION_RECOMMENDATION_TEXT", ""
            ).strip(),
            remediation_url=row.get("REMEDIATION_RECOMMENDATION_URL", "").strip(),
            remediation_cli=row.get("REMEDIATION_CODE_CLI", "").strip(),
            remediation_terraform=row.get("REMEDIATION_CODE_TERRAFORM", "").strip(),
            remediation_nativeiac=row.get("REMEDIATION_CODE_NATIVEIAC", "").strip(),
            remediation_other=row.get("REMEDIATION_CODE_OTHER", "").strip(),
            categories=categories,
            related_url=row.get("RELATED_URL", "").strip(),
            additional_urls=additional_urls,
            notes=row.get("NOTES", "").strip(),
        )

        # Parse resource
        resource = CSVResource.from_row(row, row_num)

        # Parse timestamp
        timestamp = None
        timestamp_str = row.get("TIMESTAMP", "").strip()
        if timestamp_str:
            timestamp = _parse_timestamp(timestamp_str)

        return cls(
            uid=finding_uid,
            check_id=check_id,
            severity=severity,
            status=status,
            status_extended=status_extended,
            muted=muted,
            check_metadata=check_metadata,
            compliance=compliance,
            resource=resource,
            provider_type=provider_type_normalized,
            account_uid=account_uid,
            account_name=row.get("ACCOUNT_NAME", "").strip(),
            account_email=row.get("ACCOUNT_EMAIL", "").strip(),
            account_organization_uid=row.get("ACCOUNT_ORGANIZATION_UID", "").strip(),
            account_organization_name=row.get("ACCOUNT_ORGANIZATION_NAME", "").strip(),
            account_tags=row.get("ACCOUNT_TAGS", "").strip(),
            auth_method=row.get("AUTH_METHOD", "").strip(),
            timestamp=timestamp,
            raw_row=dict(row),
        )


def _parse_compliance(compliance_str: str) -> dict[str, list[str]]:
    """
    Parse the compliance column from Prowler CSV.

    Format: "FRAMEWORK1: control1, control2 | FRAMEWORK2: control3"

    Args:
        compliance_str: Raw compliance string from CSV.

    Returns:
        Dictionary mapping framework names to lists of controls.
    """
    result: dict[str, list[str]] = {}

    if not compliance_str or not compliance_str.strip():
        return result

    # Split by pipe to get individual framework entries
    entries = compliance_str.split("|")

    for entry in entries:
        entry = entry.strip()
        if not entry:
            continue

        # Split by colon to separate framework from controls
        if ":" in entry:
            parts = entry.split(":", 1)
            framework = parts[0].strip()
            controls_str = parts[1].strip() if len(parts) > 1 else ""

            if framework:
                # Split controls by comma
                controls = [c.strip() for c in controls_str.split(",") if c.strip()]
                if framework in result:
                    result[framework].extend(controls)
                else:
                    result[framework] = controls
        else:
            # No colon - treat entire entry as framework with no controls
            framework = entry.strip()
            if framework and framework not in result:
                result[framework] = []

    return result


def _parse_timestamp(timestamp_str: str) -> datetime | None:
    """
    Parse timestamp string from CSV.

    Supports multiple formats:
    - ISO 8601: "2025-02-14T14:27:03.913874"
    - Space-separated: "2025-02-14 14:27:03.913874"

    Args:
        timestamp_str: Raw timestamp string.

    Returns:
        Parsed datetime or None if parsing fails.
    """
    if not timestamp_str:
        return None

    # Try different formats
    formats = [
        "%Y-%m-%dT%H:%M:%S.%f",  # ISO 8601 with microseconds
        "%Y-%m-%d %H:%M:%S.%f",  # Space-separated with microseconds
        "%Y-%m-%dT%H:%M:%S",  # ISO 8601 without microseconds
        "%Y-%m-%d %H:%M:%S",  # Space-separated without microseconds
        "%Y-%m-%d",  # Date only
    ]

    for fmt in formats:
        try:
            return datetime.strptime(timestamp_str, fmt)
        except ValueError:
            continue

    logger.warning(f"Could not parse timestamp: {timestamp_str}")
    return None


def _detect_delimiter(content_str: str) -> str:
    """
    Detect the CSV delimiter by analyzing the first line.

    Args:
        content_str: CSV content as string.

    Returns:
        Detected delimiter (semicolon or comma).
    """
    first_line = content_str.split("\n")[0] if "\n" in content_str else content_str

    # Count occurrences of potential delimiters
    semicolon_count = first_line.count(";")
    comma_count = first_line.count(",")

    # Prowler default is semicolon, prefer it if counts are close
    if semicolon_count >= comma_count:
        return ";"
    return ","


def parse_csv(content: bytes) -> list[CSVFinding]:
    """
    Parse CSV content into a list of CSVFinding objects.

    Args:
        content: Raw bytes containing CSV data.

    Returns:
        List of CSVFinding objects.

    Raises:
        CSVParseError: If the content is not valid CSV or doesn't match
            the expected Prowler format.
    """
    # Decode bytes to string
    try:
        content_str = content.decode("utf-8")
    except UnicodeDecodeError as e:
        raise CSVParseError(f"Invalid UTF-8 encoding: {e}")

    if not content_str.strip():
        raise CSVParseError("CSV content is empty")

    # Detect delimiter
    delimiter = _detect_delimiter(content_str)

    # Parse CSV
    try:
        reader = csv.DictReader(io.StringIO(content_str), delimiter=delimiter)
        headers = reader.fieldnames

        if not headers:
            raise CSVParseError("CSV has no headers")

        # Validate required columns exist
        headers_set = set(headers)
        missing_required = REQUIRED_CSV_COLUMNS - headers_set
        if missing_required:
            raise CSVParseError(
                f"Missing required CSV columns: {', '.join(sorted(missing_required))}"
            )

        # Warn about unexpected columns
        unexpected = headers_set - EXPECTED_CSV_COLUMNS
        if unexpected:
            logger.warning(
                f"CSV contains unexpected columns: {', '.join(sorted(unexpected))}"
            )

        # Parse each row
        findings: list[CSVFinding] = []
        errors: list[str] = []

        for row_num, row in enumerate(reader, start=2):  # Start at 2 (header is row 1)
            try:
                finding = CSVFinding.from_row(row, row_num)
                findings.append(finding)
            except CSVParseError as e:
                errors.append(str(e))

        # If all rows failed to parse, raise an error
        if len(errors) > 0 and len(findings) == 0:
            raise CSVParseError(
                f"Failed to parse any rows. Errors: {'; '.join(errors[:5])}"
                + (f" (and {len(errors) - 5} more)" if len(errors) > 5 else "")
            )

        # Log warnings for partial failures
        if len(errors) > 0:
            logger.warning(
                f"Parsed {len(findings)} findings with {len(errors)} errors: "
                f"{'; '.join(errors[:3])}"
            )

        return findings

    except csv.Error as e:
        raise CSVParseError(f"CSV parsing error: {e}")


def validate_csv_structure(content: bytes) -> tuple[bool, str | None]:
    """
    Validate that content is valid Prowler CSV without fully parsing.

    This is a lightweight validation for quick format detection.

    Args:
        content: Raw bytes to validate.

    Returns:
        Tuple of (is_valid, error_message).
        If valid, error_message is None.
    """
    try:
        content_str = content.decode("utf-8")
    except UnicodeDecodeError:
        return False, "Invalid UTF-8 encoding"

    if not content_str.strip():
        return False, "CSV content is empty"

    # Detect delimiter
    delimiter = _detect_delimiter(content_str)

    try:
        reader = csv.DictReader(io.StringIO(content_str), delimiter=delimiter)
        headers = reader.fieldnames

        if not headers:
            return False, "CSV has no headers"

        # Check for required columns
        headers_set = set(headers)
        missing_required = REQUIRED_CSV_COLUMNS - headers_set
        if missing_required:
            return (
                False,
                f"Missing required columns: {', '.join(sorted(missing_required))}",
            )

        # Try to read first row to validate structure
        try:
            first_row = next(reader, None)
            if first_row is None:
                return True, None  # Empty CSV with headers is valid

            # Check that required fields have values
            for col in REQUIRED_CSV_COLUMNS:
                if not first_row.get(col, "").strip():
                    return False, f"First row missing value for required column: {col}"

        except csv.Error as e:
            return False, f"CSV parsing error: {e}"

        return True, None

    except csv.Error as e:
        return False, f"CSV parsing error: {e}"


def validate_csv_content(
    content: bytes,
    strict: bool = False,
    max_errors: int = 100,
) -> CSVValidationResult:
    """
    Validate CSV content comprehensively.

    This function performs full validation of CSV content, checking:
    - CSV syntax and structure
    - Required columns
    - Required field values
    - Provider type validity
    - Severity and status values

    Args:
        content: Raw bytes containing CSV data.
        strict: If True, treat warnings as errors.
        max_errors: Maximum number of errors to collect before stopping.

    Returns:
        CSVValidationResult with comprehensive validation results.
    """
    result = CSVValidationResult(is_valid=True)

    # Decode bytes to string
    try:
        content_str = content.decode("utf-8")
    except UnicodeDecodeError as e:
        result.add_error(f"Invalid UTF-8 encoding: {e}", "content")
        return result

    if not content_str.strip():
        result.add_error("CSV content is empty", "content")
        return result

    # Detect delimiter
    delimiter = _detect_delimiter(content_str)

    try:
        reader = csv.DictReader(io.StringIO(content_str), delimiter=delimiter)
        headers = reader.fieldnames

        if not headers:
            result.add_error("CSV has no headers", "headers")
            return result

        # Check for required columns
        headers_set = set(headers)
        missing_required = REQUIRED_CSV_COLUMNS - headers_set
        if missing_required:
            for col in sorted(missing_required):
                result.add_error(f"Missing required column: {col}", col)
            return result

        # Warn about unexpected columns
        unexpected = headers_set - EXPECTED_CSV_COLUMNS
        for col in sorted(unexpected):
            result.add_warning(f"Unexpected column: {col}", col)

        # Validate each row
        row_count = 0
        for row_num, row in enumerate(reader, start=2):
            if len(result.errors) >= max_errors:
                result.add_warning(
                    f"Validation stopped after {max_errors} errors. "
                    f"Additional rows not validated.",
                    "content",
                )
                break

            row_count += 1
            _validate_csv_row(row, row_num, result, strict)

        if row_count == 0:
            result.add_warning("CSV contains no data rows", "content")

    except csv.Error as e:
        result.add_error(f"CSV parsing error: {e}", "content")

    return result


def _validate_csv_row(
    row: dict[str, str],
    row_num: int,
    result: CSVValidationResult,
    strict: bool,
) -> None:
    """
    Validate a single CSV row.

    Args:
        row: Dictionary containing CSV row data.
        row_num: Row number for error reporting.
        result: CSVValidationResult to add errors/warnings to.
        strict: If True, treat warnings as errors.
    """
    # Check required fields have values
    for col in REQUIRED_CSV_COLUMNS:
        value = row.get(col, "").strip()
        if not value:
            result.add_error(
                f"Missing required value for '{col}'",
                col,
                row=row_num,
            )

    # Validate provider type
    provider = row.get("PROVIDER", "").strip()
    if provider:
        provider_lower = provider.lower()
        if provider_lower not in SUPPORTED_PROVIDER_TYPES:
            msg = (
                f"Unknown provider type '{provider}'. "
                f"Supported: {', '.join(sorted(SUPPORTED_PROVIDER_TYPES))}"
            )
            if strict:
                result.add_error(msg, "PROVIDER", row=row_num, value=provider)
            else:
                result.add_warning(msg, "PROVIDER", row=row_num, value=provider)

    # Validate severity
    severity = row.get("SEVERITY", "").strip()
    if severity:
        severity_lower = severity.lower()
        if severity_lower not in VALID_SEVERITY_LEVELS:
            msg = (
                f"Unknown severity '{severity}'. "
                f"Valid values: {', '.join(sorted(VALID_SEVERITY_LEVELS))}"
            )
            if strict:
                result.add_error(msg, "SEVERITY", row=row_num, value=severity)
            else:
                result.add_warning(msg, "SEVERITY", row=row_num, value=severity)

    # Validate status
    status = row.get("STATUS", "").strip()
    if status:
        status_upper = status.upper()
        if status_upper not in VALID_STATUS_CODES:
            msg = (
                f"Unknown status '{status}'. "
                f"Valid values: {', '.join(sorted(VALID_STATUS_CODES))}"
            )
            if strict:
                result.add_error(msg, "STATUS", row=row_num, value=status)
            else:
                result.add_warning(msg, "STATUS", row=row_num, value=status)


def extract_provider_info(findings: list[CSVFinding]) -> tuple[str, str] | None:
    """
    Extract provider type and account UID from parsed findings.

    Args:
        findings: List of parsed CSV findings.

    Returns:
        Tuple of (provider_type, account_uid) or None if no findings.
    """
    if not findings:
        return None

    # Use the first finding's provider info
    first = findings[0]
    return (first.provider_type, first.account_uid)


def get_supported_provider_types() -> list[str]:
    """
    Get list of supported provider types.

    Returns:
        Sorted list of supported provider type strings.
    """
    return sorted(SUPPORTED_PROVIDER_TYPES)


def get_valid_severity_levels() -> list[str]:
    """
    Get list of valid severity levels.

    Returns:
        Sorted list of valid severity level strings.
    """
    return sorted(VALID_SEVERITY_LEVELS)


def get_valid_status_codes() -> list[str]:
    """
    Get list of valid status codes.

    Returns:
        Sorted list of valid status code strings.
    """
    return sorted(VALID_STATUS_CODES)


def get_required_csv_columns() -> list[str]:
    """
    Get list of required CSV columns.

    Returns:
        Sorted list of required column names.
    """
    return sorted(REQUIRED_CSV_COLUMNS)


def get_expected_csv_columns() -> list[str]:
    """
    Get list of all expected CSV columns.

    Returns:
        Sorted list of expected column names.
    """
    return sorted(EXPECTED_CSV_COLUMNS)
