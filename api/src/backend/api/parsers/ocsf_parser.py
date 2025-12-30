"""
OCSF (Open Cybersecurity Schema Framework) Parser for Prowler scan results.

This module provides parsing functionality for Prowler CLI JSON/OCSF output format.
It extracts findings, resources, and provider information from OCSF-formatted JSON.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

logger = logging.getLogger(__name__)

# Supported provider types for validation
SUPPORTED_PROVIDER_TYPES = frozenset({
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
})

# Valid severity levels (normalized to lowercase)
VALID_SEVERITY_LEVELS = frozenset({
    "critical",
    "high",
    "medium",
    "low",
    "informational",
})

# Valid status codes (normalized to uppercase)
VALID_STATUS_CODES = frozenset({
    "PASS",
    "FAIL",
    "MANUAL",
})

# Required top-level OCSF fields
REQUIRED_OCSF_TOP_LEVEL_FIELDS = frozenset({
    "metadata",
    "finding_info",
    "cloud",
})

# Required nested OCSF fields (path -> description)
REQUIRED_OCSF_NESTED_FIELDS = {
    "metadata.event_code": "Check ID/event code",
    "finding_info.uid": "Finding unique identifier",
    "cloud.provider": "Cloud provider type",
    "cloud.account.uid": "Cloud account identifier",
}


@dataclass
class OCSFValidationError:
    """Represents a single validation error."""

    message: str
    field: str
    index: int | None = None
    value: Any = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for API responses."""
        result = {
            "message": self.message,
            "field": self.field,
        }
        if self.index is not None:
            result["index"] = self.index
        if self.value is not None:
            result["value"] = str(self.value)[:100]  # Truncate long values
        return result


@dataclass
class OCSFValidationResult:
    """Result of OCSF validation."""

    is_valid: bool
    errors: list[OCSFValidationError] = field(default_factory=list)
    warnings: list[OCSFValidationError] = field(default_factory=list)

    def add_error(
        self,
        message: str,
        field_path: str,
        index: int | None = None,
        value: Any = None,
    ) -> None:
        """Add a validation error."""
        self.errors.append(
            OCSFValidationError(
                message=message,
                field=field_path,
                index=index,
                value=value,
            )
        )
        self.is_valid = False

    def add_warning(
        self,
        message: str,
        field_path: str,
        index: int | None = None,
        value: Any = None,
    ) -> None:
        """Add a validation warning (non-fatal)."""
        self.warnings.append(
            OCSFValidationError(
                message=message,
                field=field_path,
                index=index,
                value=value,
            )
        )


class OCSFParseError(Exception):
    """Exception raised when OCSF parsing fails."""

    def __init__(self, message: str, index: int | None = None, field: str | None = None):
        self.message = message
        self.index = index
        self.field = field
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        parts = [self.message]
        if self.index is not None:
            parts.append(f"at index {self.index}")
        if self.field:
            parts.append(f"(field: {self.field})")
        return " ".join(parts)


@dataclass
class OCSFResource:
    """Parsed OCSF resource structure."""

    uid: str
    name: str
    region: str
    service: str
    type: str
    cloud_partition: str = ""
    labels: list[str] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any], index: int = 0) -> "OCSFResource":
        """
        Create an OCSFResource from a dictionary.

        Args:
            data: Dictionary containing resource data from OCSF JSON.
            index: Index of the finding for error reporting.

        Returns:
            OCSFResource instance.

        Raises:
            OCSFParseError: If required fields are missing.
        """
        uid = data.get("uid")
        if not uid:
            raise OCSFParseError("Missing required field 'uid' in resource", index, "resources[].uid")

        return cls(
            uid=str(uid),
            name=str(data.get("name", uid)),
            region=str(data.get("region", "")),
            service=str(data.get("group", {}).get("name", "")),
            type=str(data.get("type", "")),
            cloud_partition=str(data.get("cloud_partition", "")),
            labels=data.get("labels", []),
            data=data.get("data", {}),
        )


@dataclass
class OCSFCheckMetadata:
    """Check metadata extracted from OCSF finding."""

    title: str = ""
    description: str = ""
    risk: str = ""
    remediation_description: str = ""
    remediation_references: list[str] = field(default_factory=list)
    categories: list[str] = field(default_factory=list)
    related_url: str = ""



@dataclass
class OCSFFinding:
    """Parsed OCSF finding structure."""

    # Core finding identifiers
    uid: str
    check_id: str

    # Status and severity
    severity: str
    status: str
    status_extended: str

    # Descriptive fields
    message: str
    impact_extended: str

    # Check metadata
    check_metadata: OCSFCheckMetadata

    # Compliance mappings
    compliance: dict[str, list[str]]

    # Associated resources
    resources: list[OCSFResource]

    # Provider information
    provider_type: str
    account_uid: str
    account_name: str

    # Timestamps
    timestamp: datetime | None = None

    # Raw data for reference
    raw_result: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any], index: int = 0) -> "OCSFFinding":
        """
        Create an OCSFFinding from a dictionary.

        Args:
            data: Dictionary containing finding data from OCSF JSON.
            index: Index of the finding for error reporting.

        Returns:
            OCSFFinding instance.

        Raises:
            OCSFParseError: If required fields are missing or invalid.
        """
        # Extract and validate required fields
        metadata = data.get("metadata", {})
        check_id = metadata.get("event_code")
        if not check_id:
            raise OCSFParseError(
                "Missing required field 'metadata.event_code'", index, "metadata.event_code"
            )

        finding_info = data.get("finding_info", {})
        uid = finding_info.get("uid")
        if not uid:
            raise OCSFParseError(
                "Missing required field 'finding_info.uid'", index, "finding_info.uid"
            )

        # Extract cloud/provider information
        cloud = data.get("cloud", {})
        provider_type = cloud.get("provider", "")
        if not provider_type:
            raise OCSFParseError(
                "Missing required field 'cloud.provider'", index, "cloud.provider"
            )

        # Normalize and validate provider type
        provider_type_normalized = provider_type.lower()
        if provider_type_normalized not in SUPPORTED_PROVIDER_TYPES:
            logger.warning(
                f"Unknown provider type '{provider_type}' at index {index}. "
                f"Supported types: {', '.join(sorted(SUPPORTED_PROVIDER_TYPES))}"
            )
            # Don't fail - allow unknown providers but log warning

        account = cloud.get("account", {})
        account_uid = account.get("uid", "")
        if not account_uid:
            raise OCSFParseError(
                "Missing required field 'cloud.account.uid'", index, "cloud.account.uid"
            )

        # Extract severity (normalize to lowercase)
        severity = str(data.get("severity", "informational")).lower()
        if severity not in VALID_SEVERITY_LEVELS:
            logger.warning(
                f"Unknown severity '{severity}' at index {index}, defaulting to 'informational'"
            )
            severity = "informational"

        # Extract status (normalize to uppercase for model compatibility)
        status_code = str(data.get("status_code", "")).upper()
        if status_code not in ("PASS", "FAIL", "MANUAL"):
            # Default to MANUAL if unknown status
            status_code = "MANUAL"

        # Extract status extended
        status_extended = str(data.get("status_detail", data.get("message", "")))

        # Extract message/impact
        message = str(data.get("message", ""))

        # Extract remediation info
        remediation = data.get("remediation", {})
        remediation_desc = str(remediation.get("desc", ""))
        remediation_refs = remediation.get("references", [])
        if not isinstance(remediation_refs, list):
            remediation_refs = []

        # Extract unmapped data (contains compliance, categories, etc.)
        unmapped = data.get("unmapped", {})
        compliance = unmapped.get("compliance", {})
        if not isinstance(compliance, dict):
            compliance = {}

        categories = unmapped.get("categories", [])
        if not isinstance(categories, list):
            categories = []

        related_url = str(unmapped.get("related_url", ""))

        # Build check metadata
        check_metadata = OCSFCheckMetadata(
            title=str(finding_info.get("title", "")),
            description=str(finding_info.get("desc", "")),
            risk=str(data.get("risk_details", "")),
            remediation_description=remediation_desc,
            remediation_references=remediation_refs,
            categories=categories,
            related_url=related_url,
        )

        # Parse resources
        resources_data = data.get("resources", [])
        if not isinstance(resources_data, list):
            resources_data = []

        resources = []
        for res_data in resources_data:
            try:
                resources.append(OCSFResource.from_dict(res_data, index))
            except OCSFParseError:
                # Log warning but continue - resource parsing is not critical
                logger.warning(f"Failed to parse resource at finding index {index}")

        # Parse timestamp
        timestamp = None
        time_dt = data.get("time_dt")
        if time_dt:
            try:
                timestamp = datetime.fromisoformat(str(time_dt))
            except (ValueError, TypeError):
                # Try parsing from Unix timestamp
                time_val = data.get("time")
                if time_val:
                    try:
                        timestamp = datetime.fromtimestamp(float(time_val))
                    except (ValueError, TypeError):
                        pass

        return cls(
            uid=str(uid),
            check_id=str(check_id),
            severity=severity,
            status=status_code,
            status_extended=status_extended,
            message=message,
            impact_extended=message,  # OCSF uses message for impact
            check_metadata=check_metadata,
            compliance=compliance,
            resources=resources,
            provider_type=provider_type_normalized,
            account_uid=str(account_uid),
            account_name=str(account.get("name", "")),
            timestamp=timestamp,
            raw_result=data,
        )



def parse_ocsf_json(content: bytes) -> list[OCSFFinding]:
    """
    Parse OCSF JSON content into a list of OCSFFinding objects.

    Args:
        content: Raw bytes containing OCSF JSON data (array of findings).

    Returns:
        List of OCSFFinding objects.

    Raises:
        OCSFParseError: If the content is not valid JSON or doesn't match
            the expected OCSF format.
    """
    # Decode bytes to string
    try:
        content_str = content.decode("utf-8")
    except UnicodeDecodeError as e:
        raise OCSFParseError(f"Invalid UTF-8 encoding: {e}")

    # Parse JSON
    try:
        data = json.loads(content_str)
    except json.JSONDecodeError as e:
        raise OCSFParseError(f"Invalid JSON: {e}")

    # Validate structure - must be a list
    if not isinstance(data, list):
        raise OCSFParseError(
            "Invalid OCSF format: expected a JSON array of findings"
        )

    if len(data) == 0:
        logger.warning("OCSF JSON contains no findings")
        return []

    # Parse each finding
    findings: list[OCSFFinding] = []
    errors: list[str] = []

    for index, finding_data in enumerate(data):
        if not isinstance(finding_data, dict):
            errors.append(f"Finding at index {index} is not a JSON object")
            continue

        try:
            finding = OCSFFinding.from_dict(finding_data, index)
            findings.append(finding)
        except OCSFParseError as e:
            errors.append(str(e))

    # If all findings failed to parse, raise an error
    if len(errors) > 0 and len(findings) == 0:
        raise OCSFParseError(
            f"Failed to parse any findings. Errors: {'; '.join(errors[:5])}"
            + (f" (and {len(errors) - 5} more)" if len(errors) > 5 else "")
        )

    # Log warnings for partial failures
    if len(errors) > 0:
        logger.warning(
            f"Parsed {len(findings)} findings with {len(errors)} errors: "
            f"{'; '.join(errors[:3])}"
        )

    return findings


def validate_ocsf_structure(content: bytes) -> tuple[bool, str | None]:
    """
    Validate that content is valid OCSF JSON without fully parsing.

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

    try:
        data = json.loads(content_str)
    except json.JSONDecodeError as e:
        return False, f"Invalid JSON: {e}"

    if not isinstance(data, list):
        return False, "Expected JSON array"

    if len(data) == 0:
        return True, None  # Empty array is valid

    # Check first item has expected OCSF fields
    first_item = data[0]
    if not isinstance(first_item, dict):
        return False, "Array items must be objects"

    # Check for key OCSF fields
    required_fields = ["metadata", "finding_info", "cloud"]
    missing = [f for f in required_fields if f not in first_item]
    if missing:
        return False, f"Missing required OCSF fields: {', '.join(missing)}"

    # Check metadata has event_code
    metadata = first_item.get("metadata", {})
    if not isinstance(metadata, dict) or "event_code" not in metadata:
        return False, "Missing metadata.event_code"

    return True, None


def extract_provider_info(findings: list[OCSFFinding]) -> tuple[str, str] | None:
    """
    Extract provider type and account UID from parsed findings.

    Args:
        findings: List of parsed OCSF findings.

    Returns:
        Tuple of (provider_type, account_uid) or None if no findings.
    """
    if not findings:
        return None

    # Use the first finding's provider info
    first = findings[0]
    return (first.provider_type, first.account_uid)


def _get_nested_value(data: dict[str, Any], path: str) -> Any:
    """
    Get a nested value from a dictionary using dot notation.

    Args:
        data: Dictionary to search.
        path: Dot-separated path (e.g., "cloud.account.uid").

    Returns:
        The value at the path, or None if not found.
    """
    keys = path.split(".")
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
        if current is None:
            return None
    return current


def validate_ocsf_finding(
    data: dict[str, Any],
    index: int = 0,
    strict: bool = False,
) -> OCSFValidationResult:
    """
    Validate a single OCSF finding dictionary.

    Args:
        data: Dictionary containing finding data from OCSF JSON.
        index: Index of the finding for error reporting.
        strict: If True, treat warnings as errors.

    Returns:
        OCSFValidationResult with validation status and any errors/warnings.
    """
    result = OCSFValidationResult(is_valid=True)

    # Validate required top-level fields
    for field_name in REQUIRED_OCSF_TOP_LEVEL_FIELDS:
        if field_name not in data:
            result.add_error(
                f"Missing required field '{field_name}'",
                field_name,
                index=index,
            )
        elif not isinstance(data[field_name], dict):
            result.add_error(
                f"Field '{field_name}' must be an object",
                field_name,
                index=index,
                value=type(data[field_name]).__name__,
            )

    # Validate required nested fields
    for field_path, description in REQUIRED_OCSF_NESTED_FIELDS.items():
        value = _get_nested_value(data, field_path)
        if value is None or (isinstance(value, str) and not value.strip()):
            result.add_error(
                f"Missing required field '{field_path}' ({description})",
                field_path,
                index=index,
            )

    # Validate provider type if present
    provider_type = _get_nested_value(data, "cloud.provider")
    if provider_type:
        provider_type_lower = str(provider_type).lower()
        if provider_type_lower not in SUPPORTED_PROVIDER_TYPES:
            msg = (
                f"Unknown provider type '{provider_type}'. "
                f"Supported: {', '.join(sorted(SUPPORTED_PROVIDER_TYPES))}"
            )
            if strict:
                result.add_error(msg, "cloud.provider", index=index, value=provider_type)
            else:
                result.add_warning(msg, "cloud.provider", index=index, value=provider_type)

    # Validate severity if present
    severity = data.get("severity")
    if severity:
        severity_lower = str(severity).lower()
        if severity_lower not in VALID_SEVERITY_LEVELS:
            msg = (
                f"Unknown severity '{severity}'. "
                f"Valid values: {', '.join(sorted(VALID_SEVERITY_LEVELS))}"
            )
            if strict:
                result.add_error(msg, "severity", index=index, value=severity)
            else:
                result.add_warning(msg, "severity", index=index, value=severity)

    # Validate status_code if present
    status_code = data.get("status_code")
    if status_code:
        status_upper = str(status_code).upper()
        if status_upper not in VALID_STATUS_CODES:
            msg = (
                f"Unknown status_code '{status_code}'. "
                f"Valid values: {', '.join(sorted(VALID_STATUS_CODES))}"
            )
            if strict:
                result.add_error(msg, "status_code", index=index, value=status_code)
            else:
                result.add_warning(msg, "status_code", index=index, value=status_code)

    # Validate resources array if present
    resources = data.get("resources")
    if resources is not None:
        if not isinstance(resources, list):
            result.add_error(
                "Field 'resources' must be an array",
                "resources",
                index=index,
                value=type(resources).__name__,
            )
        else:
            for res_idx, resource in enumerate(resources):
                if not isinstance(resource, dict):
                    result.add_error(
                        f"Resource at index {res_idx} must be an object",
                        f"resources[{res_idx}]",
                        index=index,
                    )
                elif not resource.get("uid"):
                    result.add_error(
                        f"Resource at index {res_idx} missing required 'uid' field",
                        f"resources[{res_idx}].uid",
                        index=index,
                    )

    # Validate compliance structure if present
    unmapped = data.get("unmapped", {})
    if isinstance(unmapped, dict):
        compliance = unmapped.get("compliance")
        if compliance is not None and not isinstance(compliance, dict):
            result.add_warning(
                "Field 'unmapped.compliance' should be an object",
                "unmapped.compliance",
                index=index,
                value=type(compliance).__name__,
            )

    return result


def validate_ocsf_content(
    content: bytes,
    strict: bool = False,
    max_errors: int = 100,
) -> OCSFValidationResult:
    """
    Validate OCSF JSON content comprehensively.

    This function performs full validation of OCSF content, checking:
    - JSON syntax and structure
    - Required fields at all levels
    - Field types and formats
    - Provider type validity
    - Severity and status values

    Args:
        content: Raw bytes containing OCSF JSON data.
        strict: If True, treat warnings as errors.
        max_errors: Maximum number of errors to collect before stopping.

    Returns:
        OCSFValidationResult with comprehensive validation results.
    """
    result = OCSFValidationResult(is_valid=True)

    # Decode bytes to string
    try:
        content_str = content.decode("utf-8")
    except UnicodeDecodeError as e:
        result.add_error(f"Invalid UTF-8 encoding: {e}", "content")
        return result

    # Parse JSON
    try:
        data = json.loads(content_str)
    except json.JSONDecodeError as e:
        result.add_error(
            f"Invalid JSON syntax at line {e.lineno}, column {e.colno}: {e.msg}",
            "content",
        )
        return result

    # Validate structure - must be a list
    if not isinstance(data, list):
        result.add_error(
            f"Expected JSON array of findings, got {type(data).__name__}",
            "content",
        )
        return result

    if len(data) == 0:
        result.add_warning("OCSF content contains no findings", "content")
        return result

    # Validate each finding
    for index, finding_data in enumerate(data):
        if len(result.errors) >= max_errors:
            result.add_warning(
                f"Validation stopped after {max_errors} errors. "
                f"Additional findings not validated.",
                "content",
            )
            break

        if not isinstance(finding_data, dict):
            result.add_error(
                f"Finding must be a JSON object, got {type(finding_data).__name__}",
                f"[{index}]",
                index=index,
            )
            continue

        # Validate individual finding
        finding_result = validate_ocsf_finding(finding_data, index, strict)

        # Merge errors and warnings
        result.errors.extend(finding_result.errors)
        result.warnings.extend(finding_result.warnings)
        if not finding_result.is_valid:
            result.is_valid = False

    return result


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
