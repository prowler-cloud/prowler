"""
Unit tests for the CSV parser module.

Tests parsing of Prowler CLI CSV output format with semicolon delimiter support.

This module provides comprehensive test coverage for:
- Delimiter detection (semicolon vs comma)
- CSV parsing with both delimiter types
- Compliance column parsing (pipe-separated format)
- Required field validation
- Required column validation
- Error handling and reporting
- Data class construction from CSV rows
- Timestamp parsing
- Muted field parsing
- Provider info extraction
- Helper functions

Test Classes
------------
TestDetectDelimiter
    Tests for the `_detect_delimiter` internal function.
    Verifies correct detection of semicolon (Prowler default) and comma delimiters.

TestParseCSVWithSemicolonDelimiter
    Tests for `parse_csv` function with semicolon-delimited content.
    Covers single row, multiple rows, and both delimiter types.

TestValidateCSVStructureWithDelimiters
    Tests for `validate_csv_structure` function.
    Validates lightweight format detection for both delimiter types.

TestParseCompliance
    Tests for `_parse_compliance` internal function.
    Verifies parsing of pipe-separated compliance framework mappings.

TestCSVParseError
    Tests for `CSVParseError` exception class.
    Validates error message formatting with row and column context.

TestCSVFindingFromRow
    Tests for `CSVFinding.from_row` class method.
    Covers valid row parsing, required field validation, and normalization.

TestCSVResourceFromRow
    Tests for `CSVResource.from_row` class method.
    Covers valid row parsing and required field validation.

TestRequiredColumnValidation
    Tests for required CSV column validation.
    Covers missing columns in headers and empty values in data rows.

TestParseTimestamp
    Tests for `_parse_timestamp` internal function.
    Verifies parsing of various timestamp formats.

TestMutedFieldParsing
    Tests for muted field parsing in CSVFinding.
    Covers various boolean representations.

TestExtractProviderInfo
    Tests for `extract_provider_info` function.
    Verifies extraction of provider type and account UID from findings.

TestHelperFunctions
    Tests for helper functions that return constants.
    Covers get_supported_provider_types, get_valid_severity_levels, etc.

TestEmptyAndInvalidContent
    Tests for edge cases with empty or invalid content.
    Covers empty CSV, invalid UTF-8, and malformed content.

Usage
-----
Run tests from the api/src/backend directory::

    poetry run pytest api/tests/test_csv_parser.py -v

Run specific test class::

    poetry run pytest api/tests/test_csv_parser.py::TestParseCompliance -v

Run with coverage::

    poetry run pytest api/tests/test_csv_parser.py --cov=api.parsers.csv_parser

See Also
--------
- api/src/backend/api/parsers/csv_parser.py : Implementation module
- api/src/backend/api/parsers/README.md : Full API documentation
- .kiro/specs/scan-results-import/tasks.md : Feature specification
"""

import pytest
from datetime import datetime

from api.parsers.csv_parser import (
    CSVFinding,
    CSVParseError,
    CSVResource,
    SUPPORTED_PROVIDER_TYPES,
    VALID_SEVERITY_LEVELS,
    VALID_STATUS_CODES,
    REQUIRED_CSV_COLUMNS,
    EXPECTED_CSV_COLUMNS,
    _detect_delimiter,
    _parse_compliance,
    _parse_timestamp,
    parse_csv,
    validate_csv_structure,
    validate_csv_content,
    extract_provider_info,
    get_supported_provider_types,
    get_valid_severity_levels,
    get_valid_status_codes,
    get_required_csv_columns,
    get_expected_csv_columns,
)


class TestDetectDelimiter:
    """
    Tests for _detect_delimiter function.

    The delimiter detection analyzes the first line of CSV content to determine
    whether semicolon (Prowler default) or comma is used as the field separator.

    Test Coverage:
        - Semicolon delimiter detection (Prowler default)
        - Comma delimiter detection (standard CSV)
        - Preference for semicolon when counts are equal
        - Single line content handling
        - Empty content handling
    """

    def test_detect_semicolon_delimiter(self):
        """Test detection of semicolon delimiter (Prowler default)."""
        content = "FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID\nfinding-1;aws;check_1;PASS;123456789012"

        delimiter = _detect_delimiter(content)

        assert delimiter == ";"

    def test_detect_comma_delimiter(self):
        """Test detection of comma delimiter."""
        content = "FINDING_UID,PROVIDER,CHECK_ID,STATUS,ACCOUNT_UID\nfinding-1,aws,check_1,PASS,123456789012"

        delimiter = _detect_delimiter(content)

        assert delimiter == ","

    def test_prefer_semicolon_when_equal(self):
        """Test that semicolon is preferred when counts are equal."""
        # Both delimiters appear same number of times
        content = "A;B,C;D,E"

        delimiter = _detect_delimiter(content)

        assert delimiter == ";"

    def test_prefer_semicolon_when_more(self):
        """Test that semicolon is chosen when more frequent."""
        content = "A;B;C;D,E"

        delimiter = _detect_delimiter(content)

        assert delimiter == ";"

    def test_choose_comma_when_more_frequent(self):
        """Test that comma is chosen when more frequent."""
        content = "A,B,C,D;E"

        delimiter = _detect_delimiter(content)

        assert delimiter == ","

    def test_single_line_content(self):
        """Test delimiter detection with single line (no newline)."""
        content = "FINDING_UID;PROVIDER;CHECK_ID"

        delimiter = _detect_delimiter(content)

        assert delimiter == ";"

    def test_empty_content_defaults_to_semicolon(self):
        """Test that empty content defaults to semicolon."""
        content = ""

        delimiter = _detect_delimiter(content)

        # Both counts are 0, so semicolon is preferred
        assert delimiter == ";"


class TestParseCSVWithSemicolonDelimiter:
    """
    Tests for parse_csv function with semicolon delimiter.

    Verifies that the parser correctly handles Prowler's default semicolon-delimited
    CSV format as well as standard comma-delimited CSV.

    Test Coverage:
        - Semicolon-delimited CSV parsing
        - Comma-delimited CSV parsing
        - Multiple row parsing
        - Field extraction and normalization

    Fixtures:
        valid_semicolon_csv_content: Sample CSV with semicolon delimiter
        valid_comma_csv_content: Sample CSV with comma delimiter
    """

    @pytest.fixture
    def valid_semicolon_csv_content(self):
        """
        Return valid CSV content with semicolon delimiter.

        Returns:
            bytes: UTF-8 encoded CSV content with semicolon delimiter
                containing one finding row with all required fields.
        """
        csv_data = """FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;SEVERITY;STATUS_EXTENDED;RESOURCE_UID;RESOURCE_NAME;REGION;SERVICE_NAME;RESOURCE_TYPE
finding-001;aws;accessanalyzer_enabled;FAIL;123456789012;low;IAM Access Analyzer is not enabled;arn:aws:accessanalyzer:us-east-1:123456789012:analyzer;analyzer;us-east-1;accessanalyzer;Other"""
        return csv_data.encode("utf-8")

    @pytest.fixture
    def valid_comma_csv_content(self):
        """
        Return valid CSV content with comma delimiter.

        Returns:
            bytes: UTF-8 encoded CSV content with comma delimiter
                containing one finding row with all required fields.
        """
        csv_data = """FINDING_UID,PROVIDER,CHECK_ID,STATUS,ACCOUNT_UID,SEVERITY,STATUS_EXTENDED,RESOURCE_UID,RESOURCE_NAME,REGION,SERVICE_NAME,RESOURCE_TYPE
finding-001,aws,accessanalyzer_enabled,FAIL,123456789012,low,IAM Access Analyzer is not enabled,arn:aws:accessanalyzer:us-east-1:123456789012:analyzer,analyzer,us-east-1,accessanalyzer,Other"""
        return csv_data.encode("utf-8")

    def test_parse_semicolon_delimited_csv(self, valid_semicolon_csv_content):
        """Test parsing CSV with semicolon delimiter (Prowler default)."""
        findings = parse_csv(valid_semicolon_csv_content)

        assert len(findings) == 1
        assert findings[0].uid == "finding-001"
        assert findings[0].provider_type == "aws"
        assert findings[0].check_id == "accessanalyzer_enabled"
        assert findings[0].status == "FAIL"
        assert findings[0].account_uid == "123456789012"
        assert findings[0].severity == "low"
        assert (
            findings[0].resource.uid
            == "arn:aws:accessanalyzer:us-east-1:123456789012:analyzer"
        )
        assert findings[0].resource.region == "us-east-1"
        assert findings[0].resource.service == "accessanalyzer"

    def test_parse_comma_delimited_csv(self, valid_comma_csv_content):
        """Test parsing CSV with comma delimiter."""
        findings = parse_csv(valid_comma_csv_content)

        assert len(findings) == 1
        assert findings[0].uid == "finding-001"
        assert findings[0].provider_type == "aws"
        assert findings[0].check_id == "accessanalyzer_enabled"

    def test_parse_multiple_rows_semicolon(self):
        """Test parsing multiple rows with semicolon delimiter."""
        csv_data = """FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;SEVERITY;RESOURCE_UID
finding-001;aws;check_1;PASS;123456789012;low;resource-1
finding-002;aws;check_2;FAIL;123456789012;high;resource-2
finding-003;azure;check_3;MANUAL;subscription-123;medium;resource-3"""
        content = csv_data.encode("utf-8")

        findings = parse_csv(content)

        assert len(findings) == 3
        assert findings[0].uid == "finding-001"
        assert findings[0].status == "PASS"
        assert findings[1].uid == "finding-002"
        assert findings[1].status == "FAIL"
        assert findings[2].uid == "finding-003"
        assert findings[2].provider_type == "azure"


class TestValidateCSVStructureWithDelimiters:
    """
    Tests for validate_csv_structure with different delimiters.

    The structure validation performs lightweight format detection without
    fully parsing all rows, useful for quick format identification.

    Test Coverage:
        - Semicolon-delimited CSV structure validation
        - Comma-delimited CSV structure validation
        - Required column presence verification
    """

    def test_validate_semicolon_csv_structure(self):
        """Test validation of semicolon-delimited CSV structure."""
        csv_data = """FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
finding-001;aws;check_1;PASS;123456789012;resource-1"""
        content = csv_data.encode("utf-8")

        is_valid, error = validate_csv_structure(content)

        assert is_valid is True
        assert error is None

    def test_validate_comma_csv_structure(self):
        """Test validation of comma-delimited CSV structure."""
        csv_data = """FINDING_UID,PROVIDER,CHECK_ID,STATUS,ACCOUNT_UID,RESOURCE_UID
finding-001,aws,check_1,PASS,123456789012,resource-1"""
        content = csv_data.encode("utf-8")

        is_valid, error = validate_csv_structure(content)

        assert is_valid is True
        assert error is None


class TestParseCompliance:
    """
    Tests for _parse_compliance function.

    The compliance column in Prowler CSV uses a pipe-separated format:
    "FRAMEWORK1: control1, control2 | FRAMEWORK2: control3"

    Test Coverage:
        - Single framework parsing
        - Multiple frameworks with pipe separator
        - Empty compliance string
        - Framework without controls
    """

    def test_parse_single_framework(self):
        """Test parsing single compliance framework."""
        compliance_str = "CIS-1.4: 1.20, 1.21"

        result = _parse_compliance(compliance_str)

        assert "CIS-1.4" in result
        assert result["CIS-1.4"] == ["1.20", "1.21"]

    def test_parse_multiple_frameworks_pipe_separated(self):
        """Test parsing multiple frameworks separated by pipe."""
        compliance_str = "CIS-1.4: 1.20 | CIS-1.5: 1.20, 1.21 | NIST: AC-1"

        result = _parse_compliance(compliance_str)

        assert "CIS-1.4" in result
        assert "CIS-1.5" in result
        assert "NIST" in result
        assert result["CIS-1.4"] == ["1.20"]
        assert result["CIS-1.5"] == ["1.20", "1.21"]
        assert result["NIST"] == ["AC-1"]

    def test_parse_empty_compliance(self):
        """Test parsing empty compliance string."""
        result = _parse_compliance("")

        assert result == {}

    def test_parse_framework_without_controls(self):
        """Test parsing framework without controls."""
        compliance_str = "CIS-1.4"

        result = _parse_compliance(compliance_str)

        assert "CIS-1.4" in result
        assert result["CIS-1.4"] == []


class TestCSVParseError:
    """
    Tests for CSVParseError exception.

    CSVParseError provides contextual error information including:
    - Error message
    - Row number (optional)
    - Column name (optional)

    Test Coverage:
        - Basic error message formatting
        - Error message with row number
        - Error message with column name
    """

    def test_error_message_basic(self):
        """Test basic error message."""
        error = CSVParseError("Test error")

        assert str(error) == "Test error"

    def test_error_message_with_row(self):
        """Test error message with row number."""
        error = CSVParseError("Test error", row=5)

        assert "at row 5" in str(error)

    def test_error_message_with_column(self):
        """Test error message with column name."""
        error = CSVParseError("Test error", column="FINDING_UID")

        assert "FINDING_UID" in str(error)


class TestCSVFindingFromRow:
    """
    Tests for CSVFinding.from_row method.

    The from_row class method constructs a CSVFinding from a dictionary
    representing a CSV row. It validates required fields and normalizes
    values (e.g., severity to lowercase, status to uppercase).

    Test Coverage:
        - Valid row parsing with all fields
        - Missing FINDING_UID raises error
        - Missing PROVIDER raises error
        - Severity normalization to lowercase
        - Status normalization to uppercase

    Fixtures:
        valid_row: Dictionary with all required and optional CSV fields
    """

    @pytest.fixture
    def valid_row(self):
        """
        Return a valid CSV row dictionary.

        Returns:
            dict[str, str]: Dictionary containing all required fields
                and common optional fields for a CSV finding row.
        """
        return {
            "FINDING_UID": "finding-123",
            "PROVIDER": "aws",
            "CHECK_ID": "accessanalyzer_enabled",
            "STATUS": "FAIL",
            "ACCOUNT_UID": "123456789012",
            "SEVERITY": "low",
            "STATUS_EXTENDED": "IAM Access Analyzer is not enabled",
            "RESOURCE_UID": "arn:aws:accessanalyzer:us-east-1:123456789012:analyzer",
            "RESOURCE_NAME": "analyzer",
            "REGION": "us-east-1",
            "SERVICE_NAME": "accessanalyzer",
            "RESOURCE_TYPE": "Other",
        }

    def test_from_row_valid(self, valid_row):
        """Test creating CSVFinding from valid row."""
        finding = CSVFinding.from_row(valid_row)

        assert finding.uid == "finding-123"
        assert finding.check_id == "accessanalyzer_enabled"
        assert finding.provider_type == "aws"
        assert finding.status == "FAIL"
        assert finding.severity == "low"

    def test_from_row_missing_finding_uid_raises_error(self, valid_row):
        """Test that missing FINDING_UID raises error."""
        del valid_row["FINDING_UID"]

        with pytest.raises(CSVParseError) as exc_info:
            CSVFinding.from_row(valid_row, row_num=2)

        assert "FINDING_UID" in str(exc_info.value)

    def test_from_row_missing_provider_raises_error(self, valid_row):
        """Test that missing PROVIDER raises error."""
        del valid_row["PROVIDER"]

        with pytest.raises(CSVParseError) as exc_info:
            CSVFinding.from_row(valid_row, row_num=2)

        assert "PROVIDER" in str(exc_info.value)

    def test_from_row_normalizes_severity(self, valid_row):
        """Test that severity is normalized to lowercase."""
        valid_row["SEVERITY"] = "HIGH"

        finding = CSVFinding.from_row(valid_row)

        assert finding.severity == "high"

    def test_from_row_normalizes_status(self, valid_row):
        """Test that status is normalized to uppercase."""
        valid_row["STATUS"] = "pass"

        finding = CSVFinding.from_row(valid_row)

        assert finding.status == "PASS"


class TestCSVResourceFromRow:
    """
    Tests for CSVResource.from_row method.

    The from_row class method constructs a CSVResource from a dictionary
    representing a CSV row. It validates the required RESOURCE_UID field
    and provides defaults for optional fields.

    Test Coverage:
        - Valid row parsing with all fields
        - Missing RESOURCE_UID raises error
        - Name defaults to UID when not provided
    """

    def test_from_row_valid(self):
        """Test creating CSVResource from valid row."""
        row = {
            "RESOURCE_UID": "arn:aws:s3:::my-bucket",
            "RESOURCE_NAME": "my-bucket",
            "REGION": "us-east-1",
            "SERVICE_NAME": "s3",
            "RESOURCE_TYPE": "bucket",
        }

        resource = CSVResource.from_row(row)

        assert resource.uid == "arn:aws:s3:::my-bucket"
        assert resource.name == "my-bucket"
        assert resource.region == "us-east-1"
        assert resource.service == "s3"
        assert resource.type == "bucket"

    def test_from_row_missing_uid_raises_error(self):
        """Test that missing RESOURCE_UID raises error."""
        row = {"RESOURCE_NAME": "my-bucket"}

        with pytest.raises(CSVParseError) as exc_info:
            CSVResource.from_row(row, row_num=2)

        assert "RESOURCE_UID" in str(exc_info.value)

    def test_from_row_defaults_name_to_uid(self):
        """Test that name defaults to uid when not provided."""
        row = {"RESOURCE_UID": "resource-123"}

        resource = CSVResource.from_row(row)

        assert resource.name == "resource-123"


class TestRequiredColumnValidation:
    """
    Tests for required CSV column validation.

    The CSV parser validates that all required columns are present in the
    CSV headers and that required field values are not empty in data rows.

    Required columns: FINDING_UID, PROVIDER, CHECK_ID, STATUS, ACCOUNT_UID

    Test Coverage:
        - Missing required column in headers raises error
        - Multiple missing columns are reported
        - Empty required field value raises error
        - Whitespace-only required field value raises error
        - validate_csv_structure detects missing columns
        - validate_csv_content detects missing column values
    """

    def test_parse_csv_missing_finding_uid_column_raises_error(self):
        """Test that missing FINDING_UID column raises CSVParseError."""
        csv_data = """PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
aws;check_1;PASS;123456789012;resource-1"""
        content = csv_data.encode("utf-8")

        with pytest.raises(CSVParseError) as exc_info:
            parse_csv(content)

        assert "FINDING_UID" in str(exc_info.value)
        assert "Missing required CSV columns" in str(exc_info.value)

    def test_parse_csv_missing_provider_column_raises_error(self):
        """Test that missing PROVIDER column raises CSVParseError."""
        csv_data = """FINDING_UID;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
finding-001;check_1;PASS;123456789012;resource-1"""
        content = csv_data.encode("utf-8")

        with pytest.raises(CSVParseError) as exc_info:
            parse_csv(content)

        assert "PROVIDER" in str(exc_info.value)

    def test_parse_csv_missing_check_id_column_raises_error(self):
        """Test that missing CHECK_ID column raises CSVParseError."""
        csv_data = """FINDING_UID;PROVIDER;STATUS;ACCOUNT_UID;RESOURCE_UID
finding-001;aws;PASS;123456789012;resource-1"""
        content = csv_data.encode("utf-8")

        with pytest.raises(CSVParseError) as exc_info:
            parse_csv(content)

        assert "CHECK_ID" in str(exc_info.value)

    def test_parse_csv_missing_status_column_raises_error(self):
        """Test that missing STATUS column raises CSVParseError."""
        csv_data = """FINDING_UID;PROVIDER;CHECK_ID;ACCOUNT_UID;RESOURCE_UID
finding-001;aws;check_1;123456789012;resource-1"""
        content = csv_data.encode("utf-8")

        with pytest.raises(CSVParseError) as exc_info:
            parse_csv(content)

        assert "STATUS" in str(exc_info.value)

    def test_parse_csv_missing_account_uid_column_raises_error(self):
        """Test that missing ACCOUNT_UID column raises CSVParseError."""
        csv_data = """FINDING_UID;PROVIDER;CHECK_ID;STATUS;RESOURCE_UID
finding-001;aws;check_1;PASS;resource-1"""
        content = csv_data.encode("utf-8")

        with pytest.raises(CSVParseError) as exc_info:
            parse_csv(content)

        assert "ACCOUNT_UID" in str(exc_info.value)

    def test_parse_csv_missing_multiple_columns_reports_all(self):
        """Test that multiple missing columns are all reported."""
        csv_data = """RESOURCE_UID;REGION
resource-1;us-east-1"""
        content = csv_data.encode("utf-8")

        with pytest.raises(CSVParseError) as exc_info:
            parse_csv(content)

        error_msg = str(exc_info.value)
        assert "FINDING_UID" in error_msg
        assert "PROVIDER" in error_msg
        assert "CHECK_ID" in error_msg
        assert "STATUS" in error_msg
        assert "ACCOUNT_UID" in error_msg

    def test_validate_csv_structure_missing_column_returns_error(self):
        """Test that validate_csv_structure detects missing required columns."""
        csv_data = """PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
aws;check_1;PASS;123456789012;resource-1"""
        content = csv_data.encode("utf-8")

        is_valid, error = validate_csv_structure(content)

        assert is_valid is False
        assert error is not None
        assert "FINDING_UID" in error

    def test_validate_csv_structure_empty_required_value_returns_error(self):
        """Test that validate_csv_structure detects empty required field values."""
        csv_data = """FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
;aws;check_1;PASS;123456789012;resource-1"""
        content = csv_data.encode("utf-8")

        is_valid, error = validate_csv_structure(content)

        assert is_valid is False
        assert error is not None
        assert "FINDING_UID" in error

    def test_validate_csv_content_missing_column_adds_error(self):
        """Test that validate_csv_content adds error for missing columns."""
        csv_data = """PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
aws;check_1;PASS;123456789012;resource-1"""
        content = csv_data.encode("utf-8")

        result = validate_csv_content(content)

        assert result.is_valid is False
        assert len(result.errors) > 0
        error_fields = [e.field for e in result.errors]
        assert "FINDING_UID" in error_fields

    def test_validate_csv_content_empty_required_value_adds_error(self):
        """Test that validate_csv_content adds error for empty required values."""
        csv_data = """FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
finding-001;aws;check_1;PASS;123456789012;resource-1
;aws;check_2;FAIL;123456789012;resource-2"""
        content = csv_data.encode("utf-8")

        result = validate_csv_content(content)

        assert result.is_valid is False
        error_messages = [e.message for e in result.errors]
        assert any("FINDING_UID" in msg for msg in error_messages)

    def test_validate_csv_content_whitespace_only_value_adds_error(self):
        """Test that validate_csv_content treats whitespace-only as empty."""
        csv_data = """FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
   ;aws;check_1;PASS;123456789012;resource-1"""
        content = csv_data.encode("utf-8")

        result = validate_csv_content(content)

        assert result.is_valid is False
        error_messages = [e.message for e in result.errors]
        assert any("FINDING_UID" in msg for msg in error_messages)

    def test_parse_csv_empty_finding_uid_value_raises_error(self):
        """Test that empty FINDING_UID value in row raises error."""
        csv_data = """FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
;aws;check_1;PASS;123456789012;resource-1"""
        content = csv_data.encode("utf-8")

        with pytest.raises(CSVParseError) as exc_info:
            parse_csv(content)

        assert "FINDING_UID" in str(exc_info.value)

    def test_parse_csv_empty_check_id_value_raises_error(self):
        """Test that empty CHECK_ID value in row raises error."""
        csv_data = """FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
finding-001;aws;;PASS;123456789012;resource-1"""
        content = csv_data.encode("utf-8")

        with pytest.raises(CSVParseError) as exc_info:
            parse_csv(content)

        assert "CHECK_ID" in str(exc_info.value)

    def test_parse_csv_empty_account_uid_value_raises_error(self):
        """Test that empty ACCOUNT_UID value in row raises error."""
        csv_data = """FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
finding-001;aws;check_1;PASS;;resource-1"""
        content = csv_data.encode("utf-8")

        with pytest.raises(CSVParseError) as exc_info:
            parse_csv(content)

        assert "ACCOUNT_UID" in str(exc_info.value)


class TestParseTimestamp:
    """
    Tests for _parse_timestamp function.

    The timestamp parsing supports multiple formats:
    - ISO 8601 with microseconds: "2025-02-14T14:27:03.913874"
    - Space-separated with microseconds: "2025-02-14 14:27:03.913874"
    - ISO 8601 without microseconds: "2025-02-14T14:27:03"
    - Space-separated without microseconds: "2025-02-14 14:27:03"
    - Date only: "2025-02-14"

    Test Coverage:
        - ISO 8601 format with microseconds
        - Space-separated format with microseconds
        - ISO 8601 format without microseconds
        - Date only format
        - Empty string returns None
        - Invalid format returns None
    """

    def test_parse_iso8601_with_microseconds(self):
        """Test parsing ISO 8601 timestamp with microseconds."""
        timestamp_str = "2025-02-14T14:27:03.913874"

        result = _parse_timestamp(timestamp_str)

        assert result is not None
        assert isinstance(result, datetime)
        assert result.year == 2025
        assert result.month == 2
        assert result.day == 14
        assert result.hour == 14
        assert result.minute == 27
        assert result.second == 3

    def test_parse_space_separated_with_microseconds(self):
        """Test parsing space-separated timestamp with microseconds."""
        timestamp_str = "2025-02-14 14:27:03.913874"

        result = _parse_timestamp(timestamp_str)

        assert result is not None
        assert result.year == 2025
        assert result.month == 2
        assert result.day == 14

    def test_parse_iso8601_without_microseconds(self):
        """Test parsing ISO 8601 timestamp without microseconds."""
        timestamp_str = "2025-02-14T14:27:03"

        result = _parse_timestamp(timestamp_str)

        assert result is not None
        assert result.hour == 14
        assert result.minute == 27
        assert result.second == 3

    def test_parse_date_only(self):
        """Test parsing date-only timestamp."""
        timestamp_str = "2025-02-14"

        result = _parse_timestamp(timestamp_str)

        assert result is not None
        assert result.year == 2025
        assert result.month == 2
        assert result.day == 14

    def test_parse_empty_string_returns_none(self):
        """Test that empty string returns None."""
        result = _parse_timestamp("")

        assert result is None

    def test_parse_invalid_format_returns_none(self):
        """Test that invalid format returns None."""
        result = _parse_timestamp("not-a-timestamp")

        assert result is None


class TestMutedFieldParsing:
    """
    Tests for muted field parsing in CSVFinding.

    The muted field accepts various boolean representations:
    - "true", "1", "yes" -> True
    - Any other value -> False

    Test Coverage:
        - Muted field with "true" value
        - Muted field with "1" value
        - Muted field with "yes" value
        - Muted field with "false" value
        - Muted field with empty value
        - Muted field case insensitivity
    """

    @pytest.fixture
    def base_row(self):
        """Return a base CSV row with all required fields."""
        return {
            "FINDING_UID": "finding-123",
            "PROVIDER": "aws",
            "CHECK_ID": "check_1",
            "STATUS": "FAIL",
            "ACCOUNT_UID": "123456789012",
            "SEVERITY": "low",
            "RESOURCE_UID": "resource-1",
        }

    def test_muted_true_string(self, base_row):
        """Test muted field with 'true' value."""
        base_row["MUTED"] = "true"

        finding = CSVFinding.from_row(base_row)

        assert finding.muted is True

    def test_muted_one_string(self, base_row):
        """Test muted field with '1' value."""
        base_row["MUTED"] = "1"

        finding = CSVFinding.from_row(base_row)

        assert finding.muted is True

    def test_muted_yes_string(self, base_row):
        """Test muted field with 'yes' value."""
        base_row["MUTED"] = "yes"

        finding = CSVFinding.from_row(base_row)

        assert finding.muted is True

    def test_muted_false_string(self, base_row):
        """Test muted field with 'false' value."""
        base_row["MUTED"] = "false"

        finding = CSVFinding.from_row(base_row)

        assert finding.muted is False

    def test_muted_empty_string(self, base_row):
        """Test muted field with empty value."""
        base_row["MUTED"] = ""

        finding = CSVFinding.from_row(base_row)

        assert finding.muted is False

    def test_muted_case_insensitive(self, base_row):
        """Test muted field is case insensitive."""
        base_row["MUTED"] = "TRUE"

        finding = CSVFinding.from_row(base_row)

        assert finding.muted is True


class TestExtractProviderInfo:
    """
    Tests for extract_provider_info function.

    The function extracts provider type and account UID from the first finding
    in a list of parsed CSV findings.

    Test Coverage:
        - Extract from single finding
        - Extract from multiple findings (uses first)
        - Empty list returns None
    """

    def test_extract_from_single_finding(self):
        """Test extracting provider info from single finding."""
        csv_data = """FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
finding-001;aws;check_1;PASS;123456789012;resource-1"""
        content = csv_data.encode("utf-8")

        findings = parse_csv(content)
        result = extract_provider_info(findings)

        assert result is not None
        assert result == ("aws", "123456789012")

    def test_extract_from_multiple_findings(self):
        """Test extracting provider info from multiple findings (uses first)."""
        csv_data = """FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
finding-001;aws;check_1;PASS;123456789012;resource-1
finding-002;azure;check_2;FAIL;subscription-123;resource-2"""
        content = csv_data.encode("utf-8")

        findings = parse_csv(content)
        result = extract_provider_info(findings)

        assert result is not None
        assert result == ("aws", "123456789012")

    def test_extract_from_empty_list_returns_none(self):
        """Test extracting provider info from empty list returns None."""
        result = extract_provider_info([])

        assert result is None


class TestHelperFunctions:
    """
    Tests for helper functions that return constants.

    These functions provide access to the parser's configuration constants
    in a sorted list format.

    Test Coverage:
        - get_supported_provider_types returns sorted list
        - get_valid_severity_levels returns sorted list
        - get_valid_status_codes returns sorted list
        - get_required_csv_columns returns sorted list
        - get_expected_csv_columns returns sorted list
        - Constants are immutable frozen sets
    """

    def test_get_supported_provider_types_returns_sorted_list(self):
        """Test get_supported_provider_types returns sorted list."""
        providers = get_supported_provider_types()

        assert isinstance(providers, list)
        assert "aws" in providers
        assert "azure" in providers
        assert "gcp" in providers
        assert providers == sorted(providers)

    def test_get_valid_severity_levels_returns_sorted_list(self):
        """Test get_valid_severity_levels returns sorted list."""
        severities = get_valid_severity_levels()

        assert isinstance(severities, list)
        assert "critical" in severities
        assert "high" in severities
        assert "low" in severities
        assert severities == sorted(severities)

    def test_get_valid_status_codes_returns_sorted_list(self):
        """Test get_valid_status_codes returns sorted list."""
        statuses = get_valid_status_codes()

        assert isinstance(statuses, list)
        assert "PASS" in statuses
        assert "FAIL" in statuses
        assert "MANUAL" in statuses
        assert statuses == sorted(statuses)

    def test_get_required_csv_columns_returns_sorted_list(self):
        """Test get_required_csv_columns returns sorted list."""
        columns = get_required_csv_columns()

        assert isinstance(columns, list)
        assert "FINDING_UID" in columns
        assert "PROVIDER" in columns
        assert "CHECK_ID" in columns
        assert "STATUS" in columns
        assert "ACCOUNT_UID" in columns
        assert columns == sorted(columns)

    def test_get_expected_csv_columns_returns_sorted_list(self):
        """Test get_expected_csv_columns returns sorted list."""
        columns = get_expected_csv_columns()

        assert isinstance(columns, list)
        assert "FINDING_UID" in columns
        assert "COMPLIANCE" in columns
        assert "TIMESTAMP" in columns
        assert columns == sorted(columns)

    def test_constants_are_frozen_sets(self):
        """Test that constants are immutable frozen sets."""
        assert isinstance(SUPPORTED_PROVIDER_TYPES, frozenset)
        assert isinstance(VALID_SEVERITY_LEVELS, frozenset)
        assert isinstance(VALID_STATUS_CODES, frozenset)
        assert isinstance(REQUIRED_CSV_COLUMNS, frozenset)
        assert isinstance(EXPECTED_CSV_COLUMNS, frozenset)


class TestEmptyAndInvalidContent:
    """
    Tests for edge cases with empty or invalid content.

    Test Coverage:
        - Empty CSV content raises error
        - Invalid UTF-8 encoding raises error
        - CSV with only headers (no data rows) is valid
        - Whitespace-only content raises error
    """

    def test_parse_csv_empty_content_raises_error(self):
        """Test that empty content raises CSVParseError."""
        content = b""

        with pytest.raises(CSVParseError) as exc_info:
            parse_csv(content)

        assert "empty" in str(exc_info.value).lower()

    def test_parse_csv_invalid_utf8_raises_error(self):
        """Test that invalid UTF-8 encoding raises CSVParseError."""
        content = b"\xff\xfe"

        with pytest.raises(CSVParseError) as exc_info:
            parse_csv(content)

        assert "UTF-8" in str(exc_info.value)

    def test_parse_csv_headers_only_returns_empty_list(self):
        """Test that CSV with only headers returns empty list."""
        csv_data = """FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID"""
        content = csv_data.encode("utf-8")

        findings = parse_csv(content)

        assert findings == []

    def test_parse_csv_whitespace_only_raises_error(self):
        """Test that whitespace-only content raises CSVParseError."""
        content = b"   \n\t\n   "

        with pytest.raises(CSVParseError) as exc_info:
            parse_csv(content)

        assert (
            "empty" in str(exc_info.value).lower()
            or "no headers" in str(exc_info.value).lower()
        )

    def test_validate_csv_structure_empty_content_returns_error(self):
        """Test that validate_csv_structure returns error for empty content."""
        content = b""

        is_valid, error = validate_csv_structure(content)

        assert is_valid is False
        assert error is not None
        assert "empty" in error.lower()

    def test_validate_csv_structure_invalid_utf8_returns_error(self):
        """Test that validate_csv_structure returns error for invalid UTF-8."""
        content = b"\xff\xfe"

        is_valid, error = validate_csv_structure(content)

        assert is_valid is False
        assert error is not None
        assert "UTF-8" in error

    def test_validate_csv_content_empty_content_adds_error(self):
        """Test that validate_csv_content adds error for empty content."""
        content = b""

        result = validate_csv_content(content)

        assert result.is_valid is False
        assert len(result.errors) > 0


class TestTimestampInFinding:
    """
    Tests for timestamp field in CSVFinding.

    Test Coverage:
        - Finding with valid timestamp
        - Finding without timestamp
        - Finding with invalid timestamp
    """

    @pytest.fixture
    def base_row(self):
        """Return a base CSV row with all required fields."""
        return {
            "FINDING_UID": "finding-123",
            "PROVIDER": "aws",
            "CHECK_ID": "check_1",
            "STATUS": "FAIL",
            "ACCOUNT_UID": "123456789012",
            "SEVERITY": "low",
            "RESOURCE_UID": "resource-1",
        }

    def test_finding_with_valid_timestamp(self, base_row):
        """Test creating finding with valid timestamp."""
        base_row["TIMESTAMP"] = "2025-02-14T14:27:03.913874"

        finding = CSVFinding.from_row(base_row)

        assert finding.timestamp is not None
        assert finding.timestamp.year == 2025
        assert finding.timestamp.month == 2
        assert finding.timestamp.day == 14

    def test_finding_without_timestamp(self, base_row):
        """Test creating finding without timestamp."""
        finding = CSVFinding.from_row(base_row)

        assert finding.timestamp is None

    def test_finding_with_invalid_timestamp(self, base_row):
        """Test creating finding with invalid timestamp (returns None)."""
        base_row["TIMESTAMP"] = "not-a-timestamp"

        finding = CSVFinding.from_row(base_row)

        assert finding.timestamp is None


class TestProviderTypeValidation:
    """
    Tests for provider type validation in CSV parsing.

    Test Coverage:
        - All supported provider types are accepted
        - Unknown provider types are accepted with warning (not error)
        - Provider type is normalized to lowercase
    """

    @pytest.fixture
    def base_row(self):
        """Return a base CSV row with all required fields."""
        return {
            "FINDING_UID": "finding-123",
            "CHECK_ID": "check_1",
            "STATUS": "FAIL",
            "ACCOUNT_UID": "123456789012",
            "SEVERITY": "low",
            "RESOURCE_UID": "resource-1",
        }

    def test_aws_provider_accepted(self, base_row):
        """Test that AWS provider is accepted."""
        base_row["PROVIDER"] = "aws"

        finding = CSVFinding.from_row(base_row)

        assert finding.provider_type == "aws"

    def test_azure_provider_accepted(self, base_row):
        """Test that Azure provider is accepted."""
        base_row["PROVIDER"] = "azure"

        finding = CSVFinding.from_row(base_row)

        assert finding.provider_type == "azure"

    def test_gcp_provider_accepted(self, base_row):
        """Test that GCP provider is accepted."""
        base_row["PROVIDER"] = "gcp"

        finding = CSVFinding.from_row(base_row)

        assert finding.provider_type == "gcp"

    def test_kubernetes_provider_accepted(self, base_row):
        """Test that Kubernetes provider is accepted."""
        base_row["PROVIDER"] = "kubernetes"

        finding = CSVFinding.from_row(base_row)

        assert finding.provider_type == "kubernetes"

    def test_provider_normalized_to_lowercase(self, base_row):
        """Test that provider type is normalized to lowercase."""
        base_row["PROVIDER"] = "AWS"

        finding = CSVFinding.from_row(base_row)

        assert finding.provider_type == "aws"

    def test_unknown_provider_accepted_with_warning(self, base_row):
        """Test that unknown provider is accepted (logs warning but doesn't fail)."""
        base_row["PROVIDER"] = "unknown_provider"

        # Should not raise an error
        finding = CSVFinding.from_row(base_row)

        assert finding.provider_type == "unknown_provider"


class TestSeverityValidation:
    """
    Tests for severity validation in CSV parsing.

    Test Coverage:
        - All valid severity levels are accepted
        - Unknown severity defaults to 'informational'
        - Severity is normalized to lowercase
    """

    @pytest.fixture
    def base_row(self):
        """Return a base CSV row with all required fields."""
        return {
            "FINDING_UID": "finding-123",
            "PROVIDER": "aws",
            "CHECK_ID": "check_1",
            "STATUS": "FAIL",
            "ACCOUNT_UID": "123456789012",
            "RESOURCE_UID": "resource-1",
        }

    def test_critical_severity_accepted(self, base_row):
        """Test that critical severity is accepted."""
        base_row["SEVERITY"] = "critical"

        finding = CSVFinding.from_row(base_row)

        assert finding.severity == "critical"

    def test_high_severity_accepted(self, base_row):
        """Test that high severity is accepted."""
        base_row["SEVERITY"] = "high"

        finding = CSVFinding.from_row(base_row)

        assert finding.severity == "high"

    def test_unknown_severity_defaults_to_informational(self, base_row):
        """Test that unknown severity defaults to informational."""
        base_row["SEVERITY"] = "unknown_severity"

        finding = CSVFinding.from_row(base_row)

        assert finding.severity == "informational"

    def test_severity_normalized_to_lowercase(self, base_row):
        """Test that severity is normalized to lowercase."""
        base_row["SEVERITY"] = "HIGH"

        finding = CSVFinding.from_row(base_row)

        assert finding.severity == "high"


class TestStatusValidation:
    """
    Tests for status validation in CSV parsing.

    Test Coverage:
        - All valid status codes are accepted
        - Unknown status defaults to 'MANUAL'
        - Status is normalized to uppercase
    """

    @pytest.fixture
    def base_row(self):
        """Return a base CSV row with all required fields."""
        return {
            "FINDING_UID": "finding-123",
            "PROVIDER": "aws",
            "CHECK_ID": "check_1",
            "ACCOUNT_UID": "123456789012",
            "SEVERITY": "low",
            "RESOURCE_UID": "resource-1",
        }

    def test_pass_status_accepted(self, base_row):
        """Test that PASS status is accepted."""
        base_row["STATUS"] = "PASS"

        finding = CSVFinding.from_row(base_row)

        assert finding.status == "PASS"

    def test_fail_status_accepted(self, base_row):
        """Test that FAIL status is accepted."""
        base_row["STATUS"] = "FAIL"

        finding = CSVFinding.from_row(base_row)

        assert finding.status == "FAIL"

    def test_manual_status_accepted(self, base_row):
        """Test that MANUAL status is accepted."""
        base_row["STATUS"] = "MANUAL"

        finding = CSVFinding.from_row(base_row)

        assert finding.status == "MANUAL"

    def test_unknown_status_defaults_to_manual(self, base_row):
        """Test that unknown status defaults to MANUAL."""
        base_row["STATUS"] = "UNKNOWN"

        finding = CSVFinding.from_row(base_row)

        assert finding.status == "MANUAL"

    def test_status_normalized_to_uppercase(self, base_row):
        """Test that status is normalized to uppercase."""
        base_row["STATUS"] = "pass"

        finding = CSVFinding.from_row(base_row)

        assert finding.status == "PASS"
