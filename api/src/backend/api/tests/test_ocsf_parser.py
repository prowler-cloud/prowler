"""
Unit tests for the OCSF parser module.

Tests parsing of Prowler CLI JSON/OCSF output format.
"""

import json
from datetime import datetime

import pytest

from api.parsers.ocsf_parser import (
    OCSFCheckMetadata,
    OCSFFinding,
    OCSFParseError,
    OCSFResource,
    OCSFValidationError,
    OCSFValidationResult,
    SUPPORTED_PROVIDER_TYPES,
    VALID_SEVERITY_LEVELS,
    VALID_STATUS_CODES,
    extract_provider_info,
    get_supported_provider_types,
    get_valid_severity_levels,
    get_valid_status_codes,
    parse_ocsf_json,
    validate_ocsf_content,
    validate_ocsf_finding,
    validate_ocsf_structure,
)


class TestOCSFResource:
    """Tests for OCSFResource dataclass."""

    def test_from_dict_valid_resource(self):
        """Test parsing a valid resource."""
        data = {
            "uid": "arn:aws:s3:::my-bucket",
            "name": "my-bucket",
            "region": "us-east-1",
            "group": {"name": "s3"},
            "type": "bucket",
            "cloud_partition": "aws",
            "labels": ["production"],
            "data": {"details": "test"},
        }

        resource = OCSFResource.from_dict(data)

        assert resource.uid == "arn:aws:s3:::my-bucket"
        assert resource.name == "my-bucket"
        assert resource.region == "us-east-1"
        assert resource.service == "s3"
        assert resource.type == "bucket"
        assert resource.cloud_partition == "aws"
        assert resource.labels == ["production"]
        assert resource.data == {"details": "test"}

    def test_from_dict_minimal_resource(self):
        """Test parsing a resource with only required fields."""
        data = {"uid": "resource-123"}

        resource = OCSFResource.from_dict(data)

        assert resource.uid == "resource-123"
        assert resource.name == "resource-123"  # Defaults to uid
        assert resource.region == ""
        assert resource.service == ""
        assert resource.type == ""

    def test_from_dict_missing_uid_raises_error(self):
        """Test that missing uid raises OCSFParseError."""
        data = {"name": "my-resource"}

        with pytest.raises(OCSFParseError) as exc_info:
            OCSFResource.from_dict(data, index=5)

        assert "uid" in str(exc_info.value)
        assert exc_info.value.index == 5


class TestOCSFFinding:
    """Tests for OCSFFinding dataclass."""

    @pytest.fixture
    def valid_finding_data(self):
        """Return valid OCSF finding data."""
        return {
            "message": "IAM Access Analyzer is not enabled.",
            "metadata": {
                "event_code": "accessanalyzer_enabled",
                "product": {"name": "Prowler", "version": "5.0.0"},
            },
            "severity": "Low",
            "status_code": "FAIL",
            "status_detail": "IAM Access Analyzer is not enabled.",
            "finding_info": {
                "uid": "finding-123",
                "title": "Check if IAM Access Analyzer is enabled",
                "desc": "Check if IAM Access Analyzer is enabled",
                "types": ["IAM"],
            },
            "cloud": {
                "provider": "aws",
                "account": {"uid": "123456789012", "name": "Production"},
                "region": "us-east-1",
            },
            "resources": [
                {
                    "uid": "arn:aws:accessanalyzer:us-east-1:123456789012:analyzer",
                    "name": "analyzer",
                    "region": "us-east-1",
                    "group": {"name": "accessanalyzer"},
                    "type": "Other",
                }
            ],
            "remediation": {
                "desc": "Enable IAM Access Analyzer",
                "references": ["https://docs.aws.amazon.com/"],
            },
            "risk_details": "IAM Access Analyzer helps identify resources.",
            "unmapped": {
                "compliance": {"CIS-1.4": ["1.20"], "CIS-1.5": ["1.20"]},
                "categories": ["security"],
                "related_url": "https://docs.aws.amazon.com/",
            },
            "time": 1739539623,
            "time_dt": "2025-02-14T14:27:03.913874",
        }

    def test_from_dict_valid_finding(self, valid_finding_data):
        """Test parsing a valid finding."""
        finding = OCSFFinding.from_dict(valid_finding_data)

        assert finding.uid == "finding-123"
        assert finding.check_id == "accessanalyzer_enabled"
        assert finding.severity == "low"
        assert finding.status == "FAIL"
        assert finding.status_extended == "IAM Access Analyzer is not enabled."
        assert finding.provider_type == "aws"
        assert finding.account_uid == "123456789012"
        assert finding.account_name == "Production"
        assert len(finding.resources) == 1
        assert finding.resources[0].uid == "arn:aws:accessanalyzer:us-east-1:123456789012:analyzer"
        assert finding.compliance == {"CIS-1.4": ["1.20"], "CIS-1.5": ["1.20"]}
        assert finding.check_metadata.title == "Check if IAM Access Analyzer is enabled"
        assert finding.check_metadata.risk == "IAM Access Analyzer helps identify resources."

    def test_from_dict_missing_event_code_raises_error(self, valid_finding_data):
        """Test that missing event_code raises OCSFParseError."""
        del valid_finding_data["metadata"]["event_code"]

        with pytest.raises(OCSFParseError) as exc_info:
            OCSFFinding.from_dict(valid_finding_data)

        assert "metadata.event_code" in str(exc_info.value)

    def test_from_dict_missing_finding_uid_raises_error(self, valid_finding_data):
        """Test that missing finding_info.uid raises OCSFParseError."""
        del valid_finding_data["finding_info"]["uid"]

        with pytest.raises(OCSFParseError) as exc_info:
            OCSFFinding.from_dict(valid_finding_data)

        assert "finding_info.uid" in str(exc_info.value)

    def test_from_dict_missing_provider_raises_error(self, valid_finding_data):
        """Test that missing cloud.provider raises OCSFParseError."""
        del valid_finding_data["cloud"]["provider"]

        with pytest.raises(OCSFParseError) as exc_info:
            OCSFFinding.from_dict(valid_finding_data)

        assert "cloud.provider" in str(exc_info.value)

    def test_from_dict_missing_account_uid_raises_error(self, valid_finding_data):
        """Test that missing cloud.account.uid raises OCSFParseError."""
        del valid_finding_data["cloud"]["account"]["uid"]

        with pytest.raises(OCSFParseError) as exc_info:
            OCSFFinding.from_dict(valid_finding_data)

        assert "cloud.account.uid" in str(exc_info.value)

    def test_from_dict_normalizes_severity(self, valid_finding_data):
        """Test that severity is normalized to lowercase."""
        valid_finding_data["severity"] = "HIGH"

        finding = OCSFFinding.from_dict(valid_finding_data)

        assert finding.severity == "high"

    def test_from_dict_normalizes_status(self, valid_finding_data):
        """Test that status is normalized to uppercase."""
        valid_finding_data["status_code"] = "pass"

        finding = OCSFFinding.from_dict(valid_finding_data)

        assert finding.status == "PASS"

    def test_from_dict_unknown_status_defaults_to_manual(self, valid_finding_data):
        """Test that unknown status defaults to MANUAL."""
        valid_finding_data["status_code"] = "UNKNOWN"

        finding = OCSFFinding.from_dict(valid_finding_data)

        assert finding.status == "MANUAL"

    def test_from_dict_parses_timestamp(self, valid_finding_data):
        """Test that timestamp is parsed correctly."""
        finding = OCSFFinding.from_dict(valid_finding_data)

        assert finding.timestamp is not None
        assert isinstance(finding.timestamp, datetime)

    def test_from_dict_handles_missing_optional_fields(self, valid_finding_data):
        """Test parsing with missing optional fields."""
        del valid_finding_data["remediation"]
        del valid_finding_data["risk_details"]
        del valid_finding_data["unmapped"]

        finding = OCSFFinding.from_dict(valid_finding_data)

        assert finding.check_metadata.remediation_description == ""
        assert finding.check_metadata.risk == ""
        assert finding.compliance == {}



class TestParseOCSFJson:
    """Tests for parse_ocsf_json function."""

    @pytest.fixture
    def valid_ocsf_content(self):
        """Return valid OCSF JSON content as bytes."""
        data = [
            {
                "message": "Finding 1",
                "metadata": {"event_code": "check_1"},
                "severity": "Low",
                "status_code": "FAIL",
                "status_detail": "Finding 1 detail",
                "finding_info": {"uid": "finding-1", "title": "Check 1", "desc": "Desc 1"},
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "123456789012", "name": "Test"},
                },
                "resources": [],
            },
            {
                "message": "Finding 2",
                "metadata": {"event_code": "check_2"},
                "severity": "High",
                "status_code": "PASS",
                "status_detail": "Finding 2 detail",
                "finding_info": {"uid": "finding-2", "title": "Check 2", "desc": "Desc 2"},
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "123456789012", "name": "Test"},
                },
                "resources": [],
            },
        ]
        return json.dumps(data).encode("utf-8")

    def test_parse_valid_ocsf_json(self, valid_ocsf_content):
        """Test parsing valid OCSF JSON."""
        findings = parse_ocsf_json(valid_ocsf_content)

        assert len(findings) == 2
        assert findings[0].check_id == "check_1"
        assert findings[0].severity == "low"
        assert findings[1].check_id == "check_2"
        assert findings[1].severity == "high"

    def test_parse_empty_array(self):
        """Test parsing empty array returns empty list."""
        content = b"[]"

        findings = parse_ocsf_json(content)

        assert findings == []

    def test_parse_invalid_json_raises_error(self):
        """Test that invalid JSON raises OCSFParseError."""
        content = b"not valid json"

        with pytest.raises(OCSFParseError) as exc_info:
            parse_ocsf_json(content)

        assert "Invalid JSON" in str(exc_info.value)

    def test_parse_non_array_raises_error(self):
        """Test that non-array JSON raises OCSFParseError."""
        content = b'{"key": "value"}'

        with pytest.raises(OCSFParseError) as exc_info:
            parse_ocsf_json(content)

        assert "expected a JSON array" in str(exc_info.value)

    def test_parse_invalid_utf8_raises_error(self):
        """Test that invalid UTF-8 raises OCSFParseError."""
        content = b"\xff\xfe"

        with pytest.raises(OCSFParseError) as exc_info:
            parse_ocsf_json(content)

        assert "Invalid UTF-8" in str(exc_info.value)

    def test_parse_partial_failures_returns_valid_findings(self):
        """Test that partial failures still return valid findings."""
        data = [
            {
                "message": "Valid finding",
                "metadata": {"event_code": "check_1"},
                "severity": "Low",
                "status_code": "FAIL",
                "finding_info": {"uid": "finding-1", "title": "Check 1", "desc": "Desc"},
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "123456789012"},
                },
            },
            {
                "message": "Invalid finding - missing required fields",
            },
        ]
        content = json.dumps(data).encode("utf-8")

        findings = parse_ocsf_json(content)

        assert len(findings) == 1
        assert findings[0].check_id == "check_1"

    def test_parse_all_invalid_raises_error(self):
        """Test that all invalid findings raises OCSFParseError."""
        data = [
            {"message": "Invalid 1"},
            {"message": "Invalid 2"},
        ]
        content = json.dumps(data).encode("utf-8")

        with pytest.raises(OCSFParseError) as exc_info:
            parse_ocsf_json(content)

        assert "Failed to parse any findings" in str(exc_info.value)


class TestValidateOCSFStructure:
    """Tests for validate_ocsf_structure function."""

    def test_valid_ocsf_structure(self):
        """Test validation of valid OCSF structure."""
        data = [
            {
                "metadata": {"event_code": "check_1"},
                "finding_info": {"uid": "finding-1"},
                "cloud": {"provider": "aws"},
            }
        ]
        content = json.dumps(data).encode("utf-8")

        is_valid, error = validate_ocsf_structure(content)

        assert is_valid is True
        assert error is None

    def test_empty_array_is_valid(self):
        """Test that empty array is valid."""
        content = b"[]"

        is_valid, error = validate_ocsf_structure(content)

        assert is_valid is True
        assert error is None

    def test_invalid_json(self):
        """Test validation of invalid JSON."""
        content = b"not json"

        is_valid, error = validate_ocsf_structure(content)

        assert is_valid is False
        assert "Invalid JSON" in error

    def test_non_array(self):
        """Test validation of non-array JSON."""
        content = b'{"key": "value"}'

        is_valid, error = validate_ocsf_structure(content)

        assert is_valid is False
        assert "Expected JSON array" in error

    def test_missing_required_fields(self):
        """Test validation with missing required fields."""
        data = [{"message": "test"}]
        content = json.dumps(data).encode("utf-8")

        is_valid, error = validate_ocsf_structure(content)

        assert is_valid is False
        assert "Missing required OCSF fields" in error

    def test_missing_event_code(self):
        """Test validation with missing event_code."""
        data = [
            {
                "metadata": {},
                "finding_info": {"uid": "finding-1"},
                "cloud": {"provider": "aws"},
            }
        ]
        content = json.dumps(data).encode("utf-8")

        is_valid, error = validate_ocsf_structure(content)

        assert is_valid is False
        assert "metadata.event_code" in error


class TestExtractProviderInfo:
    """Tests for extract_provider_info function."""

    def test_extract_provider_info(self):
        """Test extracting provider info from findings."""
        findings = [
            OCSFFinding(
                uid="finding-1",
                check_id="check_1",
                severity="low",
                status="FAIL",
                status_extended="Detail",
                message="Message",
                impact_extended="Impact",
                check_metadata=OCSFCheckMetadata(),
                compliance={},
                resources=[],
                provider_type="aws",
                account_uid="123456789012",
                account_name="Test",
            )
        ]

        result = extract_provider_info(findings)

        assert result == ("aws", "123456789012")

    def test_extract_provider_info_empty_list(self):
        """Test extracting provider info from empty list."""
        result = extract_provider_info([])

        assert result is None


class TestOCSFParseError:
    """Tests for OCSFParseError exception."""

    def test_error_message_basic(self):
        """Test basic error message."""
        error = OCSFParseError("Test error")

        assert str(error) == "Test error"

    def test_error_message_with_index(self):
        """Test error message with index."""
        error = OCSFParseError("Test error", index=5)

        assert "at index 5" in str(error)

    def test_error_message_with_field(self):
        """Test error message with field."""
        error = OCSFParseError("Test error", field="metadata.event_code")

        assert "metadata.event_code" in str(error)

    def test_error_message_with_all_params(self):
        """Test error message with all parameters."""
        error = OCSFParseError("Test error", index=3, field="cloud.provider")

        message = str(error)
        assert "Test error" in message
        assert "at index 3" in message
        assert "cloud.provider" in message


class TestOCSFValidationResult:
    """Tests for OCSFValidationResult dataclass."""

    def test_initial_state_is_valid(self):
        """Test that initial state is valid."""
        result = OCSFValidationResult(is_valid=True)

        assert result.is_valid is True
        assert result.errors == []
        assert result.warnings == []

    def test_add_error_sets_invalid(self):
        """Test that adding an error sets is_valid to False."""
        result = OCSFValidationResult(is_valid=True)

        result.add_error("Test error", "test.field")

        assert result.is_valid is False
        assert len(result.errors) == 1
        assert result.errors[0].message == "Test error"
        assert result.errors[0].field == "test.field"

    def test_add_warning_keeps_valid(self):
        """Test that adding a warning keeps is_valid True."""
        result = OCSFValidationResult(is_valid=True)

        result.add_warning("Test warning", "test.field")

        assert result.is_valid is True
        assert len(result.warnings) == 1

    def test_error_to_dict(self):
        """Test OCSFValidationError.to_dict()."""
        error = OCSFValidationError(
            message="Test error",
            field="test.field",
            index=5,
            value="test_value",
        )

        result = error.to_dict()

        assert result["message"] == "Test error"
        assert result["field"] == "test.field"
        assert result["index"] == 5
        assert result["value"] == "test_value"


class TestValidateOCSFFinding:
    """Tests for validate_ocsf_finding function."""

    @pytest.fixture
    def valid_finding_data(self):
        """Return valid OCSF finding data."""
        return {
            "message": "Test finding",
            "metadata": {"event_code": "test_check"},
            "severity": "Low",
            "status_code": "FAIL",
            "finding_info": {"uid": "finding-123", "title": "Test", "desc": "Desc"},
            "cloud": {
                "provider": "aws",
                "account": {"uid": "123456789012", "name": "Test"},
            },
            "resources": [{"uid": "resource-1", "name": "test-resource"}],
        }

    def test_valid_finding_passes(self, valid_finding_data):
        """Test that valid finding passes validation."""
        result = validate_ocsf_finding(valid_finding_data)

        assert result.is_valid is True
        assert len(result.errors) == 0

    def test_missing_metadata_fails(self, valid_finding_data):
        """Test that missing metadata fails validation."""
        del valid_finding_data["metadata"]

        result = validate_ocsf_finding(valid_finding_data)

        assert result.is_valid is False
        assert any("metadata" in e.field for e in result.errors)

    def test_missing_finding_info_fails(self, valid_finding_data):
        """Test that missing finding_info fails validation."""
        del valid_finding_data["finding_info"]

        result = validate_ocsf_finding(valid_finding_data)

        assert result.is_valid is False
        assert any("finding_info" in e.field for e in result.errors)

    def test_missing_cloud_fails(self, valid_finding_data):
        """Test that missing cloud fails validation."""
        del valid_finding_data["cloud"]

        result = validate_ocsf_finding(valid_finding_data)

        assert result.is_valid is False
        assert any("cloud" in e.field for e in result.errors)

    def test_missing_event_code_fails(self, valid_finding_data):
        """Test that missing event_code fails validation."""
        del valid_finding_data["metadata"]["event_code"]

        result = validate_ocsf_finding(valid_finding_data)

        assert result.is_valid is False
        assert any("metadata.event_code" in e.field for e in result.errors)

    def test_missing_finding_uid_fails(self, valid_finding_data):
        """Test that missing finding_info.uid fails validation."""
        del valid_finding_data["finding_info"]["uid"]

        result = validate_ocsf_finding(valid_finding_data)

        assert result.is_valid is False
        assert any("finding_info.uid" in e.field for e in result.errors)

    def test_missing_provider_fails(self, valid_finding_data):
        """Test that missing cloud.provider fails validation."""
        del valid_finding_data["cloud"]["provider"]

        result = validate_ocsf_finding(valid_finding_data)

        assert result.is_valid is False
        assert any("cloud.provider" in e.field for e in result.errors)

    def test_missing_account_uid_fails(self, valid_finding_data):
        """Test that missing cloud.account.uid fails validation."""
        del valid_finding_data["cloud"]["account"]["uid"]

        result = validate_ocsf_finding(valid_finding_data)

        assert result.is_valid is False
        assert any("cloud.account.uid" in e.field for e in result.errors)

    def test_unknown_provider_warns(self, valid_finding_data):
        """Test that unknown provider type generates warning."""
        valid_finding_data["cloud"]["provider"] = "unknown_provider"

        result = validate_ocsf_finding(valid_finding_data)

        assert result.is_valid is True  # Warning, not error
        assert len(result.warnings) > 0
        assert any("provider" in w.field for w in result.warnings)

    def test_unknown_provider_strict_fails(self, valid_finding_data):
        """Test that unknown provider type fails in strict mode."""
        valid_finding_data["cloud"]["provider"] = "unknown_provider"

        result = validate_ocsf_finding(valid_finding_data, strict=True)

        assert result.is_valid is False
        assert any("cloud.provider" in e.field for e in result.errors)

    def test_unknown_severity_warns(self, valid_finding_data):
        """Test that unknown severity generates warning."""
        valid_finding_data["severity"] = "UNKNOWN_SEVERITY"

        result = validate_ocsf_finding(valid_finding_data)

        assert result.is_valid is True
        assert any("severity" in w.field for w in result.warnings)

    def test_unknown_status_warns(self, valid_finding_data):
        """Test that unknown status_code generates warning."""
        valid_finding_data["status_code"] = "UNKNOWN_STATUS"

        result = validate_ocsf_finding(valid_finding_data)

        assert result.is_valid is True
        assert any("status_code" in w.field for w in result.warnings)

    def test_invalid_resources_type_fails(self, valid_finding_data):
        """Test that non-array resources fails validation."""
        valid_finding_data["resources"] = "not_an_array"

        result = validate_ocsf_finding(valid_finding_data)

        assert result.is_valid is False
        assert any("resources" in e.field for e in result.errors)

    def test_resource_missing_uid_fails(self, valid_finding_data):
        """Test that resource without uid fails validation."""
        valid_finding_data["resources"] = [{"name": "test"}]

        result = validate_ocsf_finding(valid_finding_data)

        assert result.is_valid is False
        assert any("resources[0].uid" in e.field for e in result.errors)


class TestValidateOCSFContent:
    """Tests for validate_ocsf_content function."""

    def test_valid_content_passes(self):
        """Test that valid OCSF content passes validation."""
        data = [
            {
                "metadata": {"event_code": "check_1"},
                "finding_info": {"uid": "finding-1"},
                "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
            }
        ]
        content = json.dumps(data).encode("utf-8")

        result = validate_ocsf_content(content)

        assert result.is_valid is True
        assert len(result.errors) == 0

    def test_invalid_utf8_fails(self):
        """Test that invalid UTF-8 fails validation."""
        content = b"\xff\xfe"

        result = validate_ocsf_content(content)

        assert result.is_valid is False
        assert any("UTF-8" in e.message for e in result.errors)

    def test_invalid_json_fails(self):
        """Test that invalid JSON fails validation."""
        content = b"not valid json"

        result = validate_ocsf_content(content)

        assert result.is_valid is False
        assert any("JSON" in e.message for e in result.errors)

    def test_non_array_fails(self):
        """Test that non-array JSON fails validation."""
        content = b'{"key": "value"}'

        result = validate_ocsf_content(content)

        assert result.is_valid is False
        assert any("array" in e.message for e in result.errors)

    def test_empty_array_warns(self):
        """Test that empty array generates warning."""
        content = b"[]"

        result = validate_ocsf_content(content)

        assert result.is_valid is True
        assert len(result.warnings) > 0

    def test_multiple_findings_validated(self):
        """Test that all findings are validated."""
        data = [
            {
                "metadata": {"event_code": "check_1"},
                "finding_info": {"uid": "finding-1"},
                "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
            },
            {
                "metadata": {},  # Missing event_code
                "finding_info": {"uid": "finding-2"},
                "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
            },
        ]
        content = json.dumps(data).encode("utf-8")

        result = validate_ocsf_content(content)

        assert result.is_valid is False
        assert any("metadata.event_code" in e.field for e in result.errors)

    def test_max_errors_limit(self):
        """Test that validation stops after max_errors."""
        # Create many invalid findings
        data = [{"invalid": i} for i in range(200)]
        content = json.dumps(data).encode("utf-8")

        result = validate_ocsf_content(content, max_errors=10)

        # Should have stopped early
        assert len(result.errors) <= 15  # Some buffer for the limit
        assert any("stopped" in w.message for w in result.warnings)


class TestHelperFunctions:
    """Tests for helper functions."""

    def test_get_supported_provider_types(self):
        """Test get_supported_provider_types returns sorted list."""
        providers = get_supported_provider_types()

        assert isinstance(providers, list)
        assert "aws" in providers
        assert "azure" in providers
        assert "gcp" in providers
        assert providers == sorted(providers)

    def test_get_valid_severity_levels(self):
        """Test get_valid_severity_levels returns sorted list."""
        severities = get_valid_severity_levels()

        assert isinstance(severities, list)
        assert "critical" in severities
        assert "high" in severities
        assert "low" in severities
        assert severities == sorted(severities)

    def test_get_valid_status_codes(self):
        """Test get_valid_status_codes returns sorted list."""
        statuses = get_valid_status_codes()

        assert isinstance(statuses, list)
        assert "PASS" in statuses
        assert "FAIL" in statuses
        assert "MANUAL" in statuses
        assert statuses == sorted(statuses)

    def test_constants_are_frozen_sets(self):
        """Test that constants are immutable frozen sets."""
        assert isinstance(SUPPORTED_PROVIDER_TYPES, frozenset)
        assert isinstance(VALID_SEVERITY_LEVELS, frozenset)
        assert isinstance(VALID_STATUS_CODES, frozenset)


class TestProviderTypeValidation:
    """Tests for provider type validation in parsing."""

    @pytest.fixture
    def base_finding_data(self):
        """Return base finding data for provider tests."""
        return {
            "message": "Test finding",
            "metadata": {"event_code": "test_check"},
            "severity": "Low",
            "status_code": "FAIL",
            "finding_info": {"uid": "finding-123", "title": "Test", "desc": "Desc"},
            "cloud": {
                "provider": "aws",
                "account": {"uid": "123456789012", "name": "Test"},
            },
            "resources": [],
        }

    def test_aws_provider_accepted(self, base_finding_data):
        """Test that AWS provider is accepted."""
        base_finding_data["cloud"]["provider"] = "aws"

        finding = OCSFFinding.from_dict(base_finding_data)

        assert finding.provider_type == "aws"

    def test_azure_provider_accepted(self, base_finding_data):
        """Test that Azure provider is accepted."""
        base_finding_data["cloud"]["provider"] = "azure"

        finding = OCSFFinding.from_dict(base_finding_data)

        assert finding.provider_type == "azure"

    def test_gcp_provider_accepted(self, base_finding_data):
        """Test that GCP provider is accepted."""
        base_finding_data["cloud"]["provider"] = "gcp"

        finding = OCSFFinding.from_dict(base_finding_data)

        assert finding.provider_type == "gcp"

    def test_kubernetes_provider_accepted(self, base_finding_data):
        """Test that Kubernetes provider is accepted."""
        base_finding_data["cloud"]["provider"] = "kubernetes"

        finding = OCSFFinding.from_dict(base_finding_data)

        assert finding.provider_type == "kubernetes"

    def test_provider_normalized_to_lowercase(self, base_finding_data):
        """Test that provider type is normalized to lowercase."""
        base_finding_data["cloud"]["provider"] = "AWS"

        finding = OCSFFinding.from_dict(base_finding_data)

        assert finding.provider_type == "aws"

    def test_unknown_provider_still_parses(self, base_finding_data):
        """Test that unknown provider still parses (with warning)."""
        base_finding_data["cloud"]["provider"] = "unknown_cloud"

        # Should not raise, just log warning
        finding = OCSFFinding.from_dict(base_finding_data)

        assert finding.provider_type == "unknown_cloud"


class TestSeverityValidation:
    """Tests for severity validation in parsing."""

    @pytest.fixture
    def base_finding_data(self):
        """Return base finding data for severity tests."""
        return {
            "message": "Test finding",
            "metadata": {"event_code": "test_check"},
            "severity": "Low",
            "status_code": "FAIL",
            "finding_info": {"uid": "finding-123", "title": "Test", "desc": "Desc"},
            "cloud": {
                "provider": "aws",
                "account": {"uid": "123456789012", "name": "Test"},
            },
            "resources": [],
        }

    def test_critical_severity_accepted(self, base_finding_data):
        """Test that critical severity is accepted."""
        base_finding_data["severity"] = "critical"

        finding = OCSFFinding.from_dict(base_finding_data)

        assert finding.severity == "critical"

    def test_high_severity_accepted(self, base_finding_data):
        """Test that high severity is accepted."""
        base_finding_data["severity"] = "high"

        finding = OCSFFinding.from_dict(base_finding_data)

        assert finding.severity == "high"

    def test_unknown_severity_defaults_to_informational(self, base_finding_data):
        """Test that unknown severity defaults to informational."""
        base_finding_data["severity"] = "UNKNOWN"

        finding = OCSFFinding.from_dict(base_finding_data)

        assert finding.severity == "informational"

    def test_severity_normalized_to_lowercase(self, base_finding_data):
        """Test that severity is normalized to lowercase."""
        base_finding_data["severity"] = "HIGH"

        finding = OCSFFinding.from_dict(base_finding_data)

        assert finding.severity == "high"
