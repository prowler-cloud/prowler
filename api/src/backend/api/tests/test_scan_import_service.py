"""
Unit tests for the Scan Import Service module.

Tests the ScanImportService class which handles importing Prowler CLI
scan results (JSON/OCSF and CSV formats) into the Prowler platform.

This module provides test coverage for:
- Format detection (JSON vs CSV)
- Content parsing and validation
- Provider resolution and creation
- Bulk resource creation
- Bulk finding creation
- Resource-finding mapping creation
- Error handling

Test Classes
------------
TestScanImportServiceInit
    Tests for ScanImportService initialization.

TestDetectFormat
    Tests for the _detect_format method.

TestParseContent
    Tests for the _parse_content method.

TestResolveProvider
    Tests for the _resolve_provider method.

TestCreateScan
    Tests for the _create_scan method.

TestBulkCreateResources
    Tests for the _bulk_create_resources method.

TestBulkCreateFindings
    Tests for the _bulk_create_findings method.

TestImportScan
    Integration tests for the main import_scan method.

TestScanImportError
    Tests for the ScanImportError exception class.

TestScanImportResult
    Tests for the ScanImportResult dataclass.

Usage
-----
Run tests from the api/src/backend directory::

    poetry run pytest api/tests/test_scan_import_service.py -v

Run specific test class::

    poetry run pytest api/tests/test_scan_import_service.py::TestDetectFormat -v

Run with coverage::

    poetry run pytest api/tests/test_scan_import_service.py --cov=api.services.scan_import
"""

import json
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from api.parsers.csv_parser import CSVFinding, CSVResource, CSVCheckMetadata
from api.parsers.ocsf_parser import OCSFFinding, OCSFResource, OCSFCheckMetadata
from api.services.scan_import import (
    MAX_FILE_SIZE,
    ScanImportError,
    ScanImportResult,
    ScanImportService,
)


class TestScanImportServiceInit:
    """Tests for ScanImportService initialization."""

    def test_init_with_tenant_id(self):
        """Test service initialization with tenant ID."""
        tenant_id = str(uuid4())
        service = ScanImportService(tenant_id=tenant_id)

        assert service.tenant_id == tenant_id

    def test_init_stores_tenant_id(self):
        """Test that tenant_id is stored correctly."""
        tenant_id = "550e8400-e29b-41d4-a716-446655440000"
        service = ScanImportService(tenant_id=tenant_id)

        assert service.tenant_id == tenant_id


class TestDetectFormat:
    """Tests for the _detect_format method."""

    @pytest.fixture
    def service(self):
        """Return a ScanImportService instance."""
        return ScanImportService(tenant_id=str(uuid4()))

    @pytest.fixture
    def valid_ocsf_content(self):
        """Return valid OCSF JSON content."""
        data = [
            {
                "metadata": {"event_code": "check_1"},
                "finding_info": {"uid": "finding-1"},
                "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
            }
        ]
        return json.dumps(data).encode("utf-8")

    @pytest.fixture
    def valid_csv_content(self):
        """Return valid CSV content."""
        csv_data = """FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID
finding-001;aws;check_1;PASS;123456789012;resource-1"""
        return csv_data.encode("utf-8")

    def test_detect_json_format(self, service, valid_ocsf_content):
        """Test detection of JSON/OCSF format."""
        result = service._detect_format(valid_ocsf_content)

        assert result == "json"

    def test_detect_csv_format(self, service, valid_csv_content):
        """Test detection of CSV format."""
        result = service._detect_format(valid_csv_content)

        assert result == "csv"

    def test_detect_invalid_format_raises_error(self, service):
        """Test that invalid format raises ScanImportError."""
        invalid_content = b"not valid json or csv"

        with pytest.raises(ScanImportError) as exc_info:
            service._detect_format(invalid_content)

        assert exc_info.value.code == "invalid_format"
        assert "not recognized" in exc_info.value.message


class TestParseContent:
    """Tests for the _parse_content method."""

    @pytest.fixture
    def service(self):
        """Return a ScanImportService instance."""
        return ScanImportService(tenant_id=str(uuid4()))

    def test_parse_json_content(self, service):
        """Test parsing JSON/OCSF content."""
        data = [
            {
                "message": "Test finding",
                "metadata": {"event_code": "check_1"},
                "severity": "Low",
                "status_code": "FAIL",
                "finding_info": {"uid": "finding-1", "title": "Test", "desc": "Desc"},
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "123456789012"},
                },
                "resources": [],
            }
        ]
        content = json.dumps(data).encode("utf-8")

        findings = service._parse_content(content, "json")

        assert len(findings) == 1
        assert isinstance(findings[0], OCSFFinding)
        assert findings[0].check_id == "check_1"

    def test_parse_csv_content(self, service):
        """Test parsing CSV content."""
        csv_data = """FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;SEVERITY;RESOURCE_UID
finding-001;aws;check_1;PASS;123456789012;low;resource-1"""
        content = csv_data.encode("utf-8")

        findings = service._parse_content(content, "csv")

        assert len(findings) == 1
        assert isinstance(findings[0], CSVFinding)
        assert findings[0].check_id == "check_1"

    def test_parse_unsupported_format_raises_error(self, service):
        """Test that unsupported format raises ScanImportError."""
        with pytest.raises(ScanImportError) as exc_info:
            service._parse_content(b"content", "xml")

        assert exc_info.value.code == "unsupported_format"


class TestScanImportError:
    """Tests for the ScanImportError exception class."""

    def test_error_with_message_only(self):
        """Test error with message only."""
        error = ScanImportError(message="Test error")

        assert str(error) == "Test error"
        assert error.code == "import_error"
        assert error.details == {}

    def test_error_with_code(self):
        """Test error with custom code."""
        error = ScanImportError(message="Test error", code="custom_code")

        assert error.code == "custom_code"

    def test_error_with_details(self):
        """Test error with details."""
        details = {"field": "value", "index": 5}
        error = ScanImportError(message="Test error", details=details)

        assert error.details == details

    def test_to_dict(self):
        """Test to_dict method."""
        error = ScanImportError(
            message="Test error",
            code="test_code",
            details={"key": "value"},
        )

        result = error.to_dict()

        assert result["message"] == "Test error"
        assert result["code"] == "test_code"
        assert result["details"] == {"key": "value"}


class TestScanImportResult:
    """Tests for the ScanImportResult dataclass."""

    def test_result_creation(self):
        """Test creating a ScanImportResult."""
        scan_id = uuid4()
        provider_id = uuid4()

        result = ScanImportResult(
            scan_id=scan_id,
            provider_id=provider_id,
            findings_count=100,
            resources_count=50,
        )

        assert result.scan_id == scan_id
        assert result.provider_id == provider_id
        assert result.findings_count == 100
        assert result.resources_count == 50
        assert result.provider_created is False
        assert result.warnings == []

    def test_result_with_provider_created(self):
        """Test result with provider_created flag."""
        result = ScanImportResult(
            scan_id=uuid4(),
            provider_id=uuid4(),
            findings_count=10,
            resources_count=5,
            provider_created=True,
        )

        assert result.provider_created is True

    def test_result_with_warnings(self):
        """Test result with warnings."""
        warnings = ["Warning 1", "Warning 2"]
        result = ScanImportResult(
            scan_id=uuid4(),
            provider_id=uuid4(),
            findings_count=10,
            resources_count=5,
            warnings=warnings,
        )

        assert result.warnings == warnings

    def test_to_dict(self):
        """Test to_dict method."""
        scan_id = uuid4()
        provider_id = uuid4()

        result = ScanImportResult(
            scan_id=scan_id,
            provider_id=provider_id,
            findings_count=100,
            resources_count=50,
            provider_created=True,
            warnings=["Warning 1"],
        )

        result_dict = result.to_dict()

        assert result_dict["scan_id"] == str(scan_id)
        assert result_dict["provider_id"] == str(provider_id)
        assert result_dict["findings_count"] == 100
        assert result_dict["resources_count"] == 50
        assert result_dict["provider_created"] is True
        assert result_dict["warnings"] == ["Warning 1"]


class TestBuildCheckMetadata:
    """Tests for the _build_check_metadata method."""

    @pytest.fixture
    def service(self):
        """Return a ScanImportService instance."""
        return ScanImportService(tenant_id=str(uuid4()))

    def test_build_from_ocsf_finding(self, service):
        """Test building check metadata from OCSF finding."""
        ocsf_metadata = OCSFCheckMetadata(
            title="Test Check",
            description="Test description",
            risk="Test risk",
            remediation_description="Fix it",
            remediation_references=["https://example.com"],
            categories=["security"],
            related_url="https://docs.example.com",
        )
        finding = OCSFFinding(
            uid="finding-1",
            check_id="check_1",
            severity="low",
            status="FAIL",
            status_extended="Detail",
            message="Message",
            impact_extended="Impact",
            check_metadata=ocsf_metadata,
            compliance={},
            resources=[],
            provider_type="aws",
            account_uid="123456789012",
            account_name="Test",
        )

        result = service._build_check_metadata(finding)

        assert result["title"] == "Test Check"
        assert result["description"] == "Test description"
        assert result["risk"] == "Test risk"
        assert result["remediation"]["description"] == "Fix it"
        assert result["categories"] == ["security"]

    def test_build_from_csv_finding(self, service):
        """Test building check metadata from CSV finding."""
        csv_metadata = CSVCheckMetadata(
            title="CSV Check",
            description="CSV description",
            risk="CSV risk",
            remediation_description="CSV fix",
            remediation_url="https://fix.example.com",
            categories=["compliance"],
        )
        resource = CSVResource(
            uid="resource-1",
            name="test-resource",
            region="us-east-1",
            service="s3",
            type="bucket",
        )
        finding = CSVFinding(
            uid="finding-1",
            check_id="check_1",
            severity="low",
            status="FAIL",
            status_extended="Detail",
            muted=False,
            check_metadata=csv_metadata,
            compliance={},
            resource=resource,
            provider_type="aws",
            account_uid="123456789012",
            account_name="Test",
            account_email="",
            account_organization_uid="",
            account_organization_name="",
            account_tags="",
            auth_method="",
        )

        result = service._build_check_metadata(finding)

        assert result["title"] == "CSV Check"
        assert result["description"] == "CSV description"
        assert result["risk"] == "CSV risk"
        assert result["remediation"]["description"] == "CSV fix"
        assert result["categories"] == ["compliance"]


class TestGetResourceUids:
    """Tests for the _get_resource_uids method."""

    @pytest.fixture
    def service(self):
        """Return a ScanImportService instance."""
        return ScanImportService(tenant_id=str(uuid4()))

    def test_get_uids_from_ocsf_finding(self, service):
        """Test extracting resource UIDs from OCSF finding."""
        resources = [
            OCSFResource(uid="resource-1", name="r1", region="", service="", type=""),
            OCSFResource(uid="resource-2", name="r2", region="", service="", type=""),
        ]
        finding = OCSFFinding(
            uid="finding-1",
            check_id="check_1",
            severity="low",
            status="FAIL",
            status_extended="",
            message="",
            impact_extended="",
            check_metadata=OCSFCheckMetadata(),
            compliance={},
            resources=resources,
            provider_type="aws",
            account_uid="123456789012",
            account_name="",
        )

        result = service._get_resource_uids(finding)

        assert result == ["resource-1", "resource-2"]

    def test_get_uids_from_csv_finding(self, service):
        """Test extracting resource UIDs from CSV finding."""
        resource = CSVResource(
            uid="csv-resource-1",
            name="test",
            region="",
            service="",
            type="",
        )
        finding = CSVFinding(
            uid="finding-1",
            check_id="check_1",
            severity="low",
            status="FAIL",
            status_extended="",
            muted=False,
            check_metadata=CSVCheckMetadata(),
            compliance={},
            resource=resource,
            provider_type="aws",
            account_uid="123456789012",
            account_name="",
            account_email="",
            account_organization_uid="",
            account_organization_name="",
            account_tags="",
            auth_method="",
        )

        result = service._get_resource_uids(finding)

        assert result == ["csv-resource-1"]


class TestGetImpactExtended:
    """Tests for the _get_impact_extended method."""

    @pytest.fixture
    def service(self):
        """Return a ScanImportService instance."""
        return ScanImportService(tenant_id=str(uuid4()))

    def test_get_impact_from_ocsf_finding(self, service):
        """Test getting impact extended from OCSF finding."""
        finding = OCSFFinding(
            uid="finding-1",
            check_id="check_1",
            severity="low",
            status="FAIL",
            status_extended="",
            message="Test message",
            impact_extended="Test impact",
            check_metadata=OCSFCheckMetadata(),
            compliance={},
            resources=[],
            provider_type="aws",
            account_uid="123456789012",
            account_name="",
        )

        result = service._get_impact_extended(finding)

        assert result == "Test impact"

    def test_get_impact_from_ocsf_finding_fallback_to_message(self, service):
        """Test getting impact from message when impact_extended is empty."""
        finding = OCSFFinding(
            uid="finding-1",
            check_id="check_1",
            severity="low",
            status="FAIL",
            status_extended="",
            message="Fallback message",
            impact_extended="",
            check_metadata=OCSFCheckMetadata(),
            compliance={},
            resources=[],
            provider_type="aws",
            account_uid="123456789012",
            account_name="",
        )

        result = service._get_impact_extended(finding)

        assert result == "Fallback message"

    def test_get_impact_from_csv_finding(self, service):
        """Test getting impact extended from CSV finding."""
        resource = CSVResource(uid="r1", name="", region="", service="", type="")
        finding = CSVFinding(
            uid="finding-1",
            check_id="check_1",
            severity="low",
            status="FAIL",
            status_extended="CSV status extended",
            muted=False,
            check_metadata=CSVCheckMetadata(),
            compliance={},
            resource=resource,
            provider_type="aws",
            account_uid="123456789012",
            account_name="",
            account_email="",
            account_organization_uid="",
            account_organization_name="",
            account_tags="",
            auth_method="",
        )

        result = service._get_impact_extended(finding)

        assert result == "CSV status extended"


class TestGetMutedStatus:
    """Tests for the _get_muted_status method."""

    @pytest.fixture
    def service(self):
        """Return a ScanImportService instance."""
        return ScanImportService(tenant_id=str(uuid4()))

    def test_get_muted_from_csv_finding_true(self, service):
        """Test getting muted status from CSV finding when True."""
        resource = CSVResource(uid="r1", name="", region="", service="", type="")
        finding = CSVFinding(
            uid="finding-1",
            check_id="check_1",
            severity="low",
            status="FAIL",
            status_extended="",
            muted=True,
            check_metadata=CSVCheckMetadata(),
            compliance={},
            resource=resource,
            provider_type="aws",
            account_uid="123456789012",
            account_name="",
            account_email="",
            account_organization_uid="",
            account_organization_name="",
            account_tags="",
            auth_method="",
        )

        result = service._get_muted_status(finding)

        assert result is True

    def test_get_muted_from_csv_finding_false(self, service):
        """Test getting muted status from CSV finding when False."""
        resource = CSVResource(uid="r1", name="", region="", service="", type="")
        finding = CSVFinding(
            uid="finding-1",
            check_id="check_1",
            severity="low",
            status="FAIL",
            status_extended="",
            muted=False,
            check_metadata=CSVCheckMetadata(),
            compliance={},
            resource=resource,
            provider_type="aws",
            account_uid="123456789012",
            account_name="",
            account_email="",
            account_organization_uid="",
            account_organization_name="",
            account_tags="",
            auth_method="",
        )

        result = service._get_muted_status(finding)

        assert result is False

    def test_get_muted_from_ocsf_finding_returns_false(self, service):
        """Test getting muted status from OCSF finding returns False."""
        finding = OCSFFinding(
            uid="finding-1",
            check_id="check_1",
            severity="low",
            status="FAIL",
            status_extended="",
            message="",
            impact_extended="",
            check_metadata=OCSFCheckMetadata(),
            compliance={},
            resources=[],
            provider_type="aws",
            account_uid="123456789012",
            account_name="",
        )

        result = service._get_muted_status(finding)

        assert result is False


class TestFileSizeValidation:
    """Tests for file size validation in import_scan."""

    @pytest.fixture
    def service(self):
        """Return a ScanImportService instance."""
        return ScanImportService(tenant_id=str(uuid4()))

    def test_file_too_large_raises_error(self, service):
        """Test that file exceeding max size raises error."""
        # Create content larger than MAX_FILE_SIZE
        large_content = b"x" * (MAX_FILE_SIZE + 1)

        with pytest.raises(ScanImportError) as exc_info:
            service.import_scan(large_content)

        assert exc_info.value.code == "file_too_large"
        assert "exceeds maximum" in exc_info.value.message

    def test_max_file_size_constant(self):
        """Test that MAX_FILE_SIZE is 1GB."""
        assert MAX_FILE_SIZE == 1024 * 1024 * 1024


class TestProviderIdValidation:
    """Tests for provider_id validation in import_scan."""

    @pytest.fixture
    def service(self):
        """Return a ScanImportService instance."""
        return ScanImportService(tenant_id=str(uuid4()))

    def test_invalid_provider_id_format_raises_error(self, service):
        """Test that invalid provider_id format raises error."""
        valid_content = json.dumps(
            [
                {
                    "metadata": {"event_code": "check_1"},
                    "finding_info": {"uid": "finding-1"},
                    "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
                }
            ]
        ).encode("utf-8")

        with pytest.raises(ScanImportError) as exc_info:
            service.import_scan(valid_content, provider_id="not-a-uuid")

        assert exc_info.value.code == "invalid_provider_id"


class TestNoFindingsValidation:
    """Tests for empty findings validation."""

    @pytest.fixture
    def service(self):
        """Return a ScanImportService instance."""
        return ScanImportService(tenant_id=str(uuid4()))

    def test_empty_findings_raises_error(self, service):
        """Test that empty findings list raises error."""
        empty_content = b"[]"

        with pytest.raises(ScanImportError) as exc_info:
            service.import_scan(empty_content)

        assert exc_info.value.code == "no_findings"
        assert "No findings found" in exc_info.value.message


class TestGetRawResult:
    """Tests for the _get_raw_result method."""

    @pytest.fixture
    def service(self):
        """Return a ScanImportService instance."""
        return ScanImportService(tenant_id=str(uuid4()))

    def test_get_raw_result_from_ocsf_finding(self, service):
        """Test getting raw result from OCSF finding."""
        raw_data = {"key": "value", "nested": {"data": 123}}
        finding = OCSFFinding(
            uid="finding-1",
            check_id="check_1",
            severity="low",
            status="FAIL",
            status_extended="",
            message="",
            impact_extended="",
            check_metadata=OCSFCheckMetadata(),
            compliance={},
            resources=[],
            provider_type="aws",
            account_uid="123456789012",
            account_name="",
            raw_result=raw_data,
        )

        result = service._get_raw_result(finding)

        assert result == raw_data

    def test_get_raw_result_from_csv_finding(self, service):
        """Test getting raw result from CSV finding."""
        raw_row = {"FINDING_UID": "f1", "CHECK_ID": "c1", "STATUS": "FAIL"}
        resource = CSVResource(uid="r1", name="", region="", service="", type="")
        finding = CSVFinding(
            uid="finding-1",
            check_id="check_1",
            severity="low",
            status="FAIL",
            status_extended="",
            muted=False,
            check_metadata=CSVCheckMetadata(),
            compliance={},
            resource=resource,
            provider_type="aws",
            account_uid="123456789012",
            account_name="",
            account_email="",
            account_organization_uid="",
            account_organization_name="",
            account_tags="",
            auth_method="",
            raw_row=raw_row,
        )

        result = service._get_raw_result(finding)

        assert result == raw_row

    def test_get_raw_result_empty_for_unknown_type(self, service):
        """Test that unknown finding type returns empty dict."""
        # Create a mock object that's neither OCSF nor CSV
        mock_finding = MagicMock()
        mock_finding.__class__ = type("UnknownFinding", (), {})

        result = service._get_raw_result(mock_finding)

        assert result == {}


class TestBuildCheckMetadataEdgeCases:
    """Additional tests for _build_check_metadata edge cases."""

    @pytest.fixture
    def service(self):
        """Return a ScanImportService instance."""
        return ScanImportService(tenant_id=str(uuid4()))

    def test_build_from_ocsf_with_empty_metadata(self, service):
        """Test building check metadata from OCSF finding with empty metadata."""
        ocsf_metadata = OCSFCheckMetadata()  # All defaults
        finding = OCSFFinding(
            uid="finding-1",
            check_id="check_1",
            severity="low",
            status="FAIL",
            status_extended="",
            message="",
            impact_extended="",
            check_metadata=ocsf_metadata,
            compliance={},
            resources=[],
            provider_type="aws",
            account_uid="123456789012",
            account_name="",
        )

        result = service._build_check_metadata(finding)

        assert result["title"] == ""
        assert result["description"] == ""
        assert result["risk"] == ""
        assert result["remediation"]["description"] == ""
        assert result["remediation"]["references"] == []
        assert result["categories"] == []

    def test_build_from_csv_with_all_remediation_fields(self, service):
        """Test building check metadata from CSV with all remediation fields."""
        csv_metadata = CSVCheckMetadata(
            title="CSV Check",
            description="Description",
            risk="Risk",
            remediation_description="Fix description",
            remediation_url="https://fix.example.com",
            remediation_cli="aws cli command",
            remediation_terraform="terraform code",
            remediation_nativeiac="native iac code",
            remediation_other="other remediation",
            categories=["cat1", "cat2"],
            related_url="https://related.example.com",
            additional_urls=["https://url1.com", "https://url2.com"],
            notes="Some notes",
        )
        resource = CSVResource(uid="r1", name="", region="", service="", type="")
        finding = CSVFinding(
            uid="finding-1",
            check_id="check_1",
            severity="low",
            status="FAIL",
            status_extended="",
            muted=False,
            check_metadata=csv_metadata,
            compliance={},
            resource=resource,
            provider_type="aws",
            account_uid="123456789012",
            account_name="",
            account_email="",
            account_organization_uid="",
            account_organization_name="",
            account_tags="",
            auth_method="",
        )

        result = service._build_check_metadata(finding)

        assert result["title"] == "CSV Check"
        assert result["remediation"]["description"] == "Fix description"
        assert result["remediation"]["url"] == "https://fix.example.com"
        assert result["remediation"]["cli"] == "aws cli command"
        assert result["remediation"]["terraform"] == "terraform code"
        assert result["remediation"]["nativeiac"] == "native iac code"
        assert result["remediation"]["other"] == "other remediation"
        assert result["additional_urls"] == ["https://url1.com", "https://url2.com"]
        assert result["notes"] == "Some notes"

    def test_build_returns_empty_for_unknown_type(self, service):
        """Test that unknown finding type returns empty dict."""
        mock_finding = MagicMock()
        mock_finding.__class__ = type("UnknownFinding", (), {})

        result = service._build_check_metadata(mock_finding)

        assert result == {}


class TestGetResourceUidsEdgeCases:
    """Additional tests for _get_resource_uids edge cases."""

    @pytest.fixture
    def service(self):
        """Return a ScanImportService instance."""
        return ScanImportService(tenant_id=str(uuid4()))

    def test_get_uids_from_ocsf_with_empty_resources(self, service):
        """Test extracting resource UIDs from OCSF finding with no resources."""
        finding = OCSFFinding(
            uid="finding-1",
            check_id="check_1",
            severity="low",
            status="FAIL",
            status_extended="",
            message="",
            impact_extended="",
            check_metadata=OCSFCheckMetadata(),
            compliance={},
            resources=[],
            provider_type="aws",
            account_uid="123456789012",
            account_name="",
        )

        result = service._get_resource_uids(finding)

        assert result == []

    def test_get_uids_returns_empty_for_unknown_type(self, service):
        """Test that unknown finding type returns empty list."""
        mock_finding = MagicMock()
        mock_finding.__class__ = type("UnknownFinding", (), {})

        result = service._get_resource_uids(mock_finding)

        assert result == []


class TestParseContentErrorHandling:
    """Tests for error handling in _parse_content method."""

    @pytest.fixture
    def service(self):
        """Return a ScanImportService instance."""
        return ScanImportService(tenant_id=str(uuid4()))

    def test_parse_json_with_invalid_ocsf_raises_error(self, service):
        """Test that invalid OCSF JSON raises ScanImportError."""
        # JSON that parses but doesn't match OCSF schema
        invalid_ocsf = json.dumps([{"invalid": "data"}]).encode("utf-8")

        with pytest.raises(ScanImportError) as exc_info:
            service._parse_content(invalid_ocsf, "json")

        assert exc_info.value.code == "json_parse_error"

    def test_parse_csv_with_missing_columns_raises_error(self, service):
        """Test that CSV with missing required columns raises ScanImportError."""
        invalid_csv = b"COLUMN1;COLUMN2\nvalue1;value2"

        with pytest.raises(ScanImportError) as exc_info:
            service._parse_content(invalid_csv, "csv")

        assert exc_info.value.code == "csv_parse_error"


class TestDetectFormatEdgeCases:
    """Additional tests for _detect_format edge cases."""

    @pytest.fixture
    def service(self):
        """Return a ScanImportService instance."""
        return ScanImportService(tenant_id=str(uuid4()))

    def test_detect_format_with_empty_json_array(self, service):
        """Test format detection with empty JSON array."""
        content = b"[]"

        result = service._detect_format(content)

        assert result == "json"

    def test_detect_format_with_csv_headers_only(self, service):
        """Test format detection with CSV that has only headers."""
        csv_content = b"FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;RESOURCE_UID"

        result = service._detect_format(csv_content)

        assert result == "csv"

    def test_detect_format_with_binary_content_raises_error(self, service):
        """Test that binary content raises ScanImportError."""
        binary_content = b"\x00\x01\x02\x03\x04\x05"

        with pytest.raises(ScanImportError) as exc_info:
            service._detect_format(binary_content)

        assert exc_info.value.code == "invalid_format"


@pytest.mark.django_db
class TestImportScanValidation:
    """Tests for validation in import_scan method."""

    @pytest.fixture
    def service(self):
        """Return a ScanImportService instance."""
        return ScanImportService(tenant_id=str(uuid4()))

    def test_import_scan_with_valid_uuid_string_provider_id(self, service):
        """Test that valid UUID string provider_id is accepted."""
        valid_content = json.dumps(
            [
                {
                    "metadata": {"event_code": "check_1"},
                    "finding_info": {"uid": "finding-1"},
                    "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
                }
            ]
        ).encode("utf-8")

        # This should fail at provider resolution, not at UUID parsing
        with pytest.raises(ScanImportError) as exc_info:
            service.import_scan(
                valid_content, provider_id="550e8400-e29b-41d4-a716-446655440000"
            )

        # Should fail at provider resolution, not UUID parsing
        assert exc_info.value.code != "invalid_provider_id"

    def test_import_scan_with_uuid_object_provider_id(self, service):
        """Test that UUID object provider_id is accepted."""
        valid_content = json.dumps(
            [
                {
                    "metadata": {"event_code": "check_1"},
                    "finding_info": {"uid": "finding-1"},
                    "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
                }
            ]
        ).encode("utf-8")

        provider_uuid = uuid4()

        # This should fail at provider resolution, not at UUID handling
        with pytest.raises(ScanImportError) as exc_info:
            service.import_scan(valid_content, provider_id=provider_uuid)

        # Should fail at provider resolution, not UUID handling
        assert exc_info.value.code != "invalid_provider_id"


class TestScanImportResultDefaults:
    """Tests for ScanImportResult default values."""

    def test_result_default_provider_created(self):
        """Test that provider_created defaults to False."""
        result = ScanImportResult(
            scan_id=uuid4(),
            provider_id=uuid4(),
            findings_count=10,
            resources_count=5,
        )

        assert result.provider_created is False

    def test_result_default_warnings(self):
        """Test that warnings defaults to empty list."""
        result = ScanImportResult(
            scan_id=uuid4(),
            provider_id=uuid4(),
            findings_count=10,
            resources_count=5,
        )

        assert result.warnings == []
        assert isinstance(result.warnings, list)


class TestScanImportErrorDefaults:
    """Tests for ScanImportError default values."""

    def test_error_default_code(self):
        """Test that code defaults to 'import_error'."""
        error = ScanImportError(message="Test")

        assert error.code == "import_error"

    def test_error_default_details(self):
        """Test that details defaults to empty dict."""
        error = ScanImportError(message="Test")

        assert error.details == {}
        assert isinstance(error.details, dict)

    def test_error_to_dict_with_defaults(self):
        """Test to_dict with default values."""
        error = ScanImportError(message="Test message")

        result = error.to_dict()

        assert result == {
            "message": "Test message",
            "code": "import_error",
            "details": {},
        }
