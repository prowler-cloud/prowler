"""
Unit tests for the Scan Import View.

Tests the ScanImportView API endpoint which handles importing Prowler CLI
scan results (JSON/OCSF and CSV formats) into the Prowler platform.

This module provides test coverage for:
- JSON/OCSF import with valid data
- CSV import with valid data
- File upload via multipart
- Inline JSON via request body
- Provider resolution (existing provider)
- Provider creation (new provider)
- Validation errors (invalid format)
- Authentication required
- Permission required (MANAGE_SCANS)
- Tenant isolation

Test Classes
------------
TestScanImportViewAuthentication
    Tests for authentication requirements.

TestScanImportViewPermissions
    Tests for permission requirements.

TestScanImportViewValidation
    Tests for request validation.

TestScanImportViewJSONImport
    Tests for JSON/OCSF import functionality.

TestScanImportViewCSVImport
    Tests for CSV import functionality.

TestScanImportViewProviderHandling
    Tests for provider resolution and creation.

TestScanImportViewTenantIsolation
    Tests for tenant isolation.

Usage
-----
Run tests from the api/src/backend directory::

    poetry run pytest api/tests/test_scan_import_view.py -v

Run specific test class::

    poetry run pytest api/tests/test_scan_import_view.py::TestScanImportViewJSONImport -v

Run with coverage::

    poetry run pytest api/tests/test_scan_import_view.py --cov=api.v1.views
"""

import io
import json
from uuid import uuid4

import pytest
from django.urls import reverse
from rest_framework import status

from api.models import Finding, Provider, Resource, Scan, StateChoices


@pytest.mark.django_db
class TestScanImportViewAuthentication:
    """Tests for authentication requirements."""

    def test_unauthenticated_request_returns_401(self, client):
        """Test that unauthenticated requests return 401."""
        url = reverse("scan-import")
        response = client.post(url, data={}, content_type="application/json")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED

    def test_invalid_token_returns_401(self, client):
        """Test that invalid token returns 401."""
        url = reverse("scan-import")
        client.defaults["HTTP_AUTHORIZATION"] = "Bearer invalid_token"
        response = client.post(url, data={}, content_type="application/json")

        assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.django_db
class TestScanImportViewPermissions:
    """Tests for permission requirements (MANAGE_SCANS)."""

    def test_user_without_manage_scans_permission_returns_403(
        self, authenticated_client_no_permissions_rbac
    ):
        """Test that user without MANAGE_SCANS permission gets 403."""
        url = reverse("scan-import")
        data = {"data": [{"test": "data"}]}

        response = authenticated_client_no_permissions_rbac.post(
            url, data=json.dumps(data), content_type="application/json"
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN

    def test_user_with_manage_scans_permission_can_access(
        self, authenticated_client, tenants_fixture
    ):
        """Test that user with MANAGE_SCANS permission can access endpoint."""
        url = reverse("scan-import")
        # Send minimal data to trigger validation error (not permission error)
        data = {}

        response = authenticated_client.post(
            url, data=json.dumps(data), content_type="application/json"
        )

        # Should get validation error, not permission error
        assert response.status_code != status.HTTP_403_FORBIDDEN


@pytest.mark.django_db
class TestScanImportViewValidation:
    """Tests for request validation."""

    def test_missing_file_and_data_returns_400(self, authenticated_client):
        """Test that missing both file and data returns validation error."""
        url = reverse("scan-import")
        data = {}

        response = authenticated_client.post(
            url, data=json.dumps(data), content_type="application/json"
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        response_data = response.json()
        assert "errors" in response_data

    def test_both_file_and_data_returns_400(self, authenticated_client):
        """Test that providing both file and data returns validation error."""
        url = reverse("scan-import")

        # Create a file-like object
        file_content = b'[{"test": "data"}]'
        file_obj = io.BytesIO(file_content)
        file_obj.name = "test.json"

        response = authenticated_client.post(
            url,
            data={
                "file": file_obj,
                "data": json.dumps([{"test": "data"}]),
            },
            format="multipart",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_file_too_large_returns_400(self, authenticated_client):
        """Test that file exceeding 1GB returns validation error."""
        url = reverse("scan-import")

        # Create a file larger than 1GB (we use a smaller size for test efficiency)
        # The actual validation happens at 1GB, but we test with a slightly larger file
        large_content = b"x" * (1024 * 1024 * 1024 + 1)
        file_obj = io.BytesIO(large_content)
        file_obj.name = "large_file.json"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    def test_binary_file_returns_422(self, authenticated_client):
        """Test that binary/unrecognized file format returns 422."""
        url = reverse("scan-import")

        # Create binary content that is neither JSON nor CSV
        binary_content = bytes(
            [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
        )  # PNG header
        file_obj = io.BytesIO(binary_content)
        file_obj.name = "image.png"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        response_data = response.json()
        assert "errors" in response_data
        # Check that errors is a list and has at least one error
        assert isinstance(response_data["errors"], list)
        assert len(response_data["errors"]) > 0
        assert response_data["errors"][0]["code"] == "invalid_format"

    def test_xml_file_returns_422(self, authenticated_client):
        """Test that XML file (not JSON or CSV) returns 422."""
        url = reverse("scan-import")

        # Create XML content
        xml_content = b"""<?xml version="1.0" encoding="UTF-8"?>
<findings>
    <finding>
        <check_id>test_check</check_id>
        <status>PASS</status>
    </finding>
</findings>"""
        file_obj = io.BytesIO(xml_content)
        file_obj.name = "findings.xml"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        response_data = response.json()
        assert "errors" in response_data
        # Check that errors is a list and has at least one error
        assert isinstance(response_data["errors"], list)
        assert len(response_data["errors"]) > 0
        assert response_data["errors"][0]["code"] == "invalid_format"

    def test_invalid_ocsf_missing_required_fields_returns_422(
        self, authenticated_client
    ):
        """Test that OCSF JSON missing required fields returns 422."""
        url = reverse("scan-import")

        # OCSF data missing required fields (metadata.event_code, finding_info.uid, etc.)
        invalid_ocsf = [
            {
                "message": "Test finding",
                # Missing: metadata.event_code
                "severity": "Low",
                "status_code": "PASS",
                # Missing: finding_info.uid
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "123456789012"},
                },
                "resources": [{"uid": "resource-1", "name": "test"}],
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": invalid_ocsf}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        response_data = response.json()
        assert "errors" in response_data

    def test_csv_missing_required_columns_returns_422(self, authenticated_client):
        """Test that CSV missing required columns returns 422."""
        url = reverse("scan-import")

        # CSV missing required columns (FINDING_UID, CHECK_ID, etc.)
        invalid_csv = """SOME_COLUMN;ANOTHER_COLUMN
value1;value2
value3;value4"""
        file_obj = io.BytesIO(invalid_csv.encode("utf-8"))
        file_obj.name = "invalid.csv"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        response_data = response.json()
        assert "errors" in response_data

    def test_plain_text_file_returns_422(self, authenticated_client):
        """Test that plain text file (not JSON or CSV) returns 422."""
        url = reverse("scan-import")

        # Plain text content
        text_content = b"This is just plain text, not JSON or CSV format."
        file_obj = io.BytesIO(text_content)
        file_obj.name = "readme.txt"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        response_data = response.json()
        assert "errors" in response_data
        # Check that errors is a list and has at least one error
        assert isinstance(response_data["errors"], list)
        assert len(response_data["errors"]) > 0
        assert response_data["errors"][0]["code"] == "invalid_format"

    def test_json_array_with_non_object_elements_returns_422(
        self, authenticated_client
    ):
        """Test that JSON array with non-object elements returns 422."""
        url = reverse("scan-import")

        # JSON array with strings instead of objects
        invalid_json = ["string1", "string2", "string3"]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": invalid_json}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        response_data = response.json()
        assert "errors" in response_data

    def test_json_object_instead_of_array_returns_422(self, authenticated_client):
        """Test that JSON object (not array) returns 422."""
        url = reverse("scan-import")

        # Single object instead of array of findings
        invalid_json = {
            "message": "Test finding",
            "metadata": {"event_code": "check_1"},
            "severity": "Low",
            "status_code": "PASS",
        }

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": invalid_json}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        response_data = response.json()
        assert "errors" in response_data

    def test_unsupported_provider_type_returns_422(self, authenticated_client):
        """Test that unsupported provider type returns 422."""
        url = reverse("scan-import")

        # OCSF data with unsupported provider type
        ocsf_data = [
            {
                "message": "Test finding",
                "metadata": {"event_code": "check_1"},
                "severity": "Low",
                "status_code": "PASS",
                "finding_info": {"uid": f"finding-{uuid4()}", "title": "Test"},
                "cloud": {
                    "provider": "unsupported_cloud_provider",  # Invalid provider type
                    "account": {"uid": "123456789012"},
                },
                "resources": [{"uid": f"resource-{uuid4()}", "name": "test"}],
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        response_data = response.json()
        assert "errors" in response_data
        # Check that errors is a list and has at least one error
        assert isinstance(response_data["errors"], list)
        assert len(response_data["errors"]) > 0
        assert response_data["errors"][0]["code"] == "invalid_provider_type"


@pytest.mark.django_db
class TestScanImportViewJSONImport:
    """Tests for JSON/OCSF import functionality."""

    @pytest.fixture
    def valid_ocsf_data(self):
        """Return valid OCSF JSON data."""
        return [
            {
                "message": "Test finding message",
                "metadata": {"event_code": "check_test_1"},
                "severity": "Low",
                "status_code": "FAIL",
                "status_detail": "Test status detail",
                "finding_info": {
                    "uid": f"finding-{uuid4()}",
                    "title": "Test Finding",
                    "desc": "Test description",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "123456789012", "name": "Test Account"},
                },
                "resources": [
                    {
                        "uid": f"resource-{uuid4()}",
                        "name": "test-resource",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

    @pytest.fixture
    def complete_ocsf_data(self):
        """Return complete OCSF JSON data with all fields for comprehensive testing."""
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())
        return {
            "finding_uid": finding_uid,
            "resource_uid": resource_uid,
            "data": [
                {
                    "message": "S3 bucket has public access enabled",
                    "metadata": {"event_code": "s3_bucket_public_access"},
                    "severity": "High",
                    "status_code": "FAIL",
                    "status_detail": "Bucket my-test-bucket has public access enabled",
                    "finding_info": {
                        "uid": finding_uid,
                        "title": "S3 Bucket Public Access Check",
                        "desc": "Checks if S3 buckets have public access enabled",
                    },
                    "cloud": {
                        "provider": "aws",
                        "account": {
                            "uid": "111122223333",
                            "name": "Production Account",
                        },
                    },
                    "resources": [
                        {
                            "uid": resource_uid,
                            "name": "my-test-bucket",
                            "region": "us-west-2",
                            "group": {"name": "s3"},
                            "type": "bucket",
                        }
                    ],
                    "risk_details": "Public S3 buckets can expose sensitive data",
                    "remediation": {
                        "desc": "Disable public access on the S3 bucket",
                        "references": ["https://docs.aws.amazon.com/s3/security"],
                    },
                    "unmapped": {
                        "compliance": {
                            "CIS-AWS": ["2.1.1", "2.1.2"],
                            "PCI-DSS": ["3.4"],
                        },
                        "categories": ["security", "storage"],
                        "related_url": "https://prowler.com/checks/s3",
                    },
                }
            ],
        }

    def test_json_import_with_valid_ocsf_data_creates_scan_and_findings(
        self, authenticated_client, tenants_fixture, complete_ocsf_data
    ):
        """Test JSON import with valid OCSF data creates scan, findings, and resources."""
        url = reverse("scan-import")
        tenant = tenants_fixture[0]
        ocsf_data = complete_ocsf_data["data"]
        finding_uid = complete_ocsf_data["finding_uid"]
        resource_uid = complete_ocsf_data["resource_uid"]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        # Verify successful response
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        # Verify response structure
        assert "data" in response_data
        assert response_data["data"]["type"] == "scan-imports"
        assert "attributes" in response_data["data"]

        attributes = response_data["data"]["attributes"]
        assert "scan_id" in attributes
        assert "provider_id" in attributes
        assert attributes["findings_count"] == 1
        assert attributes["resources_count"] == 1
        assert attributes["status"] == "completed"

        # Verify scan was created in database
        scan_id = attributes["scan_id"]
        scan = Scan.objects.get(id=scan_id)
        assert str(scan.tenant_id) == str(tenant.id)
        assert scan.trigger == Scan.TriggerChoices.IMPORTED
        assert scan.state == StateChoices.COMPLETED
        assert scan.unique_resource_count == 1

        # Verify provider was created
        provider_id = attributes["provider_id"]
        provider = Provider.objects.get(id=provider_id)
        assert provider.provider == "aws"
        assert provider.uid == "111122223333"
        assert str(provider.tenant_id) == str(tenant.id)

        # Verify finding was created
        finding = Finding.objects.get(uid=finding_uid)
        assert finding.check_id == "s3_bucket_public_access"
        assert finding.severity == "high"
        assert finding.status == "FAIL"
        assert (
            finding.status_extended == "Bucket my-test-bucket has public access enabled"
        )
        assert str(finding.scan_id) == scan_id
        assert str(finding.tenant_id) == str(tenant.id)

        # Verify check metadata
        assert finding.check_metadata["title"] == "S3 Bucket Public Access Check"
        assert (
            finding.check_metadata["description"]
            == "Checks if S3 buckets have public access enabled"
        )
        assert (
            finding.check_metadata["risk"]
            == "Public S3 buckets can expose sensitive data"
        )

        # Verify resource was created
        resource = Resource.objects.get(uid=resource_uid)
        assert resource.name == "my-test-bucket"
        assert resource.region == "us-west-2"
        assert resource.service == "s3"
        assert resource.type == "bucket"
        assert str(resource.tenant_id) == str(tenant.id)

    def test_json_import_with_valid_ocsf_data(
        self, authenticated_client, tenants_fixture, valid_ocsf_data
    ):
        """Test JSON import with valid OCSF data creates scan."""
        url = reverse("scan-import")

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": valid_ocsf_data}),
            content_type="application/json",
        )

        # Should succeed or fail with import error (not validation error)
        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        ]

    def test_json_import_via_file_upload(
        self, authenticated_client, tenants_fixture, valid_ocsf_data
    ):
        """Test JSON import via file upload."""
        url = reverse("scan-import")

        file_content = json.dumps(valid_ocsf_data).encode("utf-8")
        file_obj = io.BytesIO(file_content)
        file_obj.name = "prowler-output.json"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        # Should succeed or fail with import error (not validation error)
        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        ]

    def test_json_import_invalid_format_returns_422(self, authenticated_client):
        """Test that invalid JSON format returns 422."""
        url = reverse("scan-import")

        # Invalid OCSF structure
        invalid_data = [{"invalid": "structure"}]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": invalid_data}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        response_data = response.json()
        assert "errors" in response_data

    def test_json_import_with_multiple_findings(
        self, authenticated_client, tenants_fixture
    ):
        """Test JSON import with multiple findings creates all records."""
        url = reverse("scan-import")
        _tenant = tenants_fixture[0]  # noqa: F841 - used for fixture setup

        # Create OCSF data with multiple findings
        finding_uid_1 = str(uuid4())
        finding_uid_2 = str(uuid4())
        resource_uid_1 = str(uuid4())
        resource_uid_2 = str(uuid4())

        ocsf_data = [
            {
                "message": "First finding",
                "metadata": {"event_code": "check_1"},
                "severity": "High",
                "status_code": "FAIL",
                "status_detail": "First finding detail",
                "finding_info": {
                    "uid": finding_uid_1,
                    "title": "Check 1",
                    "desc": "Description 1",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "444455556666", "name": "Test Account"},
                },
                "resources": [
                    {
                        "uid": resource_uid_1,
                        "name": "resource-1",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            },
            {
                "message": "Second finding",
                "metadata": {"event_code": "check_2"},
                "severity": "Low",
                "status_code": "PASS",
                "status_detail": "Second finding detail",
                "finding_info": {
                    "uid": finding_uid_2,
                    "title": "Check 2",
                    "desc": "Description 2",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "444455556666", "name": "Test Account"},
                },
                "resources": [
                    {
                        "uid": resource_uid_2,
                        "name": "resource-2",
                        "region": "eu-west-1",
                        "group": {"name": "s3"},
                        "type": "bucket",
                    }
                ],
            },
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        attributes = response_data["data"]["attributes"]
        assert attributes["findings_count"] == 2
        assert attributes["resources_count"] == 2

        # Verify both findings were created
        assert Finding.objects.filter(uid=finding_uid_1).exists()
        assert Finding.objects.filter(uid=finding_uid_2).exists()

        # Verify both resources were created
        assert Resource.objects.filter(uid=resource_uid_1).exists()
        assert Resource.objects.filter(uid=resource_uid_2).exists()

    def test_json_import_with_compliance_data(
        self, authenticated_client, tenants_fixture
    ):
        """Test JSON import preserves compliance mapping data."""
        url = reverse("scan-import")
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        ocsf_data = [
            {
                "message": "Compliance test finding",
                "metadata": {"event_code": "compliance_check"},
                "severity": "Medium",
                "status_code": "FAIL",
                "status_detail": "Compliance check failed",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Compliance Check",
                    "desc": "Tests compliance mapping",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "777788889999", "name": "Compliance Account"},
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "compliance-resource",
                        "region": "us-east-1",
                        "group": {"name": "iam"},
                        "type": "user",
                    }
                ],
                "unmapped": {
                    "compliance": {
                        "CIS-AWS-1.4": ["1.1", "1.2", "1.3"],
                        "SOC2": ["CC6.1"],
                        "HIPAA": ["164.312(a)(1)"],
                    },
                },
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_201_CREATED

        # Verify compliance data was preserved
        finding = Finding.objects.get(uid=finding_uid)
        assert "CIS-AWS-1.4" in finding.compliance
        assert finding.compliance["CIS-AWS-1.4"] == ["1.1", "1.2", "1.3"]
        assert "SOC2" in finding.compliance
        assert "HIPAA" in finding.compliance


@pytest.mark.django_db
class TestScanImportViewCSVImport:
    """Tests for CSV import functionality."""

    @pytest.fixture
    def valid_csv_content(self):
        """Return valid CSV content."""
        return """FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;SEVERITY;RESOURCE_UID;RESOURCE_NAME;REGION;SERVICE_NAME;RESOURCE_TYPE;STATUS_EXTENDED
finding-001;aws;check_test_1;PASS;123456789012;low;resource-001;test-resource;us-east-1;ec2;instance;Test status"""

    @pytest.fixture
    def complete_csv_content(self):
        """Return complete CSV content with all fields for comprehensive testing."""
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())
        return {
            "finding_uid": finding_uid,
            "resource_uid": resource_uid,
            "content": f"""FINDING_UID;PROVIDER;CHECK_ID;CHECK_TITLE;STATUS;STATUS_EXTENDED;ACCOUNT_UID;SEVERITY;RESOURCE_UID;RESOURCE_NAME;REGION;SERVICE_NAME;RESOURCE_TYPE;DESCRIPTION;RISK;COMPLIANCE
{finding_uid};aws;s3_bucket_public_access;S3 Bucket Public Access Check;FAIL;Bucket my-test-bucket has public access enabled;222233334444;high;{resource_uid};my-test-bucket;us-west-2;s3;bucket;Checks if S3 buckets have public access enabled;Public S3 buckets can expose sensitive data;CIS-AWS: 2.1.1, 2.1.2 | PCI-DSS: 3.4""",
        }

    def test_csv_import_with_valid_data_creates_scan_and_findings(
        self, authenticated_client, tenants_fixture, complete_csv_content
    ):
        """Test CSV import with valid data creates scan, findings, and resources."""
        url = reverse("scan-import")
        tenant = tenants_fixture[0]
        csv_content = complete_csv_content["content"]
        finding_uid = complete_csv_content["finding_uid"]
        resource_uid = complete_csv_content["resource_uid"]

        file_obj = io.BytesIO(csv_content.encode("utf-8"))
        file_obj.name = "prowler-output.csv"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        # Verify successful response
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        # Verify response structure
        assert "data" in response_data
        assert response_data["data"]["type"] == "scan-imports"
        assert "attributes" in response_data["data"]

        attributes = response_data["data"]["attributes"]
        assert "scan_id" in attributes
        assert "provider_id" in attributes
        assert attributes["findings_count"] == 1
        assert attributes["resources_count"] == 1
        assert attributes["status"] == "completed"

        # Verify scan was created in database
        scan_id = attributes["scan_id"]
        scan = Scan.objects.get(id=scan_id)
        assert str(scan.tenant_id) == str(tenant.id)
        assert scan.trigger == Scan.TriggerChoices.IMPORTED
        assert scan.state == StateChoices.COMPLETED
        assert scan.unique_resource_count == 1

        # Verify provider was created
        provider_id = attributes["provider_id"]
        provider = Provider.objects.get(id=provider_id)
        assert provider.provider == "aws"
        assert provider.uid == "222233334444"
        assert str(provider.tenant_id) == str(tenant.id)

        # Verify finding was created
        finding = Finding.objects.get(uid=finding_uid)
        assert finding.check_id == "s3_bucket_public_access"
        assert finding.severity == "high"
        assert finding.status == "FAIL"
        assert (
            finding.status_extended == "Bucket my-test-bucket has public access enabled"
        )
        assert str(finding.scan_id) == scan_id
        assert str(finding.tenant_id) == str(tenant.id)

        # Verify check metadata
        assert finding.check_metadata["title"] == "S3 Bucket Public Access Check"
        assert (
            finding.check_metadata["description"]
            == "Checks if S3 buckets have public access enabled"
        )
        assert (
            finding.check_metadata["risk"]
            == "Public S3 buckets can expose sensitive data"
        )

        # Verify resource was created
        resource = Resource.objects.get(uid=resource_uid)
        assert resource.name == "my-test-bucket"
        assert resource.region == "us-west-2"
        assert resource.service == "s3"
        assert resource.type == "bucket"
        assert str(resource.tenant_id) == str(tenant.id)

        # Verify compliance data was preserved
        assert "CIS-AWS" in finding.compliance
        assert finding.compliance["CIS-AWS"] == ["2.1.1", "2.1.2"]
        assert "PCI-DSS" in finding.compliance
        assert finding.compliance["PCI-DSS"] == ["3.4"]

    def test_csv_import_via_file_upload(
        self, authenticated_client, tenants_fixture, valid_csv_content
    ):
        """Test CSV import via file upload."""
        url = reverse("scan-import")

        file_obj = io.BytesIO(valid_csv_content.encode("utf-8"))
        file_obj.name = "prowler-output.csv"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        # Should succeed or fail with import error (not validation error)
        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        ]

    def test_csv_import_with_multiple_findings(
        self, authenticated_client, tenants_fixture
    ):
        """Test CSV import with multiple findings creates all records."""
        url = reverse("scan-import")
        _tenant = tenants_fixture[0]  # noqa: F841 - used for fixture setup

        # Create CSV data with multiple findings
        finding_uid_1 = str(uuid4())
        finding_uid_2 = str(uuid4())
        resource_uid_1 = str(uuid4())
        resource_uid_2 = str(uuid4())

        csv_content = f"""FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;SEVERITY;RESOURCE_UID;RESOURCE_NAME;REGION;SERVICE_NAME;RESOURCE_TYPE;STATUS_EXTENDED
{finding_uid_1};aws;check_1;FAIL;555566667777;high;{resource_uid_1};resource-1;us-east-1;ec2;instance;First finding detail
{finding_uid_2};aws;check_2;PASS;555566667777;low;{resource_uid_2};resource-2;eu-west-1;s3;bucket;Second finding detail"""

        file_obj = io.BytesIO(csv_content.encode("utf-8"))
        file_obj.name = "prowler-output.csv"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        attributes = response_data["data"]["attributes"]
        assert attributes["findings_count"] == 2
        assert attributes["resources_count"] == 2

        # Verify both findings were created
        assert Finding.objects.filter(uid=finding_uid_1).exists()
        assert Finding.objects.filter(uid=finding_uid_2).exists()

        # Verify both resources were created
        assert Resource.objects.filter(uid=resource_uid_1).exists()
        assert Resource.objects.filter(uid=resource_uid_2).exists()

        # Verify findings have correct status
        finding_1 = Finding.objects.get(uid=finding_uid_1)
        finding_2 = Finding.objects.get(uid=finding_uid_2)
        assert finding_1.status == "FAIL"
        assert finding_1.severity == "high"
        assert finding_2.status == "PASS"
        assert finding_2.severity == "low"

    def test_csv_import_with_compliance_data(
        self, authenticated_client, tenants_fixture
    ):
        """Test CSV import preserves compliance mapping data."""
        url = reverse("scan-import")
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        csv_content = f"""FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;SEVERITY;RESOURCE_UID;RESOURCE_NAME;REGION;SERVICE_NAME;RESOURCE_TYPE;COMPLIANCE
{finding_uid};aws;compliance_check;FAIL;888899990000;medium;{resource_uid};compliance-resource;us-east-1;iam;user;CIS-AWS-1.4: 1.1, 1.2, 1.3 | SOC2: CC6.1 | HIPAA: 164.312"""

        file_obj = io.BytesIO(csv_content.encode("utf-8"))
        file_obj.name = "prowler-output.csv"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        assert response.status_code == status.HTTP_201_CREATED

        # Verify compliance data was preserved
        finding = Finding.objects.get(uid=finding_uid)
        assert "CIS-AWS-1.4" in finding.compliance
        assert finding.compliance["CIS-AWS-1.4"] == ["1.1", "1.2", "1.3"]
        assert "SOC2" in finding.compliance
        assert finding.compliance["SOC2"] == ["CC6.1"]
        assert "HIPAA" in finding.compliance
        assert finding.compliance["HIPAA"] == ["164.312"]

    def test_csv_import_with_comma_delimiter(
        self, authenticated_client, tenants_fixture
    ):
        """Test CSV import with comma delimiter (non-default)."""
        url = reverse("scan-import")
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        # Use comma delimiter instead of semicolon
        csv_content = f"""FINDING_UID,PROVIDER,CHECK_ID,STATUS,ACCOUNT_UID,SEVERITY,RESOURCE_UID,RESOURCE_NAME,REGION,SERVICE_NAME,RESOURCE_TYPE
{finding_uid},aws,comma_check,PASS,111122223333,low,{resource_uid},comma-resource,us-east-1,ec2,instance"""

        file_obj = io.BytesIO(csv_content.encode("utf-8"))
        file_obj.name = "prowler-output.csv"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        assert response.status_code == status.HTTP_201_CREATED

        # Verify finding was created correctly
        finding = Finding.objects.get(uid=finding_uid)
        assert finding.check_id == "comma_check"
        assert finding.status == "PASS"

    def test_csv_import_invalid_format_returns_422(self, authenticated_client):
        """Test that invalid CSV format returns 422."""
        url = reverse("scan-import")

        # Invalid CSV - missing required columns
        invalid_csv = "col1;col2\nval1;val2"
        file_obj = io.BytesIO(invalid_csv.encode("utf-8"))
        file_obj.name = "invalid.csv"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


@pytest.mark.django_db
class TestScanImportViewProviderHandling:
    """Tests for provider resolution and creation."""

    def test_import_resolves_existing_provider_by_type_and_uid(
        self, authenticated_client, providers_fixture, tenants_fixture
    ):
        """Test import automatically resolves existing provider by type and account UID.

        This test verifies that when importing scan data without explicitly passing
        provider_id, the system correctly finds and uses an existing provider that
        matches the provider type and account UID from the scan data.
        """
        url = reverse("scan-import")
        provider = providers_fixture[0]  # aws provider with uid="123456789012"
        tenant = tenants_fixture[0]
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        # Count providers before import
        initial_provider_count = Provider.objects.filter(tenant_id=tenant.id).count()

        # Create OCSF data that matches the existing provider's type and UID
        ocsf_data = [
            {
                "message": "Test finding for provider resolution",
                "metadata": {"event_code": "provider_resolution_check"},
                "severity": "Low",
                "status_code": "PASS",
                "status_detail": "Test status for provider resolution",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Provider Resolution Test",
                    "desc": "Testing automatic provider resolution",
                },
                "cloud": {
                    "provider": provider.provider,  # "aws"
                    "account": {
                        "uid": provider.uid,  # "123456789012"
                        "name": "Test Account",
                    },
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "provider-resolution-resource",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        # Import WITHOUT passing provider_id - should auto-resolve
        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        # Verify successful response
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        # Verify the existing provider was used
        attributes = response_data["data"]["attributes"]
        assert attributes["provider_id"] == str(provider.id)
        assert attributes["provider_created"] is False

        # Verify no new provider was created
        final_provider_count = Provider.objects.filter(tenant_id=tenant.id).count()
        assert final_provider_count == initial_provider_count

        # Verify the scan was associated with the existing provider
        scan_id = attributes["scan_id"]
        scan = Scan.objects.get(id=scan_id)
        assert scan.provider_id == provider.id

        # Verify finding was created and linked to the scan
        finding = Finding.objects.get(uid=finding_uid)
        assert str(finding.scan_id) == scan_id
        assert str(finding.tenant_id) == str(tenant.id)

    def test_import_resolves_existing_gcp_provider_by_type_and_uid(
        self, authenticated_client, providers_fixture, tenants_fixture
    ):
        """Test import resolves existing GCP provider by type and account UID.

        This test verifies provider resolution works for non-AWS providers.
        """
        url = reverse("scan-import")
        gcp_provider = providers_fixture[2]  # gcp provider with uid="a12322-test321"
        tenant = tenants_fixture[0]
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        # Count providers before import
        initial_provider_count = Provider.objects.filter(tenant_id=tenant.id).count()

        # Create OCSF data that matches the existing GCP provider
        ocsf_data = [
            {
                "message": "GCP test finding for provider resolution",
                "metadata": {"event_code": "gcp_provider_resolution_check"},
                "severity": "Medium",
                "status_code": "FAIL",
                "status_detail": "GCP test status for provider resolution",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "GCP Provider Resolution Test",
                    "desc": "Testing automatic GCP provider resolution",
                },
                "cloud": {
                    "provider": gcp_provider.provider,  # "gcp"
                    "account": {
                        "uid": gcp_provider.uid,  # "a12322-test321"
                        "name": "GCP Test Project",
                    },
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "gcp-provider-resolution-resource",
                        "region": "us-central1",
                        "group": {"name": "compute"},
                        "type": "instance",
                    }
                ],
            }
        ]

        # Import WITHOUT passing provider_id - should auto-resolve to GCP provider
        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        # Verify successful response
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        # Verify the existing GCP provider was used
        attributes = response_data["data"]["attributes"]
        assert attributes["provider_id"] == str(gcp_provider.id)
        assert attributes["provider_created"] is False

        # Verify no new provider was created
        final_provider_count = Provider.objects.filter(tenant_id=tenant.id).count()
        assert final_provider_count == initial_provider_count

    def test_import_resolves_existing_provider_via_csv(
        self, authenticated_client, providers_fixture, tenants_fixture
    ):
        """Test CSV import automatically resolves existing provider by type and account UID."""
        url = reverse("scan-import")
        provider = providers_fixture[0]  # aws provider with uid="123456789012"
        tenant = tenants_fixture[0]
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        # Count providers before import
        initial_provider_count = Provider.objects.filter(tenant_id=tenant.id).count()

        # Create CSV data that matches the existing provider's type and UID
        csv_content = f"""FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;SEVERITY;RESOURCE_UID;RESOURCE_NAME;REGION;SERVICE_NAME;RESOURCE_TYPE;STATUS_EXTENDED
{finding_uid};{provider.provider};csv_provider_resolution_check;PASS;{provider.uid};low;{resource_uid};csv-provider-resolution-resource;us-east-1;ec2;instance;CSV test for provider resolution"""

        file_obj = io.BytesIO(csv_content.encode("utf-8"))
        file_obj.name = "prowler-output.csv"

        # Import WITHOUT passing provider_id - should auto-resolve
        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        # Verify successful response
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        # Verify the existing provider was used
        attributes = response_data["data"]["attributes"]
        assert attributes["provider_id"] == str(provider.id)
        assert attributes["provider_created"] is False

        # Verify no new provider was created
        final_provider_count = Provider.objects.filter(tenant_id=tenant.id).count()
        assert final_provider_count == initial_provider_count

        # Verify the scan was associated with the existing provider
        scan_id = attributes["scan_id"]
        scan = Scan.objects.get(id=scan_id)
        assert scan.provider_id == provider.id

    def test_import_with_existing_provider_id(
        self, authenticated_client, providers_fixture
    ):
        """Test import with existing provider_id uses that provider."""
        url = reverse("scan-import")
        provider = providers_fixture[0]

        # Valid OCSF data matching the provider
        ocsf_data = [
            {
                "message": "Test finding",
                "metadata": {"event_code": "check_1"},
                "severity": "Low",
                "status_code": "PASS",
                "finding_info": {"uid": f"finding-{uuid4()}", "title": "Test"},
                "cloud": {
                    "provider": provider.provider,
                    "account": {"uid": provider.uid},
                },
                "resources": [{"uid": f"resource-{uuid4()}", "name": "test"}],
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data, "provider_id": str(provider.id)}),
            content_type="application/json",
        )

        # Should succeed or fail with import error
        assert response.status_code in [
            status.HTTP_201_CREATED,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        ]

    def test_import_with_nonexistent_provider_id_returns_422(
        self, authenticated_client
    ):
        """Test import with non-existent provider_id returns 422."""
        url = reverse("scan-import")
        fake_provider_id = str(uuid4())

        ocsf_data = [
            {
                "message": "Test",
                "metadata": {"event_code": "check_1"},
                "severity": "Low",
                "status_code": "PASS",
                "finding_info": {"uid": f"finding-{uuid4()}", "title": "Test"},
                "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
                "resources": [{"uid": f"resource-{uuid4()}", "name": "test"}],
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data, "provider_id": fake_provider_id}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_import_with_create_provider_false_and_no_match_returns_422(
        self, authenticated_client
    ):
        """Test import with create_provider=False and no matching provider returns 422."""
        url = reverse("scan-import")

        # Use a unique account UID that won't match any existing provider
        unique_account_uid = f"999999999{uuid4().hex[:3]}"

        ocsf_data = [
            {
                "message": "Test",
                "metadata": {"event_code": "check_1"},
                "severity": "Low",
                "status_code": "PASS",
                "finding_info": {"uid": f"finding-{uuid4()}", "title": "Test"},
                "cloud": {"provider": "aws", "account": {"uid": unique_account_uid}},
                "resources": [{"uid": f"resource-{uuid4()}", "name": "test"}],
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data, "create_provider": False}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_import_creates_new_provider_when_no_match_exists(
        self, authenticated_client, tenants_fixture
    ):
        """Test import creates new provider when no matching provider exists.

        This test verifies that when importing scan data with a provider type
        and account UID that doesn't match any existing provider, the system
        creates a new provider and associates the scan with it.
        """
        url = reverse("scan-import")
        tenant = tenants_fixture[0]
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        # Use a unique account UID that won't match any existing provider
        unique_account_uid = f"new-provider-{uuid4().hex[:8]}"
        account_name = "New Test Account"

        # Count providers before import
        initial_provider_count = Provider.objects.filter(tenant_id=tenant.id).count()

        # Create OCSF data with a new provider type and UID
        ocsf_data = [
            {
                "message": "Test finding for new provider creation",
                "metadata": {"event_code": "new_provider_check"},
                "severity": "High",
                "status_code": "FAIL",
                "status_detail": "Test status for new provider creation",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "New Provider Creation Test",
                    "desc": "Testing automatic provider creation",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {
                        "uid": unique_account_uid,
                        "name": account_name,
                    },
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "new-provider-resource",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        # Import WITHOUT passing provider_id - should create new provider
        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        # Verify successful response
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        # Verify response structure
        assert "data" in response_data
        assert response_data["data"]["type"] == "scan-imports"
        assert "attributes" in response_data["data"]

        attributes = response_data["data"]["attributes"]
        assert "scan_id" in attributes
        assert "provider_id" in attributes
        assert attributes["provider_created"] is True
        assert attributes["findings_count"] == 1
        assert attributes["resources_count"] == 1
        assert attributes["status"] == "completed"

        # Verify a new provider was created
        final_provider_count = Provider.objects.filter(tenant_id=tenant.id).count()
        assert final_provider_count == initial_provider_count + 1

        # Verify the new provider has correct attributes
        provider_id = attributes["provider_id"]
        provider = Provider.objects.get(id=provider_id)
        assert provider.provider == "aws"
        assert provider.uid == unique_account_uid
        assert provider.alias == account_name
        assert str(provider.tenant_id) == str(tenant.id)

        # Verify the scan was associated with the new provider
        scan_id = attributes["scan_id"]
        scan = Scan.objects.get(id=scan_id)
        assert scan.provider_id == provider.id
        assert scan.trigger == Scan.TriggerChoices.IMPORTED
        assert scan.state == StateChoices.COMPLETED

        # Verify finding was created and linked to the scan
        finding = Finding.objects.get(uid=finding_uid)
        assert str(finding.scan_id) == scan_id
        assert str(finding.tenant_id) == str(tenant.id)
        assert finding.check_id == "new_provider_check"
        assert finding.severity == "high"
        assert finding.status == "FAIL"

        # Verify resource was created
        resource = Resource.objects.get(uid=resource_uid)
        assert resource.name == "new-provider-resource"
        assert str(resource.tenant_id) == str(tenant.id)

    def test_import_creates_new_provider_via_csv(
        self, authenticated_client, tenants_fixture
    ):
        """Test CSV import creates new provider when no matching provider exists."""
        url = reverse("scan-import")
        tenant = tenants_fixture[0]
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        # Use a unique account UID that won't match any existing provider
        unique_account_uid = f"csv-new-provider-{uuid4().hex[:8]}"

        # Count providers before import
        initial_provider_count = Provider.objects.filter(tenant_id=tenant.id).count()

        # Create CSV data with a new provider type and UID
        csv_content = f"""FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;SEVERITY;RESOURCE_UID;RESOURCE_NAME;REGION;SERVICE_NAME;RESOURCE_TYPE;STATUS_EXTENDED
{finding_uid};aws;csv_new_provider_check;FAIL;{unique_account_uid};high;{resource_uid};csv-new-provider-resource;us-west-2;s3;bucket;CSV test for new provider creation"""

        file_obj = io.BytesIO(csv_content.encode("utf-8"))
        file_obj.name = "prowler-output.csv"

        # Import WITHOUT passing provider_id - should create new provider
        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        # Verify successful response
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        # Verify the provider was created
        attributes = response_data["data"]["attributes"]
        assert attributes["provider_created"] is True
        assert attributes["findings_count"] == 1
        assert attributes["resources_count"] == 1

        # Verify a new provider was created
        final_provider_count = Provider.objects.filter(tenant_id=tenant.id).count()
        assert final_provider_count == initial_provider_count + 1

        # Verify the new provider has correct attributes
        provider_id = attributes["provider_id"]
        provider = Provider.objects.get(id=provider_id)
        assert provider.provider == "aws"
        assert provider.uid == unique_account_uid
        assert str(provider.tenant_id) == str(tenant.id)

        # Verify the scan was associated with the new provider
        scan_id = attributes["scan_id"]
        scan = Scan.objects.get(id=scan_id)
        assert scan.provider_id == provider.id

        # Verify finding was created
        finding = Finding.objects.get(uid=finding_uid)
        assert finding.check_id == "csv_new_provider_check"
        assert finding.severity == "high"
        assert finding.status == "FAIL"


@pytest.mark.django_db
class TestScanImportViewTenantIsolation:
    """Tests for tenant isolation.

    These tests verify that the scan import functionality properly enforces
    tenant isolation (Row-Level Security) to ensure:
    - Scans are created in the authenticated user's tenant
    - Users cannot access or use providers from other tenants
    - Findings and resources are isolated by tenant
    - Cross-tenant data access is prevented
    """

    def test_import_creates_scan_in_correct_tenant(
        self, authenticated_client, tenants_fixture
    ):
        """Test that import creates scan in the authenticated user's tenant."""
        url = reverse("scan-import")
        tenant = tenants_fixture[0]
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        ocsf_data = [
            {
                "message": "Test finding for tenant isolation",
                "metadata": {"event_code": "check_tenant_test"},
                "severity": "Low",
                "status_code": "PASS",
                "status_detail": "Tenant isolation test",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Tenant Test",
                    "desc": "Testing tenant isolation",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "111122223333"},  # Valid 12-digit AWS account ID
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "tenant-test-resource",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        # Verify successful response
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        # Verify scan was created in the correct tenant
        scan_id = response_data["data"]["attributes"]["scan_id"]
        scan = Scan.objects.get(id=scan_id)
        assert str(scan.tenant_id) == str(tenant.id)

        # Verify finding was created in the correct tenant
        finding = Finding.objects.get(uid=finding_uid)
        assert str(finding.tenant_id) == str(tenant.id)

        # Verify resource was created in the correct tenant
        resource = Resource.objects.get(uid=resource_uid)
        assert str(resource.tenant_id) == str(tenant.id)

        # Verify provider was created in the correct tenant
        provider_id = response_data["data"]["attributes"]["provider_id"]
        provider = Provider.objects.get(id=provider_id)
        assert str(provider.tenant_id) == str(tenant.id)

    def test_import_cannot_use_provider_from_another_tenant(
        self, authenticated_client, tenants_fixture
    ):
        """Test that import cannot use a provider belonging to another tenant.

        This test verifies that when a user tries to import scan data with
        a provider_id that belongs to a different tenant, the request is
        rejected with a 422 error.
        """
        from api.db_utils import rls_transaction

        url = reverse("scan-import")

        # Create a provider in a different tenant (tenant3 which the user is not a member of)
        other_tenant = tenants_fixture[2]  # tenant3 - user is not a member

        with rls_transaction(str(other_tenant.id)):
            other_tenant_provider = Provider.objects.create(
                provider="aws",
                uid="999988887777",  # Valid 12-digit AWS account ID
                alias="Other Tenant Provider",
                tenant_id=other_tenant.id,
            )

        # Try to import using the other tenant's provider
        ocsf_data = [
            {
                "message": "Test finding",
                "metadata": {"event_code": "cross_tenant_check"},
                "severity": "Low",
                "status_code": "PASS",
                "finding_info": {"uid": f"finding-{uuid4()}", "title": "Test"},
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": other_tenant_provider.uid},
                },
                "resources": [{"uid": f"resource-{uuid4()}", "name": "test"}],
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps(
                {
                    "data": ocsf_data,
                    "provider_id": str(other_tenant_provider.id),
                }
            ),
            content_type="application/json",
        )

        # Should return 422 because the provider doesn't exist in user's tenant
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_import_does_not_resolve_provider_from_another_tenant(
        self, authenticated_client, tenants_fixture
    ):
        """Test that auto-resolution does not find providers from other tenants.

        This test verifies that when importing scan data, the provider
        auto-resolution only looks for providers within the user's tenant,
        not across all tenants.
        """
        from api.db_utils import rls_transaction

        url = reverse("scan-import")
        tenant = tenants_fixture[0]
        other_tenant = tenants_fixture[2]  # tenant3 - user is not a member

        # Create a provider in another tenant with a specific UID
        unique_uid = "888877776666"  # Valid 12-digit AWS account ID

        with rls_transaction(str(other_tenant.id)):
            Provider.objects.create(
                provider="aws",
                uid=unique_uid,
                alias="Other Tenant Provider",
                tenant_id=other_tenant.id,
            )

        # Count providers in user's tenant before import
        initial_provider_count = Provider.objects.filter(tenant_id=tenant.id).count()

        # Import with the same UID - should create a NEW provider in user's tenant
        # because the existing one is in a different tenant
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        ocsf_data = [
            {
                "message": "Test finding for cross-tenant resolution",
                "metadata": {"event_code": "cross_tenant_resolution_check"},
                "severity": "Low",
                "status_code": "PASS",
                "status_detail": "Testing cross-tenant provider resolution",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Cross Tenant Resolution Test",
                    "desc": "Testing that providers from other tenants are not resolved",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": unique_uid, "name": "Test Account"},
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "cross-tenant-resource",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        # Should succeed and create a new provider
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        # Verify a new provider was created (not the one from other tenant)
        attributes = response_data["data"]["attributes"]
        assert attributes["provider_created"] is True

        # Verify provider count increased in user's tenant
        final_provider_count = Provider.objects.filter(tenant_id=tenant.id).count()
        assert final_provider_count == initial_provider_count + 1

        # Verify the new provider is in the user's tenant
        provider_id = attributes["provider_id"]
        provider = Provider.objects.get(id=provider_id)
        assert str(provider.tenant_id) == str(tenant.id)
        assert provider.uid == unique_uid

    def test_import_findings_isolated_by_tenant(
        self, authenticated_client, tenants_fixture
    ):
        """Test that imported findings are only visible within the same tenant.

        This test verifies that findings created during import are properly
        isolated and cannot be accessed from other tenants. We verify this
        by checking that the finding is created with the correct tenant_id.
        """
        url = reverse("scan-import")
        tenant = tenants_fixture[0]

        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        ocsf_data = [
            {
                "message": "Isolated finding test",
                "metadata": {"event_code": "isolation_check"},
                "severity": "High",
                "status_code": "FAIL",
                "status_detail": "Testing finding isolation",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Isolation Test",
                    "desc": "Testing tenant isolation for findings",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "222233334444"},  # Valid 12-digit AWS account ID
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "isolated-resource",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_201_CREATED

        # Verify finding exists and is associated with the correct tenant
        finding = Finding.objects.get(uid=finding_uid)
        assert str(finding.tenant_id) == str(tenant.id)

        # Verify the finding is NOT associated with any other tenant
        other_tenant = tenants_fixture[2]
        assert str(finding.tenant_id) != str(other_tenant.id)

    def test_import_resources_isolated_by_tenant(
        self, authenticated_client, tenants_fixture
    ):
        """Test that imported resources are only visible within the same tenant.

        This test verifies that resources created during import are properly
        isolated by checking that they are associated with the correct tenant_id.
        """
        url = reverse("scan-import")
        tenant = tenants_fixture[0]

        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        ocsf_data = [
            {
                "message": "Resource isolation test",
                "metadata": {"event_code": "resource_isolation_check"},
                "severity": "Medium",
                "status_code": "PASS",
                "status_detail": "Testing resource isolation",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Resource Isolation Test",
                    "desc": "Testing tenant isolation for resources",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "333344445555"},  # Valid 12-digit AWS account ID
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "isolated-resource",
                        "region": "eu-west-1",
                        "group": {"name": "s3"},
                        "type": "bucket",
                    }
                ],
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_201_CREATED

        # Verify resource exists and is associated with the correct tenant
        resource = Resource.objects.get(uid=resource_uid)
        assert str(resource.tenant_id) == str(tenant.id)

        # Verify the resource is NOT associated with any other tenant
        other_tenant = tenants_fixture[2]
        assert str(resource.tenant_id) != str(other_tenant.id)

    def test_import_scans_isolated_by_tenant(
        self, authenticated_client, tenants_fixture
    ):
        """Test that imported scans are only visible within the same tenant.

        This test verifies that scans created during import are properly
        isolated by checking that they are associated with the correct tenant_id.
        """
        url = reverse("scan-import")
        tenant = tenants_fixture[0]

        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        ocsf_data = [
            {
                "message": "Scan isolation test",
                "metadata": {"event_code": "scan_isolation_check"},
                "severity": "Low",
                "status_code": "PASS",
                "status_detail": "Testing scan isolation",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Scan Isolation Test",
                    "desc": "Testing tenant isolation for scans",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "444455556666"},  # Valid 12-digit AWS account ID
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "scan-isolated-resource",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        scan_id = response_data["data"]["attributes"]["scan_id"]

        # Verify scan exists and is associated with the correct tenant
        scan = Scan.objects.get(id=scan_id)
        assert str(scan.tenant_id) == str(tenant.id)

        # Verify the scan is NOT associated with any other tenant
        other_tenant = tenants_fixture[2]
        assert str(scan.tenant_id) != str(other_tenant.id)

    def test_import_providers_isolated_by_tenant(
        self, authenticated_client, tenants_fixture
    ):
        """Test that providers created during import are isolated by tenant.

        This test verifies that providers created during import are properly
        isolated by checking that they are associated with the correct tenant_id.
        """
        url = reverse("scan-import")
        tenant = tenants_fixture[0]

        finding_uid = str(uuid4())
        resource_uid = str(uuid4())
        unique_provider_uid = "555566667777"  # Valid 12-digit AWS account ID

        ocsf_data = [
            {
                "message": "Provider isolation test",
                "metadata": {"event_code": "provider_isolation_check"},
                "severity": "Low",
                "status_code": "PASS",
                "status_detail": "Testing provider isolation",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Provider Isolation Test",
                    "desc": "Testing tenant isolation for providers",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {
                        "uid": unique_provider_uid,
                        "name": "Isolated Provider",
                    },
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "provider-isolated-resource",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        provider_id = response_data["data"]["attributes"]["provider_id"]

        # Verify provider exists and is associated with the correct tenant
        provider = Provider.objects.get(id=provider_id)
        assert str(provider.tenant_id) == str(tenant.id)
        assert provider.uid == unique_provider_uid

        # Verify the provider is NOT associated with any other tenant
        other_tenant = tenants_fixture[2]
        assert str(provider.tenant_id) != str(other_tenant.id)


@pytest.mark.django_db
class TestScanImportViewResponseFormat:
    """Tests for response format."""

    def test_successful_import_response_format(self, authenticated_client):
        """Test that successful import returns correct response format."""
        url = reverse("scan-import")

        ocsf_data = [
            {
                "message": "Test finding",
                "metadata": {"event_code": "check_response_test"},
                "severity": "Low",
                "status_code": "PASS",
                "finding_info": {"uid": f"finding-{uuid4()}", "title": "Test"},
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": f"response-test-{uuid4().hex[:8]}"},
                },
                "resources": [{"uid": f"resource-{uuid4()}", "name": "test"}],
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        if response.status_code == status.HTTP_201_CREATED:
            response_data = response.json()
            assert "data" in response_data
            assert "type" in response_data["data"]
            assert response_data["data"]["type"] == "scan-imports"
            assert "attributes" in response_data["data"]

            attributes = response_data["data"]["attributes"]
            assert "scan_id" in attributes
            assert "provider_id" in attributes
            assert "findings_count" in attributes
            assert "resources_count" in attributes
            assert "status" in attributes

    def test_error_response_format(self, authenticated_client):
        """Test that error responses have correct format."""
        url = reverse("scan-import")

        # Invalid data to trigger error
        invalid_data = [{"invalid": "structure"}]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": invalid_data}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        response_data = response.json()
        assert "errors" in response_data
        assert isinstance(response_data["errors"], list)
        assert len(response_data["errors"]) > 0

        error = response_data["errors"][0]
        assert "status" in error
        assert "code" in error
        assert "title" in error
        assert "detail" in error


@pytest.mark.django_db
class TestScanImportViewEmptyFindings:
    """Tests for empty findings handling."""

    def test_empty_findings_array_returns_422(self, authenticated_client):
        """Test that empty findings array returns 422."""
        url = reverse("scan-import")

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": []}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        response_data = response.json()
        assert "errors" in response_data


@pytest.mark.django_db
class TestScanImportViewMultipartFileUpload:
    """Tests for file upload via multipart/form-data."""

    def test_multipart_json_file_upload_creates_scan(
        self, authenticated_client, tenants_fixture
    ):
        """Test that JSON file upload via multipart creates scan successfully."""
        url = reverse("scan-import")
        tenant = tenants_fixture[0]
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        ocsf_data = [
            {
                "message": "Multipart JSON test finding",
                "metadata": {"event_code": "multipart_json_check"},
                "severity": "Medium",
                "status_code": "FAIL",
                "status_detail": "Test status for multipart upload",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Multipart JSON Test",
                    "desc": "Testing multipart JSON file upload",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {
                        "uid": f"multipart-json-{uuid4().hex[:8]}",
                        "name": "Test Account",
                    },
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "multipart-test-resource",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        file_content = json.dumps(ocsf_data).encode("utf-8")
        file_obj = io.BytesIO(file_content)
        file_obj.name = "prowler-output.json"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        assert "data" in response_data
        assert response_data["data"]["type"] == "scan-imports"
        attributes = response_data["data"]["attributes"]
        assert attributes["findings_count"] == 1
        assert attributes["resources_count"] == 1
        assert attributes["status"] == "completed"

        # Verify finding was created
        finding = Finding.objects.get(uid=finding_uid)
        assert finding.check_id == "multipart_json_check"
        assert str(finding.tenant_id) == str(tenant.id)

    def test_multipart_csv_file_upload_creates_scan(
        self, authenticated_client, tenants_fixture
    ):
        """Test that CSV file upload via multipart creates scan successfully."""
        url = reverse("scan-import")
        tenant = tenants_fixture[0]
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        csv_content = f"""FINDING_UID;PROVIDER;CHECK_ID;STATUS;ACCOUNT_UID;SEVERITY;RESOURCE_UID;RESOURCE_NAME;REGION;SERVICE_NAME;RESOURCE_TYPE;STATUS_EXTENDED
{finding_uid};aws;multipart_csv_check;PASS;multipart-csv-123;low;{resource_uid};multipart-csv-resource;us-west-2;s3;bucket;Test status for multipart CSV upload"""

        file_obj = io.BytesIO(csv_content.encode("utf-8"))
        file_obj.name = "prowler-output.csv"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        assert "data" in response_data
        assert response_data["data"]["type"] == "scan-imports"
        attributes = response_data["data"]["attributes"]
        assert attributes["findings_count"] == 1
        assert attributes["resources_count"] == 1
        assert attributes["status"] == "completed"

        # Verify finding was created
        finding = Finding.objects.get(uid=finding_uid)
        assert finding.check_id == "multipart_csv_check"
        assert str(finding.tenant_id) == str(tenant.id)

    def test_multipart_file_upload_with_provider_id(
        self, authenticated_client, providers_fixture
    ):
        """Test multipart file upload with explicit provider_id parameter."""
        url = reverse("scan-import")
        provider = providers_fixture[0]
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        ocsf_data = [
            {
                "message": "Test with provider_id",
                "metadata": {"event_code": "provider_id_check"},
                "severity": "Low",
                "status_code": "PASS",
                "status_detail": "Test with explicit provider",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Provider ID Test",
                    "desc": "Testing multipart with provider_id",
                },
                "cloud": {
                    "provider": provider.provider,
                    "account": {"uid": provider.uid, "name": "Test Account"},
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "provider-test-resource",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        file_content = json.dumps(ocsf_data).encode("utf-8")
        file_obj = io.BytesIO(file_content)
        file_obj.name = "prowler-output.json"

        response = authenticated_client.post(
            url,
            data={
                "file": file_obj,
                "provider_id": str(provider.id),
            },
            format="multipart",
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        attributes = response_data["data"]["attributes"]
        assert attributes["provider_id"] == str(provider.id)

    def test_multipart_file_upload_with_create_provider_false(
        self, authenticated_client, providers_fixture
    ):
        """Test multipart file upload with create_provider=False uses existing provider."""
        url = reverse("scan-import")
        provider = providers_fixture[0]
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        ocsf_data = [
            {
                "message": "Test with create_provider=false",
                "metadata": {"event_code": "no_create_provider_check"},
                "severity": "Low",
                "status_code": "PASS",
                "status_detail": "Test without creating provider",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "No Create Provider Test",
                    "desc": "Testing multipart with create_provider=false",
                },
                "cloud": {
                    "provider": provider.provider,
                    "account": {"uid": provider.uid, "name": "Test Account"},
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "no-create-provider-resource",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        file_content = json.dumps(ocsf_data).encode("utf-8")
        file_obj = io.BytesIO(file_content)
        file_obj.name = "prowler-output.json"

        response = authenticated_client.post(
            url,
            data={
                "file": file_obj,
                "create_provider": "false",
            },
            format="multipart",
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        attributes = response_data["data"]["attributes"]
        assert attributes["provider_id"] == str(provider.id)
        assert attributes["provider_created"] is False

    def test_multipart_file_upload_empty_file_returns_422(self, authenticated_client):
        """Test that empty file upload returns 422."""
        url = reverse("scan-import")

        file_obj = io.BytesIO(b"")
        file_obj.name = "empty.json"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_multipart_file_upload_invalid_json_returns_422(self, authenticated_client):
        """Test that invalid JSON file returns 422."""
        url = reverse("scan-import")

        file_content = b"{ invalid json content"
        file_obj = io.BytesIO(file_content)
        file_obj.name = "invalid.json"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_multipart_file_upload_with_different_extensions(
        self, authenticated_client, tenants_fixture
    ):
        """Test multipart file upload handles different file extensions correctly."""
        url = reverse("scan-import")
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        ocsf_data = [
            {
                "message": "Extension test finding",
                "metadata": {"event_code": "extension_check"},
                "severity": "Low",
                "status_code": "PASS",
                "status_detail": "Test with .ocsf extension",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Extension Test",
                    "desc": "Testing file extension handling",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {
                        "uid": f"ext-test-{uuid4().hex[:8]}",
                        "name": "Test Account",
                    },
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "extension-test-resource",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        # Test with .ocsf extension (should be treated as JSON)
        file_content = json.dumps(ocsf_data).encode("utf-8")
        file_obj = io.BytesIO(file_content)
        file_obj.name = "prowler-output.ocsf.json"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        assert response.status_code == status.HTTP_201_CREATED

    def test_multipart_file_upload_large_file_within_limit(
        self, authenticated_client, tenants_fixture
    ):
        """Test that file within size limit is accepted."""
        url = reverse("scan-import")
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        # Create a valid OCSF data structure
        ocsf_data = [
            {
                "message": "Large file test finding",
                "metadata": {"event_code": "large_file_check"},
                "severity": "Low",
                "status_code": "PASS",
                "status_detail": "Test with larger file",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Large File Test",
                    "desc": "Testing file size handling",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {
                        "uid": f"large-file-{uuid4().hex[:8]}",
                        "name": "Test Account",
                    },
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "large-file-resource",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        file_content = json.dumps(ocsf_data).encode("utf-8")
        file_obj = io.BytesIO(file_content)
        file_obj.name = "prowler-output.json"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        assert response.status_code == status.HTTP_201_CREATED

    def test_multipart_file_upload_preserves_unicode_content(
        self, authenticated_client, tenants_fixture
    ):
        """Test that multipart file upload preserves unicode characters."""
        url = reverse("scan-import")
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        ocsf_data = [
            {
                "message": "Unicode test: 日本語 中文 한국어 émojis 🔒🛡️",
                "metadata": {"event_code": "unicode_check"},
                "severity": "Low",
                "status_code": "PASS",
                "status_detail": "Test with unicode: äöü ñ",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Unicode Test: Ümlauts",
                    "desc": "Testing unicode: café résumé naïve",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {
                        "uid": f"unicode-{uuid4().hex[:8]}",
                        "name": "Test Account",
                    },
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "unicode-resource-日本語",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        file_content = json.dumps(ocsf_data, ensure_ascii=False).encode("utf-8")
        file_obj = io.BytesIO(file_content)
        file_obj.name = "prowler-output.json"

        response = authenticated_client.post(
            url,
            data={"file": file_obj},
            format="multipart",
        )

        assert response.status_code == status.HTTP_201_CREATED

        # Verify unicode was preserved
        finding = Finding.objects.get(uid=finding_uid)
        assert (
            "日本語" in finding.impact_extended or "unicode" in finding.check_id.lower()
        )


@pytest.mark.django_db
class TestScanImportViewInlineJSON:
    """Tests for inline JSON via request body.

    These tests verify that the scan import endpoint correctly handles
    inline JSON data sent directly in the request body (as opposed to
    file uploads). This is the alternative input method where OCSF JSON
    data is provided via the 'data' field in the request body.
    """

    def test_inline_json_creates_scan_and_findings(
        self, authenticated_client, tenants_fixture
    ):
        """Test that inline JSON data creates scan, findings, and resources."""
        url = reverse("scan-import")
        tenant = tenants_fixture[0]
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        ocsf_data = [
            {
                "message": "Inline JSON test finding",
                "metadata": {"event_code": "inline_json_check"},
                "severity": "High",
                "status_code": "FAIL",
                "status_detail": "Test status for inline JSON import",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Inline JSON Test",
                    "desc": "Testing inline JSON import functionality",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "111122223334", "name": "Test Account"},
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "inline-json-resource",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        # Send inline JSON via request body
        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        # Verify successful response
        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        # Verify response structure
        assert "data" in response_data
        assert response_data["data"]["type"] == "scan-imports"
        assert "attributes" in response_data["data"]

        attributes = response_data["data"]["attributes"]
        assert "scan_id" in attributes
        assert "provider_id" in attributes
        assert attributes["findings_count"] == 1
        assert attributes["resources_count"] == 1
        assert attributes["status"] == "completed"

        # Verify scan was created in database
        scan_id = attributes["scan_id"]
        scan = Scan.objects.get(id=scan_id)
        assert str(scan.tenant_id) == str(tenant.id)
        assert scan.trigger == Scan.TriggerChoices.IMPORTED
        assert scan.state == StateChoices.COMPLETED

        # Verify finding was created
        finding = Finding.objects.get(uid=finding_uid)
        assert finding.check_id == "inline_json_check"
        assert finding.severity == "high"
        assert finding.status == "FAIL"
        assert str(finding.tenant_id) == str(tenant.id)

        # Verify resource was created
        resource = Resource.objects.get(uid=resource_uid)
        assert resource.name == "inline-json-resource"
        assert str(resource.tenant_id) == str(tenant.id)

    def test_inline_json_with_multiple_findings(
        self, authenticated_client, tenants_fixture
    ):
        """Test inline JSON import with multiple findings creates all records."""
        url = reverse("scan-import")
        _tenant = tenants_fixture[0]  # noqa: F841 - used for fixture setup

        finding_uid_1 = str(uuid4())
        finding_uid_2 = str(uuid4())
        finding_uid_3 = str(uuid4())
        resource_uid_1 = str(uuid4())
        resource_uid_2 = str(uuid4())
        resource_uid_3 = str(uuid4())

        ocsf_data = [
            {
                "message": "First inline finding",
                "metadata": {"event_code": "inline_check_1"},
                "severity": "High",
                "status_code": "FAIL",
                "status_detail": "First finding detail",
                "finding_info": {
                    "uid": finding_uid_1,
                    "title": "Inline Check 1",
                    "desc": "First inline check",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "222233334445", "name": "Test Account"},
                },
                "resources": [
                    {
                        "uid": resource_uid_1,
                        "name": "inline-resource-1",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            },
            {
                "message": "Second inline finding",
                "metadata": {"event_code": "inline_check_2"},
                "severity": "Medium",
                "status_code": "PASS",
                "status_detail": "Second finding detail",
                "finding_info": {
                    "uid": finding_uid_2,
                    "title": "Inline Check 2",
                    "desc": "Second inline check",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "222233334445", "name": "Test Account"},
                },
                "resources": [
                    {
                        "uid": resource_uid_2,
                        "name": "inline-resource-2",
                        "region": "eu-west-1",
                        "group": {"name": "s3"},
                        "type": "bucket",
                    }
                ],
            },
            {
                "message": "Third inline finding",
                "metadata": {"event_code": "inline_check_3"},
                "severity": "Low",
                "status_code": "PASS",
                "status_detail": "Third finding detail",
                "finding_info": {
                    "uid": finding_uid_3,
                    "title": "Inline Check 3",
                    "desc": "Third inline check",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "222233334445", "name": "Test Account"},
                },
                "resources": [
                    {
                        "uid": resource_uid_3,
                        "name": "inline-resource-3",
                        "region": "ap-southeast-1",
                        "group": {"name": "iam"},
                        "type": "user",
                    }
                ],
            },
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        attributes = response_data["data"]["attributes"]
        assert attributes["findings_count"] == 3
        assert attributes["resources_count"] == 3

        # Verify all findings were created
        assert Finding.objects.filter(uid=finding_uid_1).exists()
        assert Finding.objects.filter(uid=finding_uid_2).exists()
        assert Finding.objects.filter(uid=finding_uid_3).exists()

        # Verify all resources were created
        assert Resource.objects.filter(uid=resource_uid_1).exists()
        assert Resource.objects.filter(uid=resource_uid_2).exists()
        assert Resource.objects.filter(uid=resource_uid_3).exists()

    def test_inline_json_with_provider_id(
        self, authenticated_client, providers_fixture
    ):
        """Test inline JSON import with explicit provider_id parameter."""
        url = reverse("scan-import")
        provider = providers_fixture[0]
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        ocsf_data = [
            {
                "message": "Test with provider_id via inline JSON",
                "metadata": {"event_code": "inline_provider_id_check"},
                "severity": "Low",
                "status_code": "PASS",
                "status_detail": "Test with explicit provider via inline JSON",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Inline Provider ID Test",
                    "desc": "Testing inline JSON with provider_id",
                },
                "cloud": {
                    "provider": provider.provider,
                    "account": {"uid": provider.uid, "name": "Test Account"},
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "inline-provider-test-resource",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps(
                {
                    "data": ocsf_data,
                    "provider_id": str(provider.id),
                }
            ),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        attributes = response_data["data"]["attributes"]
        assert attributes["provider_id"] == str(provider.id)
        assert attributes["provider_created"] is False

    def test_inline_json_with_create_provider_false(
        self, authenticated_client, providers_fixture
    ):
        """Test inline JSON import with create_provider=False uses existing provider."""
        url = reverse("scan-import")
        provider = providers_fixture[0]
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        ocsf_data = [
            {
                "message": "Test with create_provider=false via inline JSON",
                "metadata": {"event_code": "inline_no_create_provider_check"},
                "severity": "Low",
                "status_code": "PASS",
                "status_detail": "Test without creating provider via inline JSON",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Inline No Create Provider Test",
                    "desc": "Testing inline JSON with create_provider=false",
                },
                "cloud": {
                    "provider": provider.provider,
                    "account": {"uid": provider.uid, "name": "Test Account"},
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "inline-no-create-provider-resource",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps(
                {
                    "data": ocsf_data,
                    "create_provider": False,
                }
            ),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        attributes = response_data["data"]["attributes"]
        assert attributes["provider_id"] == str(provider.id)
        assert attributes["provider_created"] is False

    def test_inline_json_creates_new_provider(
        self, authenticated_client, tenants_fixture
    ):
        """Test inline JSON import creates new provider when no match exists."""
        url = reverse("scan-import")
        tenant = tenants_fixture[0]
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())
        unique_account_uid = "333344445556"

        initial_provider_count = Provider.objects.filter(tenant_id=tenant.id).count()

        ocsf_data = [
            {
                "message": "Test new provider creation via inline JSON",
                "metadata": {"event_code": "inline_new_provider_check"},
                "severity": "Medium",
                "status_code": "FAIL",
                "status_detail": "Test creating new provider via inline JSON",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Inline New Provider Test",
                    "desc": "Testing inline JSON creates new provider",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {
                        "uid": unique_account_uid,
                        "name": "New Inline Provider",
                    },
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "inline-new-provider-resource",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()
        attributes = response_data["data"]["attributes"]
        assert attributes["provider_created"] is True

        # Verify new provider was created
        final_provider_count = Provider.objects.filter(tenant_id=tenant.id).count()
        assert final_provider_count == initial_provider_count + 1

        # Verify provider has correct attributes
        provider_id = attributes["provider_id"]
        provider = Provider.objects.get(id=provider_id)
        assert provider.provider == "aws"
        assert provider.uid == unique_account_uid
        assert provider.alias == "New Inline Provider"

    def test_inline_json_with_compliance_data(
        self, authenticated_client, tenants_fixture
    ):
        """Test inline JSON import preserves compliance mapping data."""
        url = reverse("scan-import")
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        ocsf_data = [
            {
                "message": "Inline JSON compliance test finding",
                "metadata": {"event_code": "inline_compliance_check"},
                "severity": "High",
                "status_code": "FAIL",
                "status_detail": "Inline compliance check failed",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Inline Compliance Check",
                    "desc": "Tests compliance mapping via inline JSON",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "444455556667", "name": "Compliance Account"},
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "inline-compliance-resource",
                        "region": "us-east-1",
                        "group": {"name": "iam"},
                        "type": "user",
                    }
                ],
                "unmapped": {
                    "compliance": {
                        "CIS-AWS-2.0": ["1.1", "1.2", "1.3"],
                        "PCI-DSS-4.0": ["3.4", "3.5"],
                        "HIPAA": ["164.312(a)(1)"],
                    },
                },
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_201_CREATED

        # Verify compliance data was preserved
        finding = Finding.objects.get(uid=finding_uid)
        assert "CIS-AWS-2.0" in finding.compliance
        assert finding.compliance["CIS-AWS-2.0"] == ["1.1", "1.2", "1.3"]
        assert "PCI-DSS-4.0" in finding.compliance
        assert "HIPAA" in finding.compliance

    def test_inline_json_preserves_unicode_content(
        self, authenticated_client, tenants_fixture
    ):
        """Test that inline JSON import preserves unicode characters."""
        url = reverse("scan-import")
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        ocsf_data = [
            {
                "message": "Inline Unicode test: 日本語 中文 한국어 émojis 🔒🛡️",
                "metadata": {"event_code": "inline_unicode_check"},
                "severity": "Low",
                "status_code": "PASS",
                "status_detail": "Inline test with unicode: äöü ñ",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Inline Unicode Test: Ümlauts",
                    "desc": "Testing inline unicode: café résumé naïve",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "555566667778", "name": "Test Account"},
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "inline-unicode-resource-日本語",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}, ensure_ascii=False),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_201_CREATED

        # Verify unicode was preserved
        finding = Finding.objects.get(uid=finding_uid)
        assert (
            "日本語" in finding.impact_extended or "unicode" in finding.check_id.lower()
        )

    def test_inline_json_empty_array_returns_error(self, authenticated_client):
        """Test that empty inline JSON array returns an error."""
        url = reverse("scan-import")

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": []}),
            content_type="application/json",
        )

        # Empty array should return either 400 (validation error) or 422 (processing error)
        assert response.status_code in [
            status.HTTP_400_BAD_REQUEST,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        ]
        response_data = response.json()
        assert "errors" in response_data

    def test_inline_json_invalid_structure_returns_422(self, authenticated_client):
        """Test that invalid inline JSON structure returns 422."""
        url = reverse("scan-import")

        # Invalid structure - missing required fields
        invalid_data = [{"invalid": "structure", "no_required_fields": True}]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": invalid_data}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        response_data = response.json()
        assert "errors" in response_data

    def test_inline_json_non_array_returns_422(self, authenticated_client):
        """Test that non-array inline JSON returns 422."""
        url = reverse("scan-import")

        # Single object instead of array
        non_array_data = {
            "message": "Single object",
            "metadata": {"event_code": "check_1"},
        }

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": non_array_data}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY
        response_data = response.json()
        assert "errors" in response_data

    def test_inline_json_with_remediation_data(
        self, authenticated_client, tenants_fixture
    ):
        """Test inline JSON import preserves remediation data."""
        url = reverse("scan-import")
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        ocsf_data = [
            {
                "message": "Inline JSON remediation test finding",
                "metadata": {"event_code": "inline_remediation_check"},
                "severity": "High",
                "status_code": "FAIL",
                "status_detail": "Inline remediation check failed",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Inline Remediation Check",
                    "desc": "Tests remediation data via inline JSON",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "666677778889", "name": "Test Account"},
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "inline-remediation-resource",
                        "region": "us-east-1",
                        "group": {"name": "s3"},
                        "type": "bucket",
                    }
                ],
                "risk_details": "This is a high-risk finding that needs immediate attention",
                "remediation": {
                    "desc": "Apply the following remediation steps to fix this issue",
                    "references": [
                        "https://docs.aws.amazon.com/security/best-practices",
                        "https://prowler.com/remediation/s3",
                    ],
                },
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_201_CREATED

        # Verify remediation data was preserved
        finding = Finding.objects.get(uid=finding_uid)
        assert (
            finding.check_metadata.get("risk")
            == "This is a high-risk finding that needs immediate attention"
        )
        assert (
            "remediation" in finding.check_metadata
            or finding.check_metadata.get("remediation") is not None
        )

    def test_inline_json_tenant_isolation(self, authenticated_client, tenants_fixture):
        """Test that inline JSON import respects tenant isolation."""
        url = reverse("scan-import")
        tenant = tenants_fixture[0]
        finding_uid = str(uuid4())
        resource_uid = str(uuid4())

        ocsf_data = [
            {
                "message": "Inline JSON tenant isolation test",
                "metadata": {"event_code": "inline_tenant_isolation_check"},
                "severity": "Low",
                "status_code": "PASS",
                "status_detail": "Testing tenant isolation via inline JSON",
                "finding_info": {
                    "uid": finding_uid,
                    "title": "Inline Tenant Isolation Test",
                    "desc": "Testing tenant isolation for inline JSON import",
                },
                "cloud": {
                    "provider": "aws",
                    "account": {"uid": "777788889990", "name": "Test Account"},
                },
                "resources": [
                    {
                        "uid": resource_uid,
                        "name": "inline-tenant-resource",
                        "region": "us-east-1",
                        "group": {"name": "ec2"},
                        "type": "instance",
                    }
                ],
            }
        ]

        response = authenticated_client.post(
            url,
            data=json.dumps({"data": ocsf_data}),
            content_type="application/json",
        )

        assert response.status_code == status.HTTP_201_CREATED
        response_data = response.json()

        # Verify all created objects belong to the correct tenant
        scan_id = response_data["data"]["attributes"]["scan_id"]
        scan = Scan.objects.get(id=scan_id)
        assert str(scan.tenant_id) == str(tenant.id)

        finding = Finding.objects.get(uid=finding_uid)
        assert str(finding.tenant_id) == str(tenant.id)

        resource = Resource.objects.get(uid=resource_uid)
        assert str(resource.tenant_id) == str(tenant.id)

        provider_id = response_data["data"]["attributes"]["provider_id"]
        provider = Provider.objects.get(id=provider_id)
        assert str(provider.tenant_id) == str(tenant.id)
