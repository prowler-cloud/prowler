from unittest import mock

import pytest
from pydantic.v1 import ValidationError

from prowler.lib.check.models import CheckMetadata
from tests.lib.check.compliance_check_test import custom_compliance_metadata

mock_metadata = CheckMetadata(
    Provider="azure",  # Using non-AWS provider to avoid config validation issues
    CheckID="accessanalyzer_enabled",
    CheckTitle="Check 1",
    CheckType=["Security"],
    ServiceName="accessanalyzer",
    SubServiceName="subservice1",
    ResourceIdTemplate="template1",
    Severity="high",
    ResourceType="resource1",
    Description="Description 1",
    Risk="risk1",
    RelatedUrl="url1",
    Remediation={
        "Code": {
            "CLI": "cli1",
            "NativeIaC": "native1",
            "Other": "other1",
            "Terraform": "terraform1",
        },
        "Recommendation": {"Text": "text1", "Url": "url1"},
    },
    Categories=["categoryone"],
    DependsOn=["dependency1"],
    RelatedTo=["related1"],
    Notes="notes1",
    Compliance=[],
)

mock_metadata_lambda = CheckMetadata(
    Provider="azure",  # Using non-AWS provider to avoid config validation issues
    CheckID="awslambda_function_url_public",
    CheckTitle="Check 1",
    CheckType=["Security"],
    ServiceName="awslambda",
    SubServiceName="subservice1",
    ResourceIdTemplate="template1",
    Severity="high",
    ResourceType="resource1",
    Description="Description 1",
    Risk="risk1",
    RelatedUrl="url1",
    Remediation={
        "Code": {
            "CLI": "cli1",
            "NativeIaC": "native1",
            "Other": "other1",
            "Terraform": "terraform1",
        },
        "Recommendation": {"Text": "text1", "Url": "url1"},
    },
    Categories=["categoryone"],
    DependsOn=["dependency1"],
    RelatedTo=["related1"],
    Notes="notes1",
    Compliance=[],
)


class TestCheckMetada:

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_get_bulk(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        result = CheckMetadata.get_bulk(provider="aws")

        # Assertions
        assert "accessanalyzer_enabled" in result.keys()
        assert result["accessanalyzer_enabled"] == mock_metadata
        mock_recover_checks.assert_called_once_with("aws")
        mock_load_metadata.assert_called_once_with(
            "/path/to/accessanalyzer_enabled/accessanalyzer_enabled.metadata.json"
        )

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(bulk_checks_metadata=bulk_metadata)

        # Assertions
        assert result == {"accessanalyzer_enabled"}

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_get(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(bulk_checks_metadata=bulk_metadata)

        # Assertions
        assert result == {"accessanalyzer_enabled"}

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_by_severity(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(bulk_checks_metadata=bulk_metadata, severity="high")

        # Assertions
        assert result == {"accessanalyzer_enabled"}

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_by_severity_not_values(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(bulk_checks_metadata=bulk_metadata, severity="low")

        # Assertions
        assert result == set()

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_by_category(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(
            bulk_checks_metadata=bulk_metadata, category="categoryone"
        )

        # Assertions
        assert result == {"accessanalyzer_enabled"}

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_by_category_not_valid(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(
            bulk_checks_metadata=bulk_metadata, category="categorytwo"
        )

        # Assertions
        assert result == set()

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_by_service(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(
            bulk_checks_metadata=bulk_metadata, service="accessanalyzer"
        )

        # Assertions
        assert result == {"accessanalyzer_enabled"}

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_by_service_lambda(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("awslambda_function_url_public", "/path/to/awslambda_function_url_public")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata_lambda

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(
            bulk_checks_metadata=bulk_metadata, service="lambda"
        )

        # Assertions
        assert result == {"awslambda_function_url_public"}

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_by_service_awslambda(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("awslambda_function_url_public", "/path/to/awslambda_function_url_public")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata_lambda

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(
            bulk_checks_metadata=bulk_metadata, service="awslambda"
        )

        # Assertions
        assert result == {"awslambda_function_url_public"}

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_by_service_invalid(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(
            bulk_checks_metadata=bulk_metadata, service="service2"
        )

        # Assertions
        assert result == set()

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_by_compliance(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")
        bulk_compliance_frameworks = custom_compliance_metadata

        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(
            bulk_checks_metadata=bulk_metadata,
            bulk_compliance_frameworks=bulk_compliance_frameworks,
            compliance_framework="framework1_aws",
        )

        # Assertions
        assert result == {"accessanalyzer_enabled"}

    @mock.patch("prowler.lib.check.models.CheckMetadata.get_bulk")
    def test_list_by_compliance_empty(self, mock_get_bulk):
        mock_get_bulk.return_value = {}
        bulk_compliance_frameworks = custom_compliance_metadata
        result = CheckMetadata.list(
            bulk_compliance_frameworks=bulk_compliance_frameworks,
            compliance_framework="framework1_azure",
        )
        # Assertions
        assert result == set()

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_list_only_check_metadata(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = mock_metadata

        bulk_metadata = CheckMetadata.get_bulk(provider="aws")

        result = CheckMetadata.list(bulk_checks_metadata=bulk_metadata)
        assert result == set()


class TestCheckMetadataValidators:
    """Test class for CheckMetadata validators"""

    def test_valid_category_success(self):
        """Test valid category validation with valid categories"""
        valid_metadata = {
            "Provider": "azure",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["Security"],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security", "network", "data-protection"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        # Should not raise any validation error
        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.Categories == ["security", "network", "data-protection"]

    def test_valid_category_failure_non_string(self):
        """Test valid category validation fails with non-string category"""
        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["Security"],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": [123],  # Invalid: number instead of string
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert "Categories must be a list of strings" in str(exc_info.value)

    def test_valid_category_failure_invalid_format(self):
        """Test valid category validation fails with invalid format"""
        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["Security"],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["invalid_category!"],  # Invalid: contains special character
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert (
            "Categories can only contain lowercase letters, numbers and hyphen"
            in str(exc_info.value)
        )

    def test_severity_to_lower_success(self):
        """Test severity validation converts to lowercase"""
        valid_metadata = {
            "Provider": "azure",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["Security"],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "HIGH",  # Uppercase - should be converted to lowercase
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.Severity == "high"

    def test_valid_cli_command_success(self):
        """Test CLI command validation with valid command"""
        valid_metadata = {
            "Provider": "azure",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["Security"],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "aws iam create-role --role-name test",  # Valid CLI command
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        # Should not raise any validation error
        check_metadata = CheckMetadata(**valid_metadata)
        assert "aws iam create-role" in check_metadata.Remediation.Code.CLI

    def test_valid_cli_command_failure_url(self):
        """Test CLI command validation fails with URL"""
        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["Security"],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "https://example.com/command",  # Invalid: URL instead of command
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert "CLI command cannot be an URL" in str(exc_info.value)

    def test_valid_resource_type_success(self):
        """Test resource type validation with valid resource type"""
        valid_metadata = {
            "Provider": "azure",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["Security"],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "AWS::IAM::Role",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.ResourceType == "AWS::IAM::Role"

    def test_valid_resource_type_failure_empty(self):
        """Test resource type validation fails with empty string"""
        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["Security"],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "",  # Invalid: empty string
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert "ResourceType must be a non-empty string" in str(exc_info.value)

    def test_validate_service_name_success(self):
        """Test service name validation with valid service name matching CheckID"""
        valid_metadata = {
            "Provider": "azure",
            "CheckID": "s3_bucket_public_read",
            "CheckTitle": "Test Check",
            "CheckType": ["Security"],
            "ServiceName": "s3",  # Matches first part of CheckID
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "AWS::S3::Bucket",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.ServiceName == "s3"

    def test_validate_service_name_failure_mismatch(self):
        """Test service name validation fails when not matching CheckID"""
        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "s3_bucket_public_read",
            "CheckTitle": "Test Check",
            "CheckType": ["Security"],
            "ServiceName": "ec2",  # Does not match first part of CheckID
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "AWS::S3::Bucket",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert (
            "ServiceName ec2 does not belong to CheckID s3_bucket_public_read"
            in str(exc_info.value)
        )

    def test_validate_service_name_failure_uppercase(self):
        """Test service name validation fails with uppercase"""
        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "S3_bucket_public_read",
            "CheckTitle": "Test Check",
            "CheckType": ["TTPs/Discovery"],
            "ServiceName": "S3",  # Invalid: uppercase
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "AWS::S3::Bucket",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert "ServiceName S3 must be in lowercase" in str(exc_info.value)

    def test_validate_service_name_iac_provider_success(self):
        """Test service name validation allows any service name for IAC provider"""
        valid_metadata = {
            "Provider": "iac",
            "CheckID": "custom_check_id",
            "CheckTitle": "Test Check",
            "CheckType": ["Security"],
            "ServiceName": "CustomService",  # Valid for IAC provider
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.ServiceName == "CustomService"

    def test_valid_check_id_success(self):
        """Test CheckID validation with valid check ID"""
        valid_metadata = {
            "Provider": "azure",
            "CheckID": "s3_bucket_public_read_check",
            "CheckTitle": "Test Check",
            "CheckType": ["Security"],
            "ServiceName": "s3",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "AWS::S3::Bucket",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.CheckID == "s3_bucket_public_read_check"

    def test_valid_check_id_failure_empty(self):
        """Test CheckID validation fails with empty string"""
        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "",  # Invalid: empty string
            "CheckTitle": "Test Check",
            "CheckType": ["Security"],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert "CheckID must be a non-empty string" in str(exc_info.value)

    def test_valid_check_id_failure_hyphen(self):
        """Test CheckID validation fails with hyphen"""
        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "s3-bucket-public-read",  # Invalid: contains hyphens
            "CheckTitle": "Test Check",
            "CheckType": ["Security"],
            "ServiceName": "s3",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "AWS::S3::Bucket",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert (
            "CheckID s3-bucket-public-read contains a hyphen, which is not allowed"
            in str(exc_info.value)
        )

    def test_validate_check_title_success(self):
        """Test CheckTitle validation with valid title"""
        valid_metadata = {
            "Provider": "azure",
            "CheckID": "test_check",
            "CheckTitle": "A" * 150,  # Exactly 150 characters
            "CheckType": ["Security"],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert len(check_metadata.CheckTitle) == 150

    def test_validate_check_title_failure_too_long(self):
        """Test CheckTitle validation fails when too long"""
        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "A" * 151,  # Too long: 151 characters
            "CheckType": ["Security"],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert "CheckTitle must not exceed 150 characters, got 151 characters" in str(
            exc_info.value
        )

    def test_validate_check_type_success(self):
        """Test CheckType validation with valid check types"""
        valid_metadata = {
            "Provider": "azure",  # Using non-AWS provider to avoid config validation
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["Security", "Network"],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.CheckType == ["Security", "Network"]

    def test_validate_check_type_failure_empty_string(self):
        """Test CheckType validation fails with empty string in list"""
        invalid_metadata = {
            "Provider": "azure",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["Security", ""],  # Invalid: empty string in list
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert "CheckType list cannot contain empty strings" in str(exc_info.value)

    def test_validate_description_success(self):
        """Test Description validation with valid description"""
        valid_metadata = {
            "Provider": "azure",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["Security"],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "A" * 400,  # Exactly 400 characters
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert len(check_metadata.Description) == 400

    def test_validate_description_failure_too_long(self):
        """Test Description validation fails when too long"""
        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["Security"],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "A" * 401,  # Too long: 401 characters
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert "Description must not exceed 400 characters, got 401 characters" in str(
            exc_info.value
        )

    def test_validate_risk_success(self):
        """Test Risk validation with valid risk"""
        valid_metadata = {
            "Provider": "azure",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["Security"],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "A" * 400,  # Exactly 400 characters
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert len(check_metadata.Risk) == 400

    def test_validate_risk_failure_too_long(self):
        """Test Risk validation fails when too long"""
        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["Security"],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "A" * 401,  # Too long: 401 characters
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert "Risk must not exceed 400 characters, got 401 characters" in str(
            exc_info.value
        )

    def test_validate_check_type_aws_invalid_type(self):
        """Test CheckType validation fails with invalid AWS CheckType"""

        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["InvalidType"],  # Invalid: not in AWS config
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert "Invalid CheckType: 'InvalidType'" in str(exc_info.value)

    def test_validate_check_type_aws_valid_hierarchy_path(self):
        """Test CheckType validation succeeds with valid AWS CheckType hierarchy path"""

        valid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["TTPs/Initial Access"],  # Valid: partial path in hierarchy
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.CheckType == ["TTPs/Initial Access"]

    def test_validate_check_type_non_aws_provider(self):
        """Test CheckType validation doesn't apply AWS rules to non-AWS providers"""
        valid_metadata = {
            "Provider": "azure",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["CustomType"],  # Valid for non-AWS provider
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.CheckType == ["CustomType"]

    def test_validate_check_type_aws_validation_called(self):
        """Test that AWS CheckType validation function works for AWS provider"""

        valid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["Effects/Data Exposure"],  # Valid AWS CheckType
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.CheckType == ["Effects/Data Exposure"]

    def test_validate_check_type_multiple_types_all_valid(self):
        """Test CheckType validation with multiple valid types for non-AWS provider"""
        valid_metadata = {
            "Provider": "azure",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["Security", "Network", "Compliance"],  # Multiple valid types
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.CheckType == ["Security", "Network", "Compliance"]

    def test_validate_check_type_aws_multiple_types_mixed_validity(self):
        """Test CheckType validation with multiple types where one is invalid for AWS"""

        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["TTPs/Discovery", "InvalidType"],  # One valid, one invalid
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://example.com",
                },
            },
            "Categories": ["security"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert "Invalid CheckType: 'InvalidType'" in str(exc_info.value)
