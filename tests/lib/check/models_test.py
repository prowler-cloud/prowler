import sys
from unittest import mock

import pytest
from pydantic.v1 import ValidationError

from prowler.lib.check.models import Check, CheckMetadata
from tests.lib.check.compliance_check_test import custom_compliance_metadata

mock_metadata = CheckMetadata(
    Provider="aws",
    CheckID="accessanalyzer_enabled",
    CheckTitle="Check 1",
    CheckType=["Software and Configuration Checks/AWS Security Best Practices"],
    ServiceName="accessanalyzer",
    SubServiceName="subservice1",
    ResourceIdTemplate="template1",
    Severity="high",
    ResourceType="resource1",
    Description="Description 1",
    Risk="risk1",
    RelatedUrl="",
    Remediation={
        "Code": {
            "CLI": "cli1",
            "NativeIaC": "native1",
            "Other": "other1",
            "Terraform": "terraform1",
        },
        "Recommendation": {
            "Text": "text1",
            "Url": "https://hub.prowler.com/check/accessanalyzer_enabled",
        },
    },
    Categories=["encryption"],
    DependsOn=["dependency1"],
    RelatedTo=["related1"],
    Notes="notes1",
    Compliance=[],
)

mock_metadata_lambda = CheckMetadata(
    Provider="aws",
    CheckID="awslambda_function_url_public",
    CheckTitle="Check 1",
    CheckType=["Software and Configuration Checks/AWS Security Best Practices"],
    ServiceName="awslambda",
    SubServiceName="subservice1",
    ResourceIdTemplate="template1",
    Severity="high",
    ResourceType="resource1",
    Description="Description 1",
    Risk="risk1",
    RelatedUrl="",
    Remediation={
        "Code": {
            "CLI": "cli1",
            "NativeIaC": "native1",
            "Other": "other1",
            "Terraform": "terraform1",
        },
        "Recommendation": {
            "Text": "text1",
            "Url": "https://hub.prowler.com/check/awslambda_function_url_public",
        },
    },
    Categories=["encryption"],
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
            bulk_checks_metadata=bulk_metadata, category="encryption"
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
            "CheckType": [],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption", "logging", "secrets"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        # Should not raise any validation error
        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.Categories == ["encryption", "logging", "secrets"]

    def test_valid_category_failure_non_string(self):
        """Test valid category validation fails with non-string category"""
        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices/Network Reachability"
            ],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
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
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices/Network Reachability"
            ],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
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

    def test_valid_category_failure_not_predefined(self):
        """Test valid category validation fails with non-predefined category"""
        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices/Network Reachability"
            ],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["not-a-real-category"],  # Invalid: not in predefined list
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert "Invalid category: 'not-a-real-category'. Must be one of:" in str(
            exc_info.value
        )

    def test_valid_category_all_predefined_values(self):
        """Test that all predefined categories are accepted"""
        from prowler.lib.check.models import VALID_CATEGORIES

        for category in VALID_CATEGORIES:
            valid_metadata = {
                "Provider": "azure",
                "CheckID": "test_check",
                "CheckTitle": "Test Check",
                "CheckType": [],
                "ServiceName": "test",
                "SubServiceName": "subtest",
                "ResourceIdTemplate": "template",
                "Severity": "high",
                "ResourceType": "TestResource",
                "Description": "Test description",
                "Risk": "Test risk",
                "RelatedUrl": "",
                "Remediation": {
                    "Code": {
                        "CLI": "test command",
                        "NativeIaC": "test native",
                        "Other": "test other",
                        "Terraform": "test terraform",
                    },
                    "Recommendation": {
                        "Text": "test recommendation",
                        "Url": "https://hub.prowler.com/check/test_check",
                    },
                },
                "Categories": [category],
                "DependsOn": [],
                "RelatedTo": [],
                "Notes": "Test notes",
            }
            check_metadata = CheckMetadata(**valid_metadata)
            assert category in check_metadata.Categories

    def test_severity_to_lower_success(self):
        """Test severity validation converts to lowercase"""
        valid_metadata = {
            "Provider": "azure",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": [],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "HIGH",  # Uppercase - should be converted to lowercase
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "CheckType": [],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "aws iam create-role --role-name test",  # Valid CLI command
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices/Network Reachability"
            ],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "https://example.com/command",  # Invalid: URL instead of command
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "CheckType": [],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "AWS::IAM::Role",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices/Network Reachability"
            ],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "",  # Invalid: empty string
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "CheckType": [],
            "ServiceName": "s3",  # Matches first part of CheckID
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "AWS::S3::Bucket",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices/Network Reachability"
            ],
            "ServiceName": "ec2",  # Does not match first part of CheckID
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "AWS::S3::Bucket",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices/Network Reachability"
            ],
            "ServiceName": "CustomService",  # Valid for IAC provider
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "CheckType": [],
            "ServiceName": "s3",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "AWS::S3::Bucket",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices/Network Reachability"
            ],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices/Network Reachability"
            ],
            "ServiceName": "s3",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "AWS::S3::Bucket",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "CheckType": [],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices/Network Reachability"
            ],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert "CheckTitle must not exceed 150 characters, got 151 characters" in str(
            exc_info.value
        )

    def test_validate_check_title_failure_starts_with_ensure(self):
        """Test CheckTitle validation fails when starting with 'Ensure'"""
        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Ensure S3 buckets have encryption enabled",
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices"
            ],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert "CheckTitle must not start with 'Ensure'" in str(exc_info.value)

    def test_validate_related_url_must_be_empty(self):
        """Test RelatedUrl validation fails when not empty"""
        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices"
            ],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "https://example.com",  # Invalid: must be empty
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert "RelatedUrl must be empty" in str(exc_info.value)

    def test_validate_related_url_empty_is_valid(self):
        """Test RelatedUrl validation passes when empty"""
        valid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices"
            ],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.RelatedUrl == ""

    def test_validate_recommendation_url_must_be_hub(self):
        """Test Recommendation URL validation fails when not pointing to Prowler Hub"""
        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices"
            ],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://docs.aws.amazon.com/some-page",  # Invalid: not HUB
                },
            },
            "Categories": ["encryption"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert "Remediation Recommendation URL must point to Prowler Hub" in str(
            exc_info.value
        )

    def test_validate_recommendation_url_hub_is_valid(self):
        """Test Recommendation URL validation passes with Prowler Hub URL"""
        valid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices"
            ],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert (
            check_metadata.Remediation.Recommendation.Url
            == "https://hub.prowler.com/check/test_check"
        )

    def test_validate_recommendation_url_empty_is_valid(self):
        """Test Recommendation URL validation passes when empty"""
        valid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices"
            ],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "",
                },
            },
            "Categories": ["encryption"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.Remediation.Recommendation.Url == ""

    def test_validate_check_type_non_aws_must_be_empty(self):
        """Test CheckType must be empty for non-AWS providers"""
        invalid_metadata = {
            "Provider": "azure",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["SomeType"],  # Invalid: non-AWS must be empty
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert "CheckType must be empty for non-AWS providers" in str(exc_info.value)

    def test_validate_check_type_success(self):
        """Test CheckType validation with valid check types"""
        valid_metadata = {
            "Provider": "azure",  # Using non-AWS provider to avoid config validation
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": [],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.CheckType == []

    def test_validate_check_type_failure_empty_string(self):
        """Test CheckType validation fails with empty string in list"""
        invalid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": ["TTPs/Discovery", ""],  # Invalid: empty string in list
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "CheckType": [],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "A" * 400,  # Exactly 400 characters
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices/Network Reachability"
            ],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "A" * 401,  # Too long: 401 characters
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "CheckType": [],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "A" * 400,  # Exactly 400 characters
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices/Network Reachability"
            ],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "A" * 401,  # Too long: 401 characters
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
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
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.CheckType == ["TTPs/Initial Access"]

    def test_validate_check_type_non_aws_provider(self):
        """Test CheckType validation requires empty list for non-AWS providers"""
        valid_metadata = {
            "Provider": "azure",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": [],  # Non-AWS providers must have empty CheckType
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.CheckType == []

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
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.CheckType == ["Effects/Data Exposure"]

    def test_validate_check_type_multiple_types_all_valid(self):
        """Test CheckType validation with multiple valid types for AWS provider"""
        valid_metadata = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": [
                "TTPs/Discovery",
                "Effects/Data Exposure",
            ],  # Multiple valid AWS types
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        check_metadata = CheckMetadata(**valid_metadata)
        assert check_metadata.CheckType == ["TTPs/Discovery", "Effects/Data Exposure"]

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
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }

        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**invalid_metadata)
        assert "Invalid CheckType: 'InvalidType'" in str(exc_info.value)

    def test_additional_urls_valid_empty_list(self):
        """Test AdditionalURLs with valid empty list (default)"""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="test_check",
            CheckTitle="Test Check",
            CheckType=["Software and Configuration Checks/AWS Security Best Practices"],
            ServiceName="test",
            SubServiceName="subservice1",
            ResourceIdTemplate="template1",
            Severity="high",
            ResourceType="resource1",
            Description="Description 1",
            Risk="risk1",
            RelatedUrl="",
            Remediation={
                "Code": {
                    "CLI": "cli1",
                    "NativeIaC": "native1",
                    "Other": "other1",
                    "Terraform": "terraform1",
                },
                "Recommendation": {
                    "Text": "text1",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            Categories=["encryption"],
            DependsOn=["dependency1"],
            RelatedTo=["related1"],
            Notes="notes1",
            AdditionalURLs=[],
            Compliance=[],
        )
        assert metadata.AdditionalURLs == []

    def test_additional_urls_valid_with_urls(self):
        """Test AdditionalURLs with valid URLs"""
        valid_urls = [
            "https://example.com/doc1",
            "https://example.com/doc2",
            "https://aws.amazon.com/docs",
        ]
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="test_check",
            CheckTitle="Test Check",
            CheckType=["Software and Configuration Checks/AWS Security Best Practices"],
            ServiceName="test",
            SubServiceName="subservice1",
            ResourceIdTemplate="template1",
            Severity="high",
            ResourceType="resource1",
            Description="Description 1",
            Risk="risk1",
            RelatedUrl="",
            Remediation={
                "Code": {
                    "CLI": "cli1",
                    "NativeIaC": "native1",
                    "Other": "other1",
                    "Terraform": "terraform1",
                },
                "Recommendation": {
                    "Text": "text1",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            Categories=["encryption"],
            DependsOn=["dependency1"],
            RelatedTo=["related1"],
            Notes="notes1",
            AdditionalURLs=valid_urls,
            Compliance=[],
        )
        assert metadata.AdditionalURLs == valid_urls

    def test_additional_urls_invalid_not_list(self):
        """Test AdditionalURLs with non-list value"""
        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(
                Provider="aws",
                CheckID="test_check",
                CheckTitle="Test Check",
                CheckType=[
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                ServiceName="test",
                SubServiceName="subservice1",
                ResourceIdTemplate="template1",
                Severity="high",
                ResourceType="resource1",
                Description="Description 1",
                Risk="risk1",
                RelatedUrl="",
                Remediation={
                    "Code": {
                        "CLI": "cli1",
                        "NativeIaC": "native1",
                        "Other": "other1",
                        "Terraform": "terraform1",
                    },
                    "Recommendation": {
                        "Text": "text1",
                        "Url": "https://hub.prowler.com/check/test_check",
                    },
                },
                Categories=["encryption"],
                DependsOn=["dependency1"],
                RelatedTo=["related1"],
                Notes="notes1",
                AdditionalURLs="not_a_list",
                Compliance=[],
            )
        assert "AdditionalURLs must be a list" in str(exc_info.value)

    def test_additional_urls_invalid_empty_items(self):
        """Test AdditionalURLs with empty string items"""
        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(
                Provider="aws",
                CheckID="test_check",
                CheckTitle="Test Check",
                CheckType=[
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                ServiceName="test",
                SubServiceName="subservice1",
                ResourceIdTemplate="template1",
                Severity="high",
                ResourceType="resource1",
                Description="Description 1",
                Risk="risk1",
                RelatedUrl="",
                Remediation={
                    "Code": {
                        "CLI": "cli1",
                        "NativeIaC": "native1",
                        "Other": "other1",
                        "Terraform": "terraform1",
                    },
                    "Recommendation": {
                        "Text": "text1",
                        "Url": "https://hub.prowler.com/check/test_check",
                    },
                },
                Categories=["encryption"],
                DependsOn=["dependency1"],
                RelatedTo=["related1"],
                Notes="notes1",
                AdditionalURLs=["https://example.com", "", "https://example2.com"],
                Compliance=[],
            )
        assert "AdditionalURLs cannot contain empty items" in str(exc_info.value)

    def test_additional_urls_invalid_whitespace_items(self):
        """Test AdditionalURLs with whitespace-only items"""
        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(
                Provider="aws",
                CheckID="test_check",
                CheckTitle="Test Check",
                CheckType=[
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                ServiceName="test",
                SubServiceName="subservice1",
                ResourceIdTemplate="template1",
                Severity="high",
                ResourceType="resource1",
                Description="Description 1",
                Risk="risk1",
                RelatedUrl="",
                Remediation={
                    "Code": {
                        "CLI": "cli1",
                        "NativeIaC": "native1",
                        "Other": "other1",
                        "Terraform": "terraform1",
                    },
                    "Recommendation": {
                        "Text": "text1",
                        "Url": "https://hub.prowler.com/check/test_check",
                    },
                },
                Categories=["encryption"],
                DependsOn=["dependency1"],
                RelatedTo=["related1"],
                Notes="notes1",
                AdditionalURLs=["https://example.com", "   ", "https://example2.com"],
                Compliance=[],
            )
        assert "AdditionalURLs cannot contain empty items" in str(exc_info.value)

    def test_additional_urls_invalid_duplicates(self):
        """Test AdditionalURLs with duplicate items"""
        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(
                Provider="aws",
                CheckID="test_check",
                CheckTitle="Test Check",
                CheckType=[
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                ServiceName="test",
                SubServiceName="subservice1",
                ResourceIdTemplate="template1",
                Severity="high",
                ResourceType="resource1",
                Description="Description 1",
                Risk="risk1",
                RelatedUrl="",
                Remediation={
                    "Code": {
                        "CLI": "cli1",
                        "NativeIaC": "native1",
                        "Other": "other1",
                        "Terraform": "terraform1",
                    },
                    "Recommendation": {
                        "Text": "text1",
                        "Url": "https://hub.prowler.com/check/test_check",
                    },
                },
                Categories=["encryption"],
                DependsOn=["dependency1"],
                RelatedTo=["related1"],
                Notes="notes1",
                AdditionalURLs=[
                    "https://example.com",
                    "https://example2.com",
                    "https://example.com",
                ],
                Compliance=[],
            )
        assert "AdditionalURLs cannot contain duplicate items" in str(exc_info.value)

    def test_fields_with_explicit_empty_values(self):
        """Test that RelatedUrl and AdditionalURLs can be set to explicit empty values"""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="test_check_empty_fields",
            CheckTitle="Test Check with Empty Fields",
            CheckType=["Software and Configuration Checks/AWS Security Best Practices"],
            ServiceName="test",
            SubServiceName="subservice1",
            ResourceIdTemplate="template1",
            Severity="high",
            ResourceType="resource1",
            Description="Description 1",
            Risk="risk1",
            RelatedUrl="",  # Explicit empty string
            Remediation={
                "Code": {
                    "CLI": "cli1",
                    "NativeIaC": "native1",
                    "Other": "other1",
                    "Terraform": "terraform1",
                },
                "Recommendation": {
                    "Text": "text1",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            Categories=["encryption"],
            DependsOn=["dependency1"],
            RelatedTo=["related1"],
            Notes="notes1",
            AdditionalURLs=[],  # Explicit empty list
            Compliance=[],
        )

        # Assert that the fields are set to empty values
        assert metadata.RelatedUrl == ""
        assert metadata.AdditionalURLs == []

    def test_fields_default_values(self):
        """Test that RelatedUrl and AdditionalURLs use proper defaults when not provided"""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="test_check_defaults",
            CheckTitle="Test Check with Default Fields",
            CheckType=["Software and Configuration Checks/AWS Security Best Practices"],
            ServiceName="test",
            SubServiceName="subservice1",
            ResourceIdTemplate="template1",
            Severity="high",
            ResourceType="resource1",
            Description="Description 1",
            Risk="risk1",
            RelatedUrl="",
            Remediation={
                "Code": {
                    "CLI": "cli1",
                    "NativeIaC": "native1",
                    "Other": "other1",
                    "Terraform": "terraform1",
                },
                "Recommendation": {
                    "Text": "text1",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            Categories=["encryption"],
            DependsOn=["dependency1"],
            RelatedTo=["related1"],
            Notes="notes1",
            # AdditionalURLs not provided - should default to empty list via default_factory
            Compliance=[],
        )

        # Assert that the fields use their default values
        assert metadata.RelatedUrl == ""  # Should default to empty string
        assert metadata.AdditionalURLs == []  # Should default to empty list

    def test_related_url_none_fails(self):
        """Test that setting RelatedUrl to None raises a ValidationError"""
        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(
                Provider="aws",
                CheckID="test_check_none_related_url",
                CheckTitle="Test Check with None RelatedUrl",
                CheckType=[
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                ServiceName="test",
                SubServiceName="subservice1",
                ResourceIdTemplate="template1",
                Severity="high",
                ResourceType="resource1",
                Description="Description 1",
                Risk="risk1",
                RelatedUrl=None,  # This should fail
                Remediation={
                    "Code": {
                        "CLI": "cli1",
                        "NativeIaC": "native1",
                        "Other": "other1",
                        "Terraform": "terraform1",
                    },
                    "Recommendation": {
                        "Text": "text1",
                        "Url": "https://hub.prowler.com/check/test_check",
                    },
                },
                Categories=["encryption"],
                DependsOn=["dependency1"],
                RelatedTo=["related1"],
                Notes="notes1",
                AdditionalURLs=[],
                Compliance=[],
            )
        # Should contain a validation error for RelatedUrl
        assert "RelatedUrl" in str(exc_info.value)

    def test_additional_urls_none_fails(self):
        """Test that setting AdditionalURLs to None raises a ValidationError"""
        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(
                Provider="aws",
                CheckID="test_check_none_additional_urls",
                CheckTitle="Test Check with None AdditionalURLs",
                CheckType=[
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                ServiceName="test",
                SubServiceName="subservice1",
                ResourceIdTemplate="template1",
                Severity="high",
                ResourceType="resource1",
                Description="Description 1",
                Risk="risk1",
                RelatedUrl="",
                Remediation={
                    "Code": {
                        "CLI": "cli1",
                        "NativeIaC": "native1",
                        "Other": "other1",
                        "Terraform": "terraform1",
                    },
                    "Recommendation": {
                        "Text": "text1",
                        "Url": "https://hub.prowler.com/check/test_check",
                    },
                },
                Categories=["encryption"],
                DependsOn=["dependency1"],
                RelatedTo=["related1"],
                Notes="notes1",
                AdditionalURLs=None,  # This should fail
                Compliance=[],
            )
        # Should contain the validation error we set in the validator
        assert "AdditionalURLs must be a list" in str(exc_info.value)

    def test_additional_urls_invalid_type_fails(self):
        """Test that setting AdditionalURLs to non-list value raises a ValidationError"""
        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(
                Provider="aws",
                CheckID="test_check_invalid_additional_urls",
                CheckTitle="Test Check with Invalid AdditionalURLs",
                CheckType=[
                    "Software and Configuration Checks/AWS Security Best Practices"
                ],
                ServiceName="test",
                SubServiceName="subservice1",
                ResourceIdTemplate="template1",
                Severity="high",
                ResourceType="resource1",
                Description="Description 1",
                Risk="risk1",
                RelatedUrl="",
                Remediation={
                    "Code": {
                        "CLI": "cli1",
                        "NativeIaC": "native1",
                        "Other": "other1",
                        "Terraform": "terraform1",
                    },
                    "Recommendation": {
                        "Text": "text1",
                        "Url": "https://hub.prowler.com/check/test_check",
                    },
                },
                Categories=["encryption"],
                DependsOn=["dependency1"],
                RelatedTo=["related1"],
                Notes="notes1",
                AdditionalURLs="not_a_list",  # This should fail
                Compliance=[],
            )
        # Should contain the validation error we set in the validator
        assert "AdditionalURLs must be a list" in str(exc_info.value)


class TestResourceGroupValidator:
    """Test class for ResourceGroup validator"""

    def _base_metadata(self, **overrides):
        """Helper to build valid metadata with overrides"""
        base = {
            "Provider": "aws",
            "CheckID": "test_check",
            "CheckTitle": "Test Check",
            "CheckType": [
                "Software and Configuration Checks/AWS Security Best Practices"
            ],
            "ServiceName": "test",
            "SubServiceName": "subtest",
            "ResourceIdTemplate": "template",
            "Severity": "high",
            "ResourceType": "TestResource",
            "Description": "Test description",
            "Risk": "Test risk",
            "RelatedUrl": "",
            "Remediation": {
                "Code": {
                    "CLI": "test command",
                    "NativeIaC": "test native",
                    "Other": "test other",
                    "Terraform": "test terraform",
                },
                "Recommendation": {
                    "Text": "test recommendation",
                    "Url": "https://hub.prowler.com/check/test_check",
                },
            },
            "Categories": ["encryption"],
            "DependsOn": [],
            "RelatedTo": [],
            "Notes": "Test notes",
        }
        base.update(overrides)
        return base

    @pytest.mark.parametrize(
        "resource_group",
        [
            "compute",
            "container",
            "serverless",
            "database",
            "storage",
            "network",
            "IAM",
            "messaging",
            "security",
            "monitoring",
            "api_gateway",
            "ai_ml",
            "governance",
            "collaboration",
            "devops",
            "analytics",
        ],
    )
    def test_valid_resource_group(self, resource_group):
        """Test all valid ResourceGroup values are accepted"""
        metadata = CheckMetadata(**self._base_metadata(ResourceGroup=resource_group))
        assert metadata.ResourceGroup == resource_group

    def test_resource_group_empty_string_allowed(self):
        """Test that empty string (default) is allowed for ResourceGroup"""
        metadata = CheckMetadata(**self._base_metadata(ResourceGroup=""))
        assert metadata.ResourceGroup == ""

    def test_resource_group_default_is_empty(self):
        """Test that ResourceGroup defaults to empty string when not provided"""
        metadata = CheckMetadata(**self._base_metadata())
        assert metadata.ResourceGroup == ""

    def test_resource_group_invalid_value(self):
        """Test that invalid ResourceGroup value raises ValidationError"""
        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**self._base_metadata(ResourceGroup="invalid_group"))
        assert "Invalid ResourceGroup: 'invalid_group'" in str(exc_info.value)

    def test_resource_group_case_sensitive(self):
        """Test that ResourceGroup validation is case-sensitive (IAM, not iam)"""
        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**self._base_metadata(ResourceGroup="iam"))
        assert "Invalid ResourceGroup: 'iam'" in str(exc_info.value)

    def test_resource_group_typo(self):
        """Test that typos in ResourceGroup are rejected"""
        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**self._base_metadata(ResourceGroup="computee"))
        assert "Invalid ResourceGroup: 'computee'" in str(exc_info.value)


class TestCheck:
    @mock.patch("prowler.lib.check.models.CheckMetadata.parse_file")
    def test_verify_names_consistency_all_match(self, mock_parse_file):
        """Case where everything matches: CheckID == class_name == file_name"""
        mock_parse_file.return_value = mock_metadata.copy(
            update={
                "CheckID": "accessanalyzer_enabled",
                "ServiceName": "accessanalyzer",
            }
        )

        class accessanalyzer_enabled(Check):
            def execute(self):
                pass

        fake_module = mock.Mock()
        fake_module.__file__ = "/path/to/accessanalyzer_enabled.py"
        sys.modules[accessanalyzer_enabled.__module__] = fake_module

        accessanalyzer_enabled()

    @mock.patch("prowler.lib.check.models.CheckMetadata.parse_file")
    def test_verify_names_consistency_class_mismatch(self, mock_parse_file):
        """CheckID != class name, but matches file_name"""
        mock_parse_file.return_value = mock_metadata.copy(
            update={
                "CheckID": "accessanalyzer_enabled",
                "ServiceName": "accessanalyzer",
            }
        )

        class WrongClass(Check):
            def execute(self):
                pass

        fake_module = mock.Mock()
        fake_module.__file__ = "/path/to/accessanalyzer_enabled.py"
        sys.modules[WrongClass.__module__] = fake_module

        with pytest.raises(ValidationError) as excinfo:
            WrongClass()

        assert "!= class name" in str(excinfo.value)

    @mock.patch("prowler.lib.check.models.CheckMetadata.parse_file")
    def test_verify_names_consistency_file_mismatch(self, mock_parse_file):
        """CheckID == class name, but != file_name"""
        mock_parse_file.return_value = mock_metadata.copy(
            update={
                "CheckID": "accessanalyzer_enabled",
                "ServiceName": "accessanalyzer",
            }
        )

        class accessanalyzer_enabled(Check):
            def execute(self):
                pass

        fake_module = mock.Mock()
        fake_module.__file__ = "/path/to/OtherFile.py"
        sys.modules[accessanalyzer_enabled.__module__] = fake_module

        with pytest.raises(ValidationError) as excinfo:
            accessanalyzer_enabled()

        assert "!= file name" in str(excinfo.value)

    @mock.patch("prowler.lib.check.models.CheckMetadata.parse_file")
    def test_verify_names_consistency_both_mismatch(self, mock_parse_file):
        """Neither class name nor file name match the CheckID"""
        mock_parse_file.return_value = mock_metadata.copy(
            update={
                "CheckID": "accessanalyzer_enabled",
                "ServiceName": "accessanalyzer",
            }
        )

        class WrongClass(Check):
            def execute(self):
                pass

        fake_module = mock.Mock()
        fake_module.__file__ = "/path/to/OtherFile.py"
        sys.modules[WrongClass.__module__] = fake_module

        with pytest.raises(ValidationError) as excinfo:
            WrongClass()

        msg = str(excinfo.value)
        assert "!= class name" in msg
        assert "!= file name" in msg


class TestExternalToolProviderValidatorBypass:
    """Validators skip strict rules for external tool providers (image, iac, llm)."""

    EXTERNAL_METADATA_BASE = {
        "Provider": "image",
        "CheckID": "CVE-2024-1234",
        "CheckTitle": "OpenSSL Buffer Overflow",
        "CheckType": ["Container Image Security"],
        "ServiceName": "container-image",
        "SubServiceName": "",
        "ResourceIdTemplate": "",
        "Severity": "high",
        "ResourceType": "container-image",
        "ResourceGroup": "container",
        "Description": "A buffer overflow vulnerability.",
        "Risk": "Remote code execution.",
        "RelatedUrl": "",
        "Remediation": {
            "Code": {
                "CLI": "",
                "NativeIaC": "",
                "Other": "",
                "Terraform": "",
            },
            "Recommendation": {
                "Text": "Upgrade openssl",
                "Url": "https://avd.aquasec.com/nvd/cve-2024-1234",
            },
        },
        "Categories": ["vulnerability"],
        "DependsOn": [],
        "RelatedTo": [],
        "Notes": "",
    }

    def test_external_provider_allows_non_hub_recommendation_url(self):
        metadata = CheckMetadata(**self.EXTERNAL_METADATA_BASE)
        assert (
            metadata.Remediation.Recommendation.Url
            == "https://avd.aquasec.com/nvd/cve-2024-1234"
        )

    def test_native_provider_rejects_non_hub_recommendation_url(self):
        data = {
            **self.EXTERNAL_METADATA_BASE,
            "Provider": "azure",
            "CheckID": "test_check",
            "ServiceName": "test",
            "CheckType": [],
            "Remediation": {
                "Code": {
                    "CLI": "",
                    "NativeIaC": "",
                    "Other": "",
                    "Terraform": "",
                },
                "Recommendation": {
                    "Text": "Fix it",
                    "Url": "https://avd.aquasec.com/nvd/cve-2024-1234",
                },
            },
        }
        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**data)
        assert "Prowler Hub" in str(exc_info.value)

    def test_external_provider_allows_long_description(self):
        data = {**self.EXTERNAL_METADATA_BASE, "Description": "A" * 500}
        metadata = CheckMetadata(**data)
        assert len(metadata.Description) == 500

    def test_native_provider_rejects_long_description(self):
        data = {
            **self.EXTERNAL_METADATA_BASE,
            "Provider": "azure",
            "CheckID": "test_check",
            "ServiceName": "test",
            "CheckType": [],
            "Categories": ["encryption"],
            "Description": "A" * 401,
            "Remediation": {
                "Code": {
                    "CLI": "",
                    "NativeIaC": "",
                    "Other": "",
                    "Terraform": "",
                },
                "Recommendation": {
                    "Text": "",
                    "Url": "",
                },
            },
        }
        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**data)
        assert "Description must not exceed 400 characters" in str(exc_info.value)

    def test_external_provider_allows_long_risk(self):
        data = {**self.EXTERNAL_METADATA_BASE, "Risk": "R" * 500}
        metadata = CheckMetadata(**data)
        assert len(metadata.Risk) == 500

    def test_native_provider_rejects_long_risk(self):
        data = {
            **self.EXTERNAL_METADATA_BASE,
            "Provider": "azure",
            "CheckID": "test_check",
            "ServiceName": "test",
            "CheckType": [],
            "Categories": ["encryption"],
            "Risk": "R" * 401,
            "Remediation": {
                "Code": {
                    "CLI": "",
                    "NativeIaC": "",
                    "Other": "",
                    "Terraform": "",
                },
                "Recommendation": {
                    "Text": "",
                    "Url": "",
                },
            },
        }
        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**data)
        assert "Risk must not exceed 400 characters" in str(exc_info.value)

    def test_external_provider_allows_long_check_title(self):
        data = {**self.EXTERNAL_METADATA_BASE, "CheckTitle": "T" * 200}
        metadata = CheckMetadata(**data)
        assert len(metadata.CheckTitle) == 200

    def test_native_provider_rejects_long_check_title(self):
        data = {
            **self.EXTERNAL_METADATA_BASE,
            "Provider": "azure",
            "CheckID": "test_check",
            "ServiceName": "test",
            "CheckType": [],
            "Categories": ["encryption"],
            "CheckTitle": "T" * 151,
            "Remediation": {
                "Code": {
                    "CLI": "",
                    "NativeIaC": "",
                    "Other": "",
                    "Terraform": "",
                },
                "Recommendation": {
                    "Text": "",
                    "Url": "",
                },
            },
        }
        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**data)
        assert "CheckTitle must not exceed 150 characters" in str(exc_info.value)

    def test_external_provider_allows_non_standard_category(self):
        data = {**self.EXTERNAL_METADATA_BASE, "Categories": ["vulnerability"]}
        metadata = CheckMetadata(**data)
        assert metadata.Categories == ["vulnerability"]

    def test_native_provider_rejects_non_standard_category(self):
        data = {
            **self.EXTERNAL_METADATA_BASE,
            "Provider": "azure",
            "CheckID": "test_check",
            "ServiceName": "test",
            "CheckType": [],
            "Categories": ["vulnerability"],
            "Remediation": {
                "Code": {
                    "CLI": "",
                    "NativeIaC": "",
                    "Other": "",
                    "Terraform": "",
                },
                "Recommendation": {
                    "Text": "",
                    "Url": "",
                },
            },
        }
        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**data)
        assert "Invalid category" in str(exc_info.value)

    def test_external_provider_allows_ensure_prefix_in_title(self):
        data = {
            **self.EXTERNAL_METADATA_BASE,
            "CheckTitle": "Ensure containers run as non-root",
        }
        metadata = CheckMetadata(**data)
        assert metadata.CheckTitle == "Ensure containers run as non-root"

    def test_external_provider_allows_non_empty_related_url(self):
        data = {
            **self.EXTERNAL_METADATA_BASE,
            "RelatedUrl": "https://avd.aquasec.com/nvd/cve-2024-1234",
        }
        metadata = CheckMetadata(**data)
        assert metadata.RelatedUrl == "https://avd.aquasec.com/nvd/cve-2024-1234"

    def test_native_provider_rejects_non_empty_related_url(self):
        data = {
            **self.EXTERNAL_METADATA_BASE,
            "Provider": "azure",
            "CheckID": "test_check",
            "ServiceName": "test",
            "CheckType": [],
            "Categories": ["encryption"],
            "RelatedUrl": "https://example.com",
            "Remediation": {
                "Code": {
                    "CLI": "",
                    "NativeIaC": "",
                    "Other": "",
                    "Terraform": "",
                },
                "Recommendation": {
                    "Text": "",
                    "Url": "",
                },
            },
        }
        with pytest.raises(ValidationError) as exc_info:
            CheckMetadata(**data)
        assert "RelatedUrl must be empty" in str(exc_info.value)

    def test_all_external_providers_bypass(self):
        for provider in ("image", "iac", "llm"):
            data = {
                **self.EXTERNAL_METADATA_BASE,
                "Provider": provider,
                "Description": "D" * 500,
                "Risk": "R" * 500,
                "CheckTitle": "T" * 200,
                "Categories": ["vulnerability"],
                "RelatedUrl": "https://example.com/vuln",
            }
            metadata = CheckMetadata(**data)
            assert metadata.Provider == provider
