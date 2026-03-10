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
    CheckType=["type1"],
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
    Provider="aws",
    CheckID="awslambda_function_url_public",
    CheckTitle="Check 1",
    CheckType=["type1"],
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

    def test_additional_urls_valid_empty_list(self):
        """Test AdditionalURLs with valid empty list (default)"""
        metadata = CheckMetadata(
            Provider="aws",
            CheckID="test_check",
            CheckTitle="Test Check",
            CheckType=["type1"],
            ServiceName="test",
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
            CheckType=["type1"],
            ServiceName="test",
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
                CheckType=["type1"],
                ServiceName="test",
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
                CheckType=["type1"],
                ServiceName="test",
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
                CheckType=["type1"],
                ServiceName="test",
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
                CheckType=["type1"],
                ServiceName="test",
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
            CheckType=["type1"],
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
                "Recommendation": {"Text": "text1", "Url": "url1"},
            },
            Categories=["categoryone"],
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
            CheckType=["type1"],
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
                "Recommendation": {"Text": "text1", "Url": "url1"},
            },
            Categories=["categoryone"],
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
                CheckType=["type1"],
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
                    "Recommendation": {"Text": "text1", "Url": "url1"},
                },
                Categories=["categoryone"],
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
                CheckType=["type1"],
                ServiceName="test",
                SubServiceName="subservice1",
                ResourceIdTemplate="template1",
                Severity="high",
                ResourceType="resource1",
                Description="Description 1",
                Risk="risk1",
                RelatedUrl="https://example.com",
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
                CheckType=["type1"],
                ServiceName="test",
                SubServiceName="subservice1",
                ResourceIdTemplate="template1",
                Severity="high",
                ResourceType="resource1",
                Description="Description 1",
                Risk="risk1",
                RelatedUrl="https://example.com",
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
                AdditionalURLs="not_a_list",  # This should fail
                Compliance=[],
            )
        # Should contain the validation error we set in the validator
        assert "AdditionalURLs must be a list" in str(exc_info.value)


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
