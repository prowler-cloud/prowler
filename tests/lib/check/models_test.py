from unittest import mock

import pytest
from pydantic.v1 import ValidationError

from prowler.lib.check.models import CheckMetadata
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
        """Test AdditionalUrls with valid empty list (default)"""
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
            AdditionalUrls=[],
            Compliance=[],
        )
        assert metadata.AdditionalUrls == []

    def test_additional_urls_valid_with_urls(self):
        """Test AdditionalUrls with valid URLs"""
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
            AdditionalUrls=valid_urls,
            Compliance=[],
        )
        assert metadata.AdditionalUrls == valid_urls

    def test_additional_urls_invalid_not_list(self):
        """Test AdditionalUrls with non-list value"""
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
                AdditionalUrls="not_a_list",
                Compliance=[],
            )
        assert "AdditionalUrls must be a list" in str(exc_info.value)

    def test_additional_urls_invalid_empty_items(self):
        """Test AdditionalUrls with empty string items"""
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
                AdditionalUrls=["https://example.com", "", "https://example2.com"],
                Compliance=[],
            )
        assert "AdditionalUrls cannot contain empty items" in str(exc_info.value)

    def test_additional_urls_invalid_whitespace_items(self):
        """Test AdditionalUrls with whitespace-only items"""
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
                AdditionalUrls=["https://example.com", "   ", "https://example2.com"],
                Compliance=[],
            )
        assert "AdditionalUrls cannot contain empty items" in str(exc_info.value)

    def test_additional_urls_invalid_duplicates(self):
        """Test AdditionalUrls with duplicate items"""
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
                AdditionalUrls=[
                    "https://example.com",
                    "https://example2.com",
                    "https://example.com",
                ],
                Compliance=[],
            )
        assert "AdditionalUrls cannot contain duplicate items" in str(exc_info.value)
