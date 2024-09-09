from unittest import mock

from prowler.lib.check.models import CheckMetadata


class TestCheckMetada:

    @mock.patch("prowler.lib.check.models.load_check_metadata")
    @mock.patch("prowler.lib.check.models.recover_checks_from_provider")
    def test_get_bulk(self, mock_recover_checks, mock_load_metadata):
        # Mock the return value of recover_checks_from_provider
        mock_recover_checks.return_value = [
            ("accessanalyzer_enabled", "/path/to/accessanalyzer_enabled")
        ]

        check_metadata = CheckMetadata(
            Provider="aws",
            CheckID="accessanalyzer_enabled",
            CheckTitle="Check 1",
            CheckType=["type1"],
            ServiceName="service1",
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

        # Mock the return value of load_check_metadata
        mock_load_metadata.return_value = check_metadata

        result = CheckMetadata.get_bulk(provider="aws")

        # Assertions
        assert "accessanalyzer_enabled" in result.keys()
        assert result["accessanalyzer_enabled"] == check_metadata
        mock_recover_checks.assert_called_once_with("aws")
        mock_load_metadata.assert_called_once_with(
            "/path/to/accessanalyzer_enabled/accessanalyzer_enabled.metadata.json"
        )
