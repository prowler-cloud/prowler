from unittest import mock

from prowler.providers.aws.services.accessanalyzer.accessanalyzer_service import (
    Analyzer,
)


class Test_accessanalyzer_enabled:
    def test_no_analyzers(self):
        accessanalyzer_client = mock.MagicMock
        accessanalyzer_client.analyzers = []
        with mock.patch(
            "prowler.providers.aws.services.accessanalyzer.accessanalyzer_service.AccessAnalyzer",
            new=accessanalyzer_client,
        ):
            # Test Check
            from prowler.providers.aws.services.accessanalyzer.accessanalyzer_enabled.accessanalyzer_enabled import (
                accessanalyzer_enabled,
            )

            check = accessanalyzer_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_one_analyzer_not_available(self):
        # Include analyzers to check
        accessanalyzer_client = mock.MagicMock
        accessanalyzer_client.analyzers = [
            Analyzer(
                arn="",
                name="012345678910",
                status="NOT_AVAILABLE",
                tags=[],
                type="",
                region="eu-west-1",
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.accessanalyzer.accessanalyzer_service.AccessAnalyzer",
            accessanalyzer_client,
        ):
            from prowler.providers.aws.services.accessanalyzer.accessanalyzer_enabled.accessanalyzer_enabled import (
                accessanalyzer_enabled,
            )

            check = accessanalyzer_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "IAM Access Analyzer in account 012345678910 is not enabled"
            )
            assert result[0].resource_id == "012345678910"

    def test_two_analyzers(self):
        accessanalyzer_client = mock.MagicMock
        accessanalyzer_client.analyzers = [
            Analyzer(
                arn="",
                name="012345678910",
                status="NOT_AVAILABLE",
                tags=[],
                type="",
                region="eu-west-1",
            ),
            Analyzer(
                arn="",
                name="Test Analyzer",
                status="ACTIVE",
                tags=[],
                type="",
                region="eu-west-2",
            ),
        ]

        # Patch AccessAnalyzer Client
        with mock.patch(
            "prowler.providers.aws.services.accessanalyzer.accessanalyzer_service.AccessAnalyzer",
            new=accessanalyzer_client,
        ):
            # Test Check
            from prowler.providers.aws.services.accessanalyzer.accessanalyzer_enabled.accessanalyzer_enabled import (
                accessanalyzer_enabled,
            )

            check = accessanalyzer_enabled()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "IAM Access Analyzer in account 012345678910 is not enabled"
            )
            assert result[0].resource_id == "012345678910"
            assert result[0].region == "eu-west-1"
            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == "IAM Access Analyzer Test Analyzer is enabled"
            )
            assert result[1].resource_id == "Test Analyzer"
            assert result[1].region == "eu-west-2"

    def test_one_active_analyzer(self):
        accessanalyzer_client = mock.MagicMock
        accessanalyzer_client.analyzers = [
            Analyzer(
                arn="",
                name="Test Analyzer",
                status="ACTIVE",
                tags=[],
                type="",
                region="eu-west-2",
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.accessanalyzer.accessanalyzer_service.AccessAnalyzer",
            new=accessanalyzer_client,
        ):
            # Test Check
            from prowler.providers.aws.services.accessanalyzer.accessanalyzer_enabled.accessanalyzer_enabled import (
                accessanalyzer_enabled,
            )

            check = accessanalyzer_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "IAM Access Analyzer Test Analyzer is enabled"
            )
            assert result[0].resource_id == "Test Analyzer"
            assert result[0].region == "eu-west-2"
