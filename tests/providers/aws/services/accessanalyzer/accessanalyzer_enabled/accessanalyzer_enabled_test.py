from unittest import mock

from prowler.providers.aws.services.accessanalyzer.accessanalyzer_service import (
    Analyzer,
)
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_ARN,
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_WEST_2,
)

ACCESS_ANALYZER_NAME = "test-analyzer"
ACCESS_ANALYZER_ARN = f"arn:aws:access-analyzer:{AWS_REGION_EU_WEST_2}:{AWS_ACCOUNT_NUMBER}:analyzer/{ACCESS_ANALYZER_NAME}"


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
        accessanalyzer_client.region = AWS_REGION_EU_WEST_1
        accessanalyzer_client.analyzers = [
            Analyzer(
                arn=AWS_ACCOUNT_ARN,
                name=AWS_ACCOUNT_NUMBER,
                status="NOT_AVAILABLE",
                tags=[],
                type="",
                region=AWS_REGION_EU_WEST_1,
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
                == f"IAM Access Analyzer in account {AWS_ACCOUNT_NUMBER} is not enabled."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    def test_one_analyzer_not_available_allowlisted(self):
        # Include analyzers to check
        accessanalyzer_client = mock.MagicMock
        accessanalyzer_client.region = AWS_REGION_EU_WEST_2
        accessanalyzer_client.audit_config = {"allowlist_non_default_regions": True}
        accessanalyzer_client.analyzers = [
            Analyzer(
                arn=AWS_ACCOUNT_ARN,
                name=AWS_ACCOUNT_NUMBER,
                status="NOT_AVAILABLE",
                tags=[],
                type="",
                region=AWS_REGION_EU_WEST_1,
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
            assert result[0].status == "WARNING"
            assert (
                result[0].status_extended
                == f"IAM Access Analyzer in account {AWS_ACCOUNT_NUMBER} is not enabled."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    def test_two_analyzers(self):
        accessanalyzer_client = mock.MagicMock
        accessanalyzer_client.region = AWS_REGION_EU_WEST_1
        accessanalyzer_client.analyzers = [
            Analyzer(
                arn=AWS_ACCOUNT_ARN,
                name=AWS_ACCOUNT_NUMBER,
                status="NOT_AVAILABLE",
                tags=[],
                type="",
                region=AWS_REGION_EU_WEST_1,
            ),
            Analyzer(
                arn=ACCESS_ANALYZER_ARN,
                name=ACCESS_ANALYZER_NAME,
                status="ACTIVE",
                tags=[],
                type="",
                region=AWS_REGION_EU_WEST_2,
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
                == f"IAM Access Analyzer in account {AWS_ACCOUNT_NUMBER} is not enabled."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_1

            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == f"IAM Access Analyzer {ACCESS_ANALYZER_NAME} is enabled."
            )
            assert result[1].resource_id == ACCESS_ANALYZER_NAME
            assert result[1].resource_arn == ACCESS_ANALYZER_ARN
            assert result[1].resource_tags == []
            assert result[1].region == AWS_REGION_EU_WEST_2

    def test_one_active_analyzer(self):
        accessanalyzer_client = mock.MagicMock
        accessanalyzer_client.analyzers = [
            Analyzer(
                arn=ACCESS_ANALYZER_ARN,
                name=ACCESS_ANALYZER_NAME,
                status="ACTIVE",
                tags=[],
                type="",
                region=AWS_REGION_EU_WEST_2,
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
                == f"IAM Access Analyzer {ACCESS_ANALYZER_NAME} is enabled."
            )
            assert result[0].resource_id == ACCESS_ANALYZER_NAME
            assert result[0].resource_arn == ACCESS_ANALYZER_ARN
            assert result[0].resource_tags == []
            assert result[0].region == AWS_REGION_EU_WEST_2
