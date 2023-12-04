from unittest import mock

from prowler.providers.aws.services.accessanalyzer.accessanalyzer_service import (
    Analyzer,
    Finding,
)
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_ARN,
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_EU_WEST_2,
)

ACCESS_ANALYZER_NAME = "test-analyzer"
ACCESS_ANALYZER_ARN = f"arn:aws:access-analyzer:{AWS_REGION_EU_WEST_2}:{AWS_ACCOUNT_NUMBER}:analyzer/{ACCESS_ANALYZER_NAME}"


class Test_accessanalyzer_enabled_without_findings:
    def test_no_analyzers(self):
        accessanalyzer_client = mock.MagicMock
        accessanalyzer_client.analyzers = []
        with mock.patch(
            "prowler.providers.aws.services.accessanalyzer.accessanalyzer_service.AccessAnalyzer",
            new=accessanalyzer_client,
        ):
            # Test Check
            from prowler.providers.aws.services.accessanalyzer.accessanalyzer_enabled_without_findings.accessanalyzer_enabled_without_findings import (
                accessanalyzer_enabled_without_findings,
            )

            check = accessanalyzer_enabled_without_findings()
            result = check.execute()

            assert len(result) == 0

    def test_one_analyzer_not_available(self):
        # Include analyzers to check
        accessanalyzer_client = mock.MagicMock
        accessanalyzer_client.analyzers = [
            Analyzer(
                arn=AWS_ACCOUNT_ARN,
                name=AWS_ACCOUNT_NUMBER,
                status="NOT_AVAILABLE",
                tags=[],
                type="",
                fidings=[],
                region=AWS_REGION_EU_WEST_1,
            )
        ]
        with mock.patch(
            "prowler.providers.aws.services.accessanalyzer.accessanalyzer_service.AccessAnalyzer",
            accessanalyzer_client,
        ):
            from prowler.providers.aws.services.accessanalyzer.accessanalyzer_enabled_without_findings.accessanalyzer_enabled_without_findings import (
                accessanalyzer_enabled_without_findings,
            )

            check = accessanalyzer_enabled_without_findings()
            result = check.execute()

            assert len(result) == 0

    def test_two_analyzers_but_one_with_findings(self):
        accessanalyzer_client = mock.MagicMock
        accessanalyzer_client.analyzers = [
            Analyzer(
                arn=AWS_ACCOUNT_ARN,
                name=AWS_ACCOUNT_NUMBER,
                status="NOT_AVAILABLE",
                tags=[],
                fidings=[],
                type="",
                region=AWS_REGION_EU_WEST_1,
            ),
            Analyzer(
                arn=ACCESS_ANALYZER_ARN,
                name=ACCESS_ANALYZER_NAME,
                status="ACTIVE",
                findings=[
                    Finding(
                        id="test-finding-1",
                        status="ACTIVE",
                    ),
                    Finding(
                        id="test-finding-2",
                        status="ARCHIVED",
                    ),
                ],
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
            from prowler.providers.aws.services.accessanalyzer.accessanalyzer_enabled_without_findings.accessanalyzer_enabled_without_findings import (
                accessanalyzer_enabled_without_findings,
            )

            check = accessanalyzer_enabled_without_findings()
            result = check.execute()

            assert len(result) == 1

            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"IAM Access Analyzer {ACCESS_ANALYZER_NAME} has 1 active findings."
            )
            assert result[0].resource_id == ACCESS_ANALYZER_NAME
            assert result[0].resource_arn == ACCESS_ANALYZER_ARN
            assert result[0].region == AWS_REGION_EU_WEST_2
            assert result[0].resource_tags == []

    def test_one_active_analyzer_without_findings(self):
        accessanalyzer_client = mock.MagicMock
        accessanalyzer_client.analyzers = [
            Analyzer(
                arn=ACCESS_ANALYZER_ARN,
                name=ACCESS_ANALYZER_NAME,
                status="ACTIVE",
                tags=[],
                fidings=[],
                type="",
                region=AWS_REGION_EU_WEST_2,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.accessanalyzer.accessanalyzer_service.AccessAnalyzer",
            new=accessanalyzer_client,
        ):
            # Test Check
            from prowler.providers.aws.services.accessanalyzer.accessanalyzer_enabled_without_findings.accessanalyzer_enabled_without_findings import (
                accessanalyzer_enabled_without_findings,
            )

            check = accessanalyzer_enabled_without_findings()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"IAM Access Analyzer {ACCESS_ANALYZER_NAME} does not have active findings."
            )
            assert result[0].resource_id == ACCESS_ANALYZER_NAME
            assert result[0].resource_arn == ACCESS_ANALYZER_ARN
            assert result[0].region == AWS_REGION_EU_WEST_2
            assert result[0].resource_tags == []

    def test_one_active_analyzer_not_active_without_findings(self):
        accessanalyzer_client = mock.MagicMock
        accessanalyzer_client.analyzers = [
            Analyzer(
                arn=AWS_ACCOUNT_ARN,
                name=AWS_ACCOUNT_NUMBER,
                status="NOT_AVAILABLE",
                tags=[],
                fidings=[],
                type="",
                region=AWS_REGION_EU_WEST_1,
            ),
        ]
        # Patch AccessAnalyzer Client
        with mock.patch(
            "prowler.providers.aws.services.accessanalyzer.accessanalyzer_service.AccessAnalyzer",
            new=accessanalyzer_client,
        ):
            # Test Check
            from prowler.providers.aws.services.accessanalyzer.accessanalyzer_enabled_without_findings.accessanalyzer_enabled_without_findings import (
                accessanalyzer_enabled_without_findings,
            )

            check = accessanalyzer_enabled_without_findings()
            result = check.execute()

            assert len(result) == 0

    def test_analyzer_finding_without_status(self):
        accessanalyzer_client = mock.MagicMock
        accessanalyzer_client.analyzers = [
            Analyzer(
                arn=ACCESS_ANALYZER_ARN,
                name=ACCESS_ANALYZER_NAME,
                status="ACTIVE",
                findings=[
                    Finding(
                        id="test-finding-1",
                        status="",
                    ),
                ],
                tags=[],
                type="",
                region=AWS_REGION_EU_WEST_1,
            ),
        ]

        # Patch AccessAnalyzer Client
        with mock.patch(
            "prowler.providers.aws.services.accessanalyzer.accessanalyzer_service.AccessAnalyzer",
            new=accessanalyzer_client,
        ):
            # Test Check
            from prowler.providers.aws.services.accessanalyzer.accessanalyzer_enabled_without_findings.accessanalyzer_enabled_without_findings import (
                accessanalyzer_enabled_without_findings,
            )

            check = accessanalyzer_enabled_without_findings()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"IAM Access Analyzer {ACCESS_ANALYZER_NAME} does not have active findings."
            )
            assert result[0].resource_id == ACCESS_ANALYZER_NAME
            assert result[0].resource_arn == ACCESS_ANALYZER_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []
