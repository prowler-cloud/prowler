from unittest import mock

from prowler.providers.aws.services.accessanalyzer.accessanalyzer_service import (
    Analyzer,
    Finding,
)

AWS_REGION_1 = "eu-west-1"
AWS_REGION_2 = "eu-west-2"
AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
ACCESS_ANALYZER_NAME = "test-analyzer"
ACCESS_ANALYZER_ARN = f"arn:aws:access-analyzer:{AWS_REGION_2}:{AWS_ACCOUNT_NUMBER}:analyzer/{ACCESS_ANALYZER_NAME}"


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
                region=AWS_REGION_1,
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

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"IAM Access Analyzer in account {AWS_ACCOUNT_NUMBER} is not enabled."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
            assert result[0].region == AWS_REGION_1
            assert result[0].resource_tags == []

    def test_two_analyzers(self):
        accessanalyzer_client = mock.MagicMock
        accessanalyzer_client.analyzers = [
            Analyzer(
                arn=AWS_ACCOUNT_ARN,
                name=AWS_ACCOUNT_NUMBER,
                status="NOT_AVAILABLE",
                tags=[],
                fidings=[],
                type="",
                region=AWS_REGION_1,
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
                region=AWS_REGION_2,
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

            assert len(result) == 2

            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"IAM Access Analyzer in account {AWS_ACCOUNT_NUMBER} is not enabled."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
            assert result[0].region == AWS_REGION_1
            assert result[0].resource_tags == []

            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended
                == f"IAM Access Analyzer {ACCESS_ANALYZER_NAME} has 1 active findings."
            )
            assert result[1].resource_id == ACCESS_ANALYZER_NAME
            assert result[1].resource_arn == ACCESS_ANALYZER_ARN
            assert result[1].region == AWS_REGION_2
            assert result[1].resource_tags == []

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
                region=AWS_REGION_2,
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
            assert result[0].region == AWS_REGION_2
            assert result[0].resource_tags == []

    def test_one_active_analyzer_not_active(self):
        accessanalyzer_client = mock.MagicMock
        accessanalyzer_client.analyzers = [
            Analyzer(
                arn=AWS_ACCOUNT_ARN,
                name=AWS_ACCOUNT_NUMBER,
                status="NOT_AVAILABLE",
                tags=[],
                fidings=[],
                type="",
                region=AWS_REGION_1,
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
                == f"IAM Access Analyzer in account {AWS_ACCOUNT_NUMBER} is not enabled."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
            assert result[0].region == AWS_REGION_1
            assert result[0].resource_tags == []

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
                region=AWS_REGION_1,
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
            assert result[0].region == AWS_REGION_1
            assert result[0].resource_tags == []
