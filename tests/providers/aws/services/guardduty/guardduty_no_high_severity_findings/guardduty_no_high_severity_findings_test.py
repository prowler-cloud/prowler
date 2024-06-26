from re import search
from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.guardduty.guardduty_service import Detector
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

DETECTOR_ID = str(uuid4())
DETECTOR_ARN = f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{DETECTOR_ID}"


class Test_guardduty_no_high_severity_findings:
    def test_no_detectors(self):
        guardduty_client = mock.MagicMock
        guardduty_client.detectors = []
        with mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_service.GuardDuty",
            guardduty_client,
        ):
            from prowler.providers.aws.services.guardduty.guardduty_no_high_severity_findings.guardduty_no_high_severity_findings import (
                guardduty_no_high_severity_findings,
            )

            check = guardduty_no_high_severity_findings()
            result = check.execute()
            assert len(result) == 0

    def test_no_high_findings(self):
        guardduty_client = mock.MagicMock
        guardduty_client.detectors = []
        guardduty_client.detectors.append(
            Detector(
                id=DETECTOR_ID,
                arn=DETECTOR_ARN,
                region=AWS_REGION_EU_WEST_1,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_service.GuardDuty",
            guardduty_client,
        ):
            from prowler.providers.aws.services.guardduty.guardduty_no_high_severity_findings.guardduty_no_high_severity_findings import (
                guardduty_no_high_severity_findings,
            )

            check = guardduty_no_high_severity_findings()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search(
                "does not have high severity findings.", result[0].status_extended
            )
            assert result[0].resource_id == DETECTOR_ID
            assert result[0].resource_arn == DETECTOR_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_not_enabled_account_detector(self):
        guardduty_client = mock.MagicMock
        guardduty_client.detectors = []
        guardduty_client.detectors.append(
            Detector(
                id=AWS_ACCOUNT_NUMBER,
                arn=DETECTOR_ARN,
                region=AWS_REGION_EU_WEST_1,
                enabled_in_account=False,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_service.GuardDuty",
            guardduty_client,
        ):
            from prowler.providers.aws.services.guardduty.guardduty_no_high_severity_findings.guardduty_no_high_severity_findings import (
                guardduty_no_high_severity_findings,
            )

            check = guardduty_no_high_severity_findings()
            result = check.execute()
            assert len(result) == 0

    def test_high_findings(self):
        guardduty_client = mock.MagicMock
        guardduty_client.detectors = []
        guardduty_client.detectors.append(
            Detector(
                id=DETECTOR_ID,
                region=AWS_REGION_EU_WEST_1,
                arn=DETECTOR_ARN,
                status=False,
                findings=[str(uuid4())],
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_service.GuardDuty",
            guardduty_client,
        ):
            from prowler.providers.aws.services.guardduty.guardduty_no_high_severity_findings.guardduty_no_high_severity_findings import (
                guardduty_no_high_severity_findings,
            )

            check = guardduty_no_high_severity_findings()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search("has 1 high severity findings", result[0].status_extended)
            assert result[0].resource_id == DETECTOR_ID
            assert result[0].resource_arn == DETECTOR_ARN
            assert result[0].region == AWS_REGION_EU_WEST_1
