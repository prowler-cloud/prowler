from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.guardduty.guardduty_service import Detector

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_NUMBER_ADMIN = "123456789013"
DETECTOR_ID = str(uuid4())
DETECTOR_ARN = (
    f"arn:aws:guardduty:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:detector/{DETECTOR_ID}"
)


class Test_guardduty_centrally_managed:
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

    def test_detector_no_centralized_managed(self):
        guardduty_client = mock.MagicMock
        guardduty_client.detectors = []
        guardduty_client.detectors.append(
            Detector(
                id=DETECTOR_ID,
                region=AWS_REGION,
                arn=DETECTOR_ARN,
                status=False,
                findings=[str(uuid4())],
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_service.GuardDuty",
            guardduty_client,
        ):
            # Test Check
            from prowler.providers.aws.services.guardduty.guardduty_centrally_managed.guardduty_centrally_managed import (
                guardduty_centrally_managed,
            )

            check = guardduty_centrally_managed()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"GuardDuty detector {DETECTOR_ID} is not centrally managed."
            )
            assert result[0].resource_id == DETECTOR_ID
            assert result[0].region == AWS_REGION
            assert result[0].resource_arn == DETECTOR_ARN

    def test_not_enabled_account_detector(self):
        guardduty_client = mock.MagicMock
        guardduty_client.detectors = []
        guardduty_client.detectors.append(
            Detector(
                id=AWS_ACCOUNT_NUMBER,
                region=AWS_REGION,
                arn=DETECTOR_ARN,
                enabled_in_account=False,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_service.GuardDuty",
            guardduty_client,
        ):
            # Test Check
            from prowler.providers.aws.services.guardduty.guardduty_centrally_managed.guardduty_centrally_managed import (
                guardduty_centrally_managed,
            )

            check = guardduty_centrally_managed()
            result = check.execute()
            assert len(result) == 0

    def test_detector_centralized_managed(self):
        guardduty_client = mock.MagicMock
        guardduty_client.detectors = []
        guardduty_client.detectors.append(
            Detector(
                id=DETECTOR_ID,
                region=AWS_REGION,
                arn=DETECTOR_ARN,
                status=False,
                findings=[str(uuid4())],
                administrator_account=AWS_ACCOUNT_NUMBER_ADMIN,
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_service.GuardDuty",
            guardduty_client,
        ):
            # Test Check
            from prowler.providers.aws.services.guardduty.guardduty_centrally_managed.guardduty_centrally_managed import (
                guardduty_centrally_managed,
            )

            check = guardduty_centrally_managed()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"GuardDuty detector {DETECTOR_ID} is centrally managed by account {AWS_ACCOUNT_NUMBER_ADMIN}."
            )
            assert result[0].resource_id == DETECTOR_ID
            assert result[0].region == AWS_REGION
            assert result[0].resource_arn == DETECTOR_ARN

    def test_detector_administrator(self):
        guardduty_client = mock.MagicMock
        guardduty_client.detectors = []
        guardduty_client.detectors.append(
            Detector(
                id=DETECTOR_ID,
                region=AWS_REGION,
                arn=DETECTOR_ARN,
                status=False,
                findings=[str(uuid4())],
                member_accounts=[AWS_ACCOUNT_NUMBER_ADMIN],
            )
        )

        with mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_service.GuardDuty",
            guardduty_client,
        ):
            # Test Check
            from prowler.providers.aws.services.guardduty.guardduty_centrally_managed.guardduty_centrally_managed import (
                guardduty_centrally_managed,
            )

            check = guardduty_centrally_managed()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"GuardDuty detector {DETECTOR_ID} is administrator account with 1 member accounts."
            )
            assert result[0].resource_id == DETECTOR_ID
            assert result[0].region == AWS_REGION
            assert result[0].resource_arn == DETECTOR_ARN
