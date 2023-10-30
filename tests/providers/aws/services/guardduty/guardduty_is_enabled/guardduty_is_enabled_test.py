from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.guardduty.guardduty_service import Detector

AWS_REGION = "us-east-1"
AWS_ACCOUNT_ID = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"

DETECTOR_ID = str(uuid4())
DETECTOR_ARN = f"arn:aws:guardduty:{AWS_REGION}:{AWS_ACCOUNT_ID}:detector/{DETECTOR_ID}"


class Test_:
    def test_no_detectors(self):
        guardduty_client = mock.MagicMock
        guardduty_client.detectors = []
        guardduty_client.detectors.append(
            Detector(
                id=AWS_ACCOUNT_ID,
                region=AWS_REGION,
                arn=AWS_ACCOUNT_ARN,
                enabled_in_account=False,
            )
        )
        guardduty_client.audited_account_arn = AWS_ACCOUNT_ARN
        with mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_service.GuardDuty",
            guardduty_client,
        ):
            from prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled import (
                guardduty_is_enabled,
            )

            check = guardduty_is_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == "GuardDuty is not enabled."
            assert result[0].resource_id == AWS_ACCOUNT_ID
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
            assert result[0].region == AWS_REGION

    def test_guardduty_enabled(self):
        guardduty_client = mock.MagicMock
        guardduty_client.detectors = []
        guardduty_client.detectors.append(
            Detector(
                id=DETECTOR_ID,
                region=AWS_REGION,
                arn=DETECTOR_ARN,
                status=True,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_service.GuardDuty",
            guardduty_client,
        ):
            from prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled import (
                guardduty_is_enabled,
            )

            check = guardduty_is_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"GuardDuty detector {DETECTOR_ID} enabled."
            )
            assert result[0].resource_id == DETECTOR_ID
            assert result[0].resource_arn == DETECTOR_ARN
            assert result[0].region == AWS_REGION

    def test_guardduty_configured_but_suspended(self):
        guardduty_client = mock.MagicMock
        guardduty_client.detectors = []
        guardduty_client.detectors.append(
            Detector(
                id=DETECTOR_ID,
                arn=DETECTOR_ARN,
                region=AWS_REGION,
                status=False,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_service.GuardDuty",
            guardduty_client,
        ):
            from prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled import (
                guardduty_is_enabled,
            )

            check = guardduty_is_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"GuardDuty detector {DETECTOR_ID} configured but suspended."
            )
            assert result[0].resource_id == DETECTOR_ID
            assert result[0].resource_arn == DETECTOR_ARN
            assert result[0].region == AWS_REGION

    def test_guardduty_not_configured(self):
        guardduty_client = mock.MagicMock
        guardduty_client.detectors = []
        guardduty_client.detectors.append(
            Detector(
                id=DETECTOR_ID,
                arn=DETECTOR_ARN,
                region=AWS_REGION,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_service.GuardDuty",
            guardduty_client,
        ):
            from prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled import (
                guardduty_is_enabled,
            )

            check = guardduty_is_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"GuardDuty detector {DETECTOR_ID} not configured."
            )
            assert result[0].resource_id == DETECTOR_ID
            assert result[0].resource_arn == DETECTOR_ARN
            assert result[0].region == AWS_REGION
