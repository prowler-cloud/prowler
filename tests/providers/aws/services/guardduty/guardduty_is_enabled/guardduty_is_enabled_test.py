from re import search
from unittest import mock
from uuid import uuid4

from prowler.providers.aws.services.guardduty.guardduty_service import Detector

AWS_REGION = "us-east-1"
AWS_ACCOUNT_ID = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"

detector_id = str(uuid4())
detector_arn = f"arn:aws:guardduty:{AWS_REGION}:{AWS_ACCOUNT_ID}:detector/{detector_id}"


class Test_guardduty_is_enabled:
    def test_no_detectors(self):
        guardduty_client = mock.MagicMock
        guardduty_client.detectors = []
        guardduty_client.detectors.append(
            Detector(
                id=AWS_ACCOUNT_ID,
                region=AWS_REGION,
                arn=AWS_ACCOUNT_ARN,
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
            assert search("is not enabled", result[0].status_extended)
            assert result[0].resource_id == AWS_ACCOUNT_ID
            assert result[0].resource_arn == AWS_ACCOUNT_ARN
            assert result[0].region == AWS_REGION

    def test_guardduty_enabled(self):
        guardduty_client = mock.MagicMock
        guardduty_client.detectors = []
        guardduty_client.detectors.append(
            Detector(
                id=detector_id,
                region=AWS_REGION,
                arn=detector_arn,
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
            assert search("enabled", result[0].status_extended)
            assert result[0].resource_id == detector_id
            assert result[0].resource_arn == detector_arn
            assert result[0].region == AWS_REGION

    def test_guardduty_configured_but_suspended(self):
        guardduty_client = mock.MagicMock
        guardduty_client.detectors = []
        guardduty_client.detectors.append(
            Detector(
                id=detector_id,
                arn=detector_arn,
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
            assert search("configured but suspended", result[0].status_extended)
            assert result[0].resource_id == detector_id
            assert result[0].resource_arn == detector_arn
            assert result[0].region == AWS_REGION

    def test_guardduty_not_configured(self):
        guardduty_client = mock.MagicMock
        guardduty_client.detectors = []
        guardduty_client.detectors.append(
            Detector(
                id=detector_id,
                arn=detector_arn,
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
            assert search("not configured", result[0].status_extended)
            assert result[0].resource_id == detector_id
            assert result[0].resource_arn == detector_arn
            assert result[0].region == AWS_REGION

    def test_guardduty_not_configured_allowlisted(self):
        guardduty_client = mock.MagicMock
        guardduty_client.audit_config = {"allowlist_non_default_regions": True}
        guardduty_client.detectors = []
        guardduty_client.detectors.append(
            Detector(
                id=detector_id,
                arn=detector_arn,
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
            assert result[0].status == "WARNING"
            assert (
                result[0].status_extended
                == f"GuardDuty detector {detector_id} not configured."
            )
            assert result[0].resource_id == detector_id
            assert result[0].resource_arn == detector_arn
            assert result[0].region == AWS_REGION
