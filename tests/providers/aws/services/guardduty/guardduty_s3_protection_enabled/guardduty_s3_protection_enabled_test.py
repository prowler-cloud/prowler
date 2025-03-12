from unittest import mock

from prowler.providers.aws.services.guardduty.guardduty_service import Detector
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_guardduty_s3_protection_enabled:
    def test_no_detectors(self):
        guardduty_client = mock.MagicMock()
        guardduty_client.detectors = []

        with mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_service.GuardDuty",
            new=guardduty_client,
        ), mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_s3_protection_enabled.guardduty_s3_protection_enabled.guardduty_client",
            new=guardduty_client,
        ):

            from prowler.providers.aws.services.guardduty.guardduty_s3_protection_enabled.guardduty_s3_protection_enabled import (
                guardduty_s3_protection_enabled,
            )

            check = guardduty_s3_protection_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_detector_disabled(self):
        guardduty_client = mock.MagicMock()
        detector_arn = f"arn:aws:guardduty:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:detector/1234567890"
        guardduty_client.detectors = [
            Detector(
                id="1234567890",
                arn=detector_arn,
                region=AWS_REGION_US_EAST_1,
                tags=[],
                enabled_in_account=False,
                s3_protection=False,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_service.GuardDuty",
            new=guardduty_client,
        ), mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_s3_protection_enabled.guardduty_s3_protection_enabled.guardduty_client",
            new=guardduty_client,
        ):

            from prowler.providers.aws.services.guardduty.guardduty_s3_protection_enabled.guardduty_s3_protection_enabled import (
                guardduty_s3_protection_enabled,
            )

            check = guardduty_s3_protection_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_detector_enabled_s3_protection_disabled(self):
        guardduty_client = mock.MagicMock()
        detector_arn = f"arn:aws:guardduty:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:detector/1234567890"
        guardduty_client.detectors = [
            Detector(
                id="1234567890",
                arn=detector_arn,
                region=AWS_REGION_US_EAST_1,
                tags=[],
                enabled_in_account=True,
                s3_protection=False,
                status=True,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_service.GuardDuty",
            new=guardduty_client,
        ), mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_s3_protection_enabled.guardduty_s3_protection_enabled.guardduty_client",
            new=guardduty_client,
        ):

            from prowler.providers.aws.services.guardduty.guardduty_s3_protection_enabled.guardduty_s3_protection_enabled import (
                guardduty_s3_protection_enabled,
            )

            check = guardduty_s3_protection_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "GuardDuty detector does not have S3 Protection enabled."
            )
            assert result[0].resource_id == "1234567890"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == detector_arn
            assert result[0].resource_tags == []

    def test_detector_enabled_s3_protection_enabled(self):
        guardduty_client = mock.MagicMock()
        detector_arn = f"arn:aws:guardduty:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:detector/1234567890"
        guardduty_client.detectors = [
            Detector(
                id="1234567890",
                arn=detector_arn,
                region=AWS_REGION_US_EAST_1,
                tags=[],
                enabled_in_account=True,
                s3_protection=True,
                status=True,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_service.GuardDuty",
            new=guardduty_client,
        ), mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_s3_protection_enabled.guardduty_s3_protection_enabled.guardduty_client",
            new=guardduty_client,
        ):
            from prowler.providers.aws.services.guardduty.guardduty_s3_protection_enabled.guardduty_s3_protection_enabled import (
                guardduty_s3_protection_enabled,
            )

            check = guardduty_s3_protection_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "GuardDuty detector has S3 Protection enabled."
            )
            assert result[0].resource_id == "1234567890"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == detector_arn
            assert result[0].resource_tags == []
