from unittest import mock
from uuid import uuid4

from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_ARN,
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
)

DETECTOR_ID = str(uuid4())
DETECTOR_ARN = f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{DETECTOR_ID}"


class Test_guardduty_is_enabled_fixer:
    @mock_aws
    def test_guardduty_is_enabled_fixer(self):
        guardduty_client = mock.MagicMock
        guardduty_client.region = AWS_REGION_EU_WEST_1
        guardduty_client.detectors = []
        guardduty_client.audited_account_arn = AWS_ACCOUNT_ARN
        with mock.patch(
            "prowler.providers.aws.services.guardduty.guardduty_service.GuardDuty",
            guardduty_client,
        ):
            from prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled_fixer import (
                fixer,
            )

            assert fixer(AWS_REGION_EU_WEST_1)
