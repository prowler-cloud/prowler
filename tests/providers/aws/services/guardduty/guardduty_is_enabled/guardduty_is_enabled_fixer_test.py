from unittest import mock
from uuid import uuid4

from tests.providers.aws.utils import (
    AWS_ACCOUNT_ARN,
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
)

DETECTOR_ID = str(uuid4())
DETECTOR_ARN = f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{DETECTOR_ID}"


class Test_guardduty_is_enabled_fixer:
    @mock.patch("prowler.providers.aws.services.guardduty.guardduty_service.GuardDuty")
    def test_guardduty_is_enabled_fixer(self, mock_guardduty_client_class):
        mock_client = mock.MagicMock()
        mock_client.region = AWS_REGION_EU_WEST_1
        mock_client.detectors = []
        mock_client.audited_account_arn = AWS_ACCOUNT_ARN
        mock_guardduty_client_class.return_value.regional_clients = {
            AWS_REGION_EU_WEST_1: mock_client
        }

        mock_client.create_detector.return_value = None

        from prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled_fixer import (
            fixer,
        )

        result = fixer(AWS_REGION_EU_WEST_1)
        assert result
