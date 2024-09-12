from unittest import mock
from uuid import uuid4

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

DETECTOR_ID = str(uuid4())
DETECTOR_ARN = f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{DETECTOR_ID}"


class Test_guardduty_is_enabled_fixer:
    @mock_aws
    def test_guardduty_is_enabled_fixer(self):
        from prowler.providers.aws.services.guardduty.guardduty_service import GuardDuty

        aws_provider = set_mocked_aws_provider(
            audited_regions=[AWS_REGION_EU_WEST_1],
            fixer_config={
                "guardduty_is_enabled": {
                    "DetectorId": DETECTOR_ID,
                },
            },
        )

        guardduty = client("guardduty", region_name=AWS_REGION_EU_WEST_1)
        guardduty.create_detector(
            Enable=True,
            FindingPublishingFrequency="FIFTEEN_MINUTES",
            DataSources={
                "S3Logs": {
                    "Enable": True,
                },
            },
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled_fixer.guardduty_client",
                new=GuardDuty(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled_fixer import (
                    fixer,
                )

                assert fixer(AWS_REGION_EU_WEST_1)
