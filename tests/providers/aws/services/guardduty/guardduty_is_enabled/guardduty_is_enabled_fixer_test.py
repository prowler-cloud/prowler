from unittest import mock
from uuid import uuid4

import botocore
import botocore.client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

DETECTOR_ID = str(uuid4())
DETECTOR_ARN = f"arn:aws:guardduty:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:detector/{DETECTOR_ID}"

mock_make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call_create_detector_success(self, operation_name, kwarg):
    if operation_name == "CreateDetector":
        return {"DetectorId": DETECTOR_ID}
    elif operation_name == "GetDetector":
        return {"Status": "ENABLED"}
    return mock_make_api_call(self, operation_name, kwarg)


def mock_make_api_call_create_detector_failure(self, operation_name, kwarg):
    if operation_name == "CreateDetector":
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "AccessDeniedException",
                    "Message": "User: arn:aws:iam::012345678901:user/test is not authorized to perform: guardduty:CreateDetector",
                }
            },
            "CreateDetector",
        )
    return mock_make_api_call(self, operation_name, kwarg)


class Test_guardduty_is_enabled_fixer:
    @mock_aws
    def test_guardduty_is_enabled_fixer(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_create_detector_success,
        ):

            from prowler.providers.aws.services.guardduty.guardduty_service import (
                GuardDuty,
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled_fixer.guardduty_client",
                new=GuardDuty(aws_provider),
            ):
                from prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled_fixer import (
                    fixer,
                )

                assert fixer(AWS_REGION_EU_WEST_1)

    @mock_aws
    def test_guardduty_is_enabled_fixer_failure(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_create_detector_failure,
        ):

            from prowler.providers.aws.services.guardduty.guardduty_service import (
                GuardDuty,
            )

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled_fixer.guardduty_client",
                new=GuardDuty(aws_provider),
            ):
                from prowler.providers.aws.services.guardduty.guardduty_is_enabled.guardduty_is_enabled_fixer import (
                    fixer,
                )

                assert not fixer(AWS_REGION_EU_WEST_1)
