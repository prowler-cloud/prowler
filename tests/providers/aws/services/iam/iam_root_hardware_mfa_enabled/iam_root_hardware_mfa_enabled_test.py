from re import search
from unittest import mock

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_iam_root_hardware_mfa_enabled_test:
    from tests.providers.aws.audit_info_utils import (
        AWS_ACCOUNT_ARN,
        AWS_ACCOUNT_NUMBER,
        AWS_REGION_US_EAST_1,
        set_mocked_aws_audit_info,
    )

    def test_root_virtual_mfa_enabled(self):
        iam_client = mock.MagicMock
        iam_client.account_summary = {
            "SummaryMap": {"AccountMFAEnabled": 1},
        }
        iam_client.virtual_mfa_devices = [
            {
                "SerialNumber": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:mfa/mfa",
                "User": {"Arn": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"},
            }
        ]
        iam_client.audited_partition = "aws"
        iam_client.region = AWS_REGION_US_EAST_1
        iam_client.mfa_arn_template = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:mfa"

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled.iam_client",
            new=iam_client,
        ):
            from prowler.providers.aws.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled import (
                iam_root_hardware_mfa_enabled,
            )

            check = iam_root_hardware_mfa_enabled()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert search(
                "Root account has a virtual MFA instead of a hardware MFA device enabled.",
                result[0].status_extended,
            )
            assert result[0].resource_id == "<root_account>"

    def test_root_hardware_mfa_enabled(self):
        iam_client = mock.MagicMock
        iam_client.account_summary = {
            "SummaryMap": {"AccountMFAEnabled": 1},
        }
        iam_client.virtual_mfa_devices = []
        iam_client.audited_partition = "aws"
        iam_client.region = AWS_REGION_US_EAST_1
        iam_client.mfa_arn_template = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:mfa"

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled.iam_client",
            new=iam_client,
        ):
            from prowler.providers.aws.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled import (
                iam_root_hardware_mfa_enabled,
            )

            check = iam_root_hardware_mfa_enabled()
            result = check.execute()
            assert result[0].status == "PASS"
            assert search(
                "Root account has a hardware MFA device enabled.",
                result[0].status_extended,
            )
            assert result[0].resource_id == "<root_account>"
