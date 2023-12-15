from re import search
from unittest import mock

from boto3 import client
from moto import mock_iam

from tests.providers.aws.audit_info_utils import (
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

    @mock_iam
    def test_root_hardware_virtual_mfa_enabled(self):
        iam = client("iam")
        mfa_device_name = "mfa-test"
        iam.create_virtual_mfa_device(VirtualMFADeviceName=mfa_device_name)

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled import (
                iam_root_hardware_mfa_enabled,
            )

            service_client.account_summary["SummaryMap"]["AccountMFAEnabled"] = 1
            service_client.virtual_mfa_devices[0]["SerialNumber"] = "sddfaf-root-sfsfds"

            check = iam_root_hardware_mfa_enabled()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert search(
                "Root account has a virtual MFA instead of a hardware MFA device enabled.",
                result[0].status_extended,
            )
            assert result[0].resource_id == "<root_account>"

    @mock_iam
    def test_root_hardware_virtual_hardware_mfa_enabled(self):
        iam = client("iam")
        mfa_device_name = "mfa-test"
        iam.create_virtual_mfa_device(VirtualMFADeviceName=mfa_device_name)

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_root_hardware_mfa_enabled.iam_root_hardware_mfa_enabled import (
                iam_root_hardware_mfa_enabled,
            )

            service_client.account_summary["SummaryMap"]["AccountMFAEnabled"] = 1
            service_client.virtual_mfa_devices[0]["SerialNumber"] = ""

            check = iam_root_hardware_mfa_enabled()
            result = check.execute()
            assert result[0].status == "PASS"
            assert search(
                "Root account has a hardware MFA device enabled.",
                result[0].status_extended,
            )
            assert result[0].resource_id == "<root_account>"
            assert (
                result[0].resource_arn
                == f"arn:aws:iam::{service_client.audited_account}:root"
            )
