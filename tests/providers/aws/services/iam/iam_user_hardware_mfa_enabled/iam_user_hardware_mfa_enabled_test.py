from re import search
from unittest import mock

from boto3 import client
from moto import mock_iam

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_iam_user_hardware_mfa_enabled_test:
    from tests.providers.aws.audit_info_utils import (
        AWS_ACCOUNT_ARN,
        AWS_ACCOUNT_NUMBER,
        AWS_REGION_US_EAST_1,
        set_mocked_aws_audit_info,
    )

    @mock_iam
    def test_user_no_mfa_devices(self):
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_hardware_mfa_enabled.iam_user_hardware_mfa_enabled.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_user_hardware_mfa_enabled.iam_user_hardware_mfa_enabled import (
                iam_user_hardware_mfa_enabled,
            )

            service_client.users[0].mfa_devices = []
            check = iam_user_hardware_mfa_enabled()
            result = check.execute()

            assert result[0].status == "FAIL"
            assert search(
                f"User {user} does not have any type of MFA enabled.",
                result[0].status_extended,
            )
            assert result[0].resource_id == user
            assert result[0].resource_arn == arn

    @mock_iam
    def test_user_virtual_mfa_devices(self):
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM, MFADevice

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_hardware_mfa_enabled.iam_user_hardware_mfa_enabled.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_user_hardware_mfa_enabled.iam_user_hardware_mfa_enabled import (
                iam_user_hardware_mfa_enabled,
            )

            mfa_devices = [
                MFADevice(serial_number="123454", type="mfa"),
                MFADevice(serial_number="1234547", type="sms-mfa"),
            ]

            service_client.users[0].mfa_devices = mfa_devices
            check = iam_user_hardware_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"User {user} has a virtual MFA instead of a hardware MFA device enabled.",
                result[0].status_extended,
            )
            assert result[0].resource_id == user
            assert result[0].resource_arn == arn

    @mock_iam
    def test_user_virtual_sms_mfa_devices(self):
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM, MFADevice

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_hardware_mfa_enabled.iam_user_hardware_mfa_enabled.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_user_hardware_mfa_enabled.iam_user_hardware_mfa_enabled import (
                iam_user_hardware_mfa_enabled,
            )

            mfa_devices = [
                MFADevice(serial_number="123454", type="test-mfa"),
                MFADevice(serial_number="1234547", type="sms-mfa"),
            ]

            service_client.users[0].mfa_devices = mfa_devices
            check = iam_user_hardware_mfa_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search(
                f"User {user} has a virtual MFA instead of a hardware MFA device enabled.",
                result[0].status_extended,
            )
            assert result[0].resource_id == user
            assert result[0].resource_arn == arn
