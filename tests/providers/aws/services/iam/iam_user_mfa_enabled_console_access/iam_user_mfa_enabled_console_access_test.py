from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_iam_user_mfa_enabled_console_access_test:
    from tests.providers.aws.audit_info_utils import (
        AWS_ACCOUNT_ARN,
        AWS_ACCOUNT_NUMBER,
        AWS_REGION_US_EAST_1,
        set_mocked_aws_audit_info,
    )

    @mock_aws
    def test_root_user_not_password_console_enabled(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_mfa_enabled_console_access.iam_user_mfa_enabled_console_access.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_user_mfa_enabled_console_access.iam_user_mfa_enabled_console_access import (
                iam_user_mfa_enabled_console_access,
            )

            service_client.credential_report = [
                {
                    "user": "<root_account>",
                    "arn": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
                    "user_creation_time": "2022-02-17T14:59:38+00:00",
                    "password_enabled": "not_supported",
                    "password_last_used": "2023-05-22T09:52:24+00:00",
                    "password_last_changed": "not_supported",
                    "password_next_rotation": "not_supported",
                    "mfa_active": "true",
                    "access_key_1_active": "false",
                    "access_key_1_last_rotated": "N/A",
                    "access_key_1_last_used_date": "N/A",
                    "access_key_1_last_used_region": "N/A",
                    "access_key_1_last_used_service": "N/A",
                    "access_key_2_active": "false",
                    "access_key_2_last_rotated": "N/A",
                    "access_key_2_last_used_date": "N/A",
                    "access_key_2_last_used_region": "N/A",
                    "access_key_2_last_used_service": "N/A",
                    "cert_1_active": "false",
                    "cert_1_last_rotated": "N/A",
                    "cert_2_active": "false",
                    "cert_2_last_rotated": "N/A",
                }
            ]

            check = iam_user_mfa_enabled_console_access()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_user_not_password_console_enabled(self):
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_mfa_enabled_console_access.iam_user_mfa_enabled_console_access.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_user_mfa_enabled_console_access.iam_user_mfa_enabled_console_access import (
                iam_user_mfa_enabled_console_access,
            )

            service_client.credential_report[0]["password_enabled"] = "false"

            check = iam_user_mfa_enabled_console_access()
            result = check.execute()

            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"User {user} does not have Console Password enabled."
            )
            assert result[0].resource_id == user
            assert result[0].resource_arn == arn

    @mock_aws
    def test_user_password_console_and_mfa_enabled(self):
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_mfa_enabled_console_access.iam_user_mfa_enabled_console_access.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_user_mfa_enabled_console_access.iam_user_mfa_enabled_console_access import (
                iam_user_mfa_enabled_console_access,
            )

            service_client.credential_report[0]["password_enabled"] = "true"
            service_client.credential_report[0]["mfa_active"] = "true"

            check = iam_user_mfa_enabled_console_access()
            result = check.execute()

            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"User {user} has Console Password enabled and MFA enabled."
            )
            assert result[0].resource_id == user
            assert result[0].resource_arn == arn

    @mock_aws
    def test_user_password_console_enabled_and_mfa_not_enabled(self):
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])
        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_mfa_enabled_console_access.iam_user_mfa_enabled_console_access.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_user_mfa_enabled_console_access.iam_user_mfa_enabled_console_access import (
                iam_user_mfa_enabled_console_access,
            )

            service_client.credential_report[0]["password_enabled"] = "true"
            service_client.credential_report[0]["mfa_active"] = "false"

            check = iam_user_mfa_enabled_console_access()
            result = check.execute()

            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"User {user} has Console Password enabled but MFA disabled."
            )
            assert result[0].resource_id == user
            assert result[0].resource_arn == arn
