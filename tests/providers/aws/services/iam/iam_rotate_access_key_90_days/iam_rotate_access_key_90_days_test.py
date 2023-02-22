import datetime
from unittest import mock

from boto3 import client
from moto import mock_iam


class Test_iam_rotate_access_key_90_days_test:
    @mock_iam
    def test_user_no_access_keys(self):
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_rotate_access_key_90_days.iam_rotate_access_key_90_days.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_rotate_access_key_90_days.iam_rotate_access_key_90_days import (
                iam_rotate_access_key_90_days,
            )

            service_client.credential_report[0]["access_key_1_last_rotated"] == "N/A"
            service_client.credential_report[0]["access_key_2_last_rotated"] == "N/A"

            check = iam_rotate_access_key_90_days()
            result = check.execute()
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended == f"User {user} does not have access keys."
            )
            assert result[0].resource_id == user
            assert result[0].resource_arn == arn

    @mock_iam
    def test_user_access_key_1_not_rotated(self):
        credentials_last_rotated = (
            datetime.datetime.now() - datetime.timedelta(days=100)
        ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_rotate_access_key_90_days.iam_rotate_access_key_90_days.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_rotate_access_key_90_days.iam_rotate_access_key_90_days import (
                iam_rotate_access_key_90_days,
            )

            service_client.credential_report[0]["access_key_1_active"] = "true"
            service_client.credential_report[0][
                "access_key_1_last_rotated"
            ] = credentials_last_rotated

            check = iam_rotate_access_key_90_days()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"User {user} has not rotated access key 1 in over 90 days (100 days)."
            )
            assert result[0].resource_id == user
            assert result[0].resource_arn == arn

    @mock_iam
    def test_user_access_key_2_not_rotated(self):
        credentials_last_rotated = (
            datetime.datetime.now() - datetime.timedelta(days=100)
        ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_rotate_access_key_90_days.iam_rotate_access_key_90_days.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_rotate_access_key_90_days.iam_rotate_access_key_90_days import (
                iam_rotate_access_key_90_days,
            )

            service_client.credential_report[0]["access_key_2_active"] = "true"
            service_client.credential_report[0][
                "access_key_2_last_rotated"
            ] = credentials_last_rotated

            check = iam_rotate_access_key_90_days()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"User {user} has not rotated access key 2 in over 90 days (100 days)."
            )
            assert result[0].resource_id == user
            assert result[0].resource_arn == arn
