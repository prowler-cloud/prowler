import datetime
from re import search
from unittest import mock

from boto3 import client
from moto import mock_iam


class Test_iam_disable_30_days_credentials_test:
    @mock_iam
    def test_iam_user_logged_30_days(self):
        password_last_used = (
            datetime.datetime.now() - datetime.timedelta(days=2)
        ).strftime("%Y-%m-%d %H:%M:%S+00:00")
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials import (
                iam_disable_30_days_credentials,
            )

            service_client.users[0].password_last_used = password_last_used
            check = iam_disable_30_days_credentials()
            result = check.execute()
            assert result[0].status == "PASS"
            assert search(
                f"User {user} has logged in to the console in the past 30 days.",
                result[0].status_extended,
            )
            assert result[0].resource_id == user
            assert result[0].resource_arn == arn

    @mock_iam
    def test_iam_user_not_logged_30_days(self):
        password_last_used = (
            datetime.datetime.now() - datetime.timedelta(days=60)
        ).strftime("%Y-%m-%d %H:%M:%S+00:00")
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials import (
                iam_disable_30_days_credentials,
            )

            service_client.users[0].password_last_used = password_last_used
            check = iam_disable_30_days_credentials()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert search(
                f"User {user} has not logged in to the console in the past 30 days.",
                result[0].status_extended,
            )
            assert result[0].resource_id == user
            assert result[0].resource_arn == arn

    @mock_iam
    def test_iam_user_not_logged(self):
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]
        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials import (
                iam_disable_30_days_credentials,
            )

            service_client.users[0].password_last_used = ""
            # raise Exception
            check = iam_disable_30_days_credentials()
            result = check.execute()
            assert result[0].status == "PASS"
            assert search(
                f"User {user} does not have a console password or is unused.",
                result[0].status_extended,
            )
            assert result[0].resource_id == user
            assert result[0].resource_arn == arn

    @mock_iam
    def test_user_no_access_keys(self):
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "prowler.providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials import (
                iam_disable_30_days_credentials,
            )

            service_client.credential_report[0]["access_key_1_last_rotated"] == "N/A"
            service_client.credential_report[0]["access_key_2_last_rotated"] == "N/A"

            check = iam_disable_30_days_credentials()
            result = check.execute()
            assert result[-1].status == "PASS"
            assert (
                result[-1].status_extended == f"User {user} does not have access keys."
            )
            assert result[-1].resource_id == user
            assert result[-1].resource_arn == arn

    @mock_iam
    def test_user_access_key_1_not_used(self):
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
            "prowler.providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials import (
                iam_disable_30_days_credentials,
            )

            service_client.credential_report[0]["access_key_1_active"] = "true"
            service_client.credential_report[0][
                "access_key_1_last_used_date"
            ] = credentials_last_rotated

            check = iam_disable_30_days_credentials()
            result = check.execute()
            assert result[-1].status == "FAIL"
            assert (
                result[-1].status_extended
                == f"User {user} has not used access key 1 in the last 30 days (100 days)."
            )
            assert result[-1].resource_id == user
            assert result[-1].resource_arn == arn

    @mock_iam
    def test_user_access_key_2_not_used(self):
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
            "prowler.providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials import (
                iam_disable_30_days_credentials,
            )

            service_client.credential_report[0]["access_key_2_active"] = "true"
            service_client.credential_report[0][
                "access_key_2_last_used_date"
            ] = credentials_last_rotated

            check = iam_disable_30_days_credentials()
            result = check.execute()
            assert result[-1].status == "FAIL"
            assert (
                result[-1].status_extended
                == f"User {user} has not used access key 2 in the last 30 days (100 days)."
            )
            assert result[-1].resource_id == user
            assert result[-1].resource_arn == arn
