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
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials import (
                iam_disable_30_days_credentials,
            )

            service_client.users[0].password_last_used = password_last_used
            check = iam_disable_30_days_credentials()
            result = check.execute()
            assert result[0].status == "PASS"
            assert search(
                f"User {user} has logged into the console in the past 30 days.",
                result[0].status_extended,
            )
            assert result[0].resource_id == user
            assert result[0].resource_arn == arn

    @mock_iam
    def test_iam_user_not_logged_30_days(self):
        password_last_used = (
            datetime.datetime.now() - datetime.timedelta(days=40)
        ).strftime("%Y-%m-%d %H:%M:%S+00:00")
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials import (
                iam_disable_30_days_credentials,
            )

            service_client.users[0].password_last_used = password_last_used
            check = iam_disable_30_days_credentials()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert search(
                f"User {user} has not logged into the console in the past 30 days.",
                result[0].status_extended,
            )
            assert result[0].resource_id == user
            assert result[0].resource_arn == arn

    @mock_iam
    def test_iam_user_not_logged(self):
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]
        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from providers.aws.services.iam.iam_disable_30_days_credentials.iam_disable_30_days_credentials import (
                iam_disable_30_days_credentials,
            )

            service_client.users[0].password_last_used = ""

            # raise Exception
            check = iam_disable_30_days_credentials()
            result = check.execute()
            assert result[0].status == "PASS"
            assert search(
                f"User {user} has not a console password or is unused.",
                result[0].status_extended,
            )
            assert result[0].resource_id == user
            assert result[0].resource_arn == arn
