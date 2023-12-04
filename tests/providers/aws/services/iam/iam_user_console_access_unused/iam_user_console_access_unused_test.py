import datetime
from unittest import mock

from boto3 import client
from moto import mock_iam

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)


class Test_iam_user_console_access_unused_test:
    @mock_iam
    def test_iam_user_logged_45_days(self):
        password_last_used = (
            datetime.datetime.now() - datetime.timedelta(days=2)
        ).strftime("%Y-%m-%d %H:%M:%S+00:00")
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1], audit_config={"max_console_access_days": 45}
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_user_console_access_unused.iam_user_console_access_unused.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_user_console_access_unused.iam_user_console_access_unused import (
                    iam_user_console_access_unused,
                )

                service_client.users[0].password_last_used = password_last_used
                check = iam_user_console_access_unused()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"User {user} has logged in to the console in the past 45 days (2 days)."
                )
                assert result[0].resource_id == user
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_iam
    def test_iam_user_not_logged_45_days(self):
        password_last_used = (
            datetime.datetime.now() - datetime.timedelta(days=60)
        ).strftime("%Y-%m-%d %H:%M:%S+00:00")
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1], audit_config={"max_console_access_days": 45}
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_user_console_access_unused.iam_user_console_access_unused.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_user_console_access_unused.iam_user_console_access_unused import (
                    iam_user_console_access_unused,
                )

                service_client.users[0].password_last_used = password_last_used
                check = iam_user_console_access_unused()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"User {user} has not logged in to the console in the past 45 days (60 days)."
                )
                assert result[0].resource_id == user
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_iam
    def test_iam_user_not_logged(self):
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1], audit_config={"max_console_access_days": 45}
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_user_console_access_unused.iam_user_console_access_unused.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_user_console_access_unused.iam_user_console_access_unused import (
                    iam_user_console_access_unused,
                )

                service_client.users[0].password_last_used = ""
                # raise Exception
                check = iam_user_console_access_unused()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"User {user} does not have a console password or is unused."
                )
                assert result[0].resource_id == user
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION_EU_WEST_1
