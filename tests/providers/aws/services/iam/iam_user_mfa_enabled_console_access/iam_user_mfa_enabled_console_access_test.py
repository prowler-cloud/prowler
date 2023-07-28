from unittest import mock

from boto3 import client, session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_iam_user_mfa_enabled_console_access_test:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=["us-east-1", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )

        return audit_info

    @mock_iam
    def test_root_user_not_password_console_enabled(self):
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = self.set_mocked_audit_info()
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

            service_client.credential_report[0]["password_enabled"] = "not_supported"

            check = iam_user_mfa_enabled_console_access()
            result = check.execute()

            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"User {user} does not have Console Password enabled."
            )
            assert result[0].resource_id == user
            assert result[0].resource_arn == arn

    @mock_iam
    def test_user_not_password_console_enabled(self):
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = self.set_mocked_audit_info()
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

    @mock_iam
    def test_user_password_console_and_mfa_enabled(self):
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = self.set_mocked_audit_info()
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

    @mock_iam
    def test_user_password_console_enabled_and_mfa_not_enabled(self):
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = self.set_mocked_audit_info()
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
