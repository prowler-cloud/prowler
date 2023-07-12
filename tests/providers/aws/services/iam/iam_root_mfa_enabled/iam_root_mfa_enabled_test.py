from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_iam_root_mfa_enabled_test:
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
        )

        return audit_info

    @mock_iam
    def test_root_mfa_not_enabled(self):
        iam_client = client("iam")
        user = "test-user"
        iam_client.create_user(UserName=user)["User"]["Arn"]

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_root_mfa_enabled.iam_root_mfa_enabled.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_root_mfa_enabled.iam_root_mfa_enabled import (
                iam_root_mfa_enabled,
            )

            service_client.credential_report[0]["user"] = "<root_account>"
            service_client.credential_report[0]["mfa_active"] = "false"
            service_client.credential_report[0][
                "arn"
            ] = "arn:aws:iam::123456789012:<root_account>:root"

            check = iam_root_mfa_enabled()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert search(
                "MFA is not enabled for root account.", result[0].status_extended
            )
            assert result[0].resource_id == "<root_account>"
            assert result[0].resource_arn == service_client.credential_report[0]["arn"]

    @mock_iam
    def test_root_mfa_enabled(self):
        iam_client = client("iam")
        user = "test-user"
        iam_client.create_user(UserName=user)["User"]["Arn"]

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_root_mfa_enabled.iam_root_mfa_enabled.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_root_mfa_enabled.iam_root_mfa_enabled import (
                iam_root_mfa_enabled,
            )

            service_client.credential_report[0]["user"] = "<root_account>"
            service_client.credential_report[0]["mfa_active"] = "true"
            service_client.credential_report[0][
                "arn"
            ] = "arn:aws:iam::123456789012:<root_account>:root"

            check = iam_root_mfa_enabled()
            result = check.execute()
            assert result[0].status == "PASS"
            assert search("MFA is enabled for root account.", result[0].status_extended)
            assert result[0].resource_id == "<root_account>"
            assert result[0].resource_arn == service_client.credential_report[0]["arn"]
