from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_iam_password_policy_symbol:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
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
        )

        return audit_info

    @mock_iam
    def test_iam_password_policy_no_symbol_flag(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(RequireSymbols=False)

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_symbol.iam_password_policy_symbol.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_password_policy_symbol.iam_password_policy_symbol import (
                iam_password_policy_symbol,
            )

            check = iam_password_policy_symbol()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert search(
                "IAM password policy does not require at least one symbol.",
                result[0].status_extended,
            )
            assert result[0].resource_id == "password_policy"

    @mock_iam
    def test_iam_password_policy_symbol_flag(self):
        iam_client = client("iam")
        # update password policy
        iam_client.update_account_password_policy(RequireSymbols=True)

        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_password_policy_symbol.iam_password_policy_symbol.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_password_policy_symbol.iam_password_policy_symbol import (
                iam_password_policy_symbol,
            )

            check = iam_password_policy_symbol()
            result = check.execute()
            assert result[0].status == "PASS"
            assert search(
                "IAM password policy requires at least one symbol.",
                result[0].status_extended,
            )
            assert result[0].resource_id == "password_policy"
