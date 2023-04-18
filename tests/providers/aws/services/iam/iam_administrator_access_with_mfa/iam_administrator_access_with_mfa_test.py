from json import dumps
from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_iam_administrator_access_with_mfa_test:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
                region_name=AWS_REGION,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=AWS_REGION,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    @mock_iam
    def test_group_with_no_policies(self):
        iam = client("iam")
        group_name = "test-group"

        arn = iam.create_group(GroupName=group_name)["Group"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_administrator_access_with_mfa.iam_administrator_access_with_mfa.iam_client",
                new=IAM(audit_info),
            ):
                from prowler.providers.aws.services.iam.iam_administrator_access_with_mfa.iam_administrator_access_with_mfa import (
                    iam_administrator_access_with_mfa,
                )

                check = iam_administrator_access_with_mfa()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == group_name
                assert result[0].resource_arn == arn
                assert search(
                    f"Group {group_name} has no policies.", result[0].status_extended
                )

    @mock_iam
    def test_group_non_administrative_policy(self):
        iam = client("iam")
        group_name = "test-group"
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "logs:CreateLogGroup", "Resource": "*"},
            ],
        }
        policy_arn = iam.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]
        arn = iam.create_group(GroupName=group_name)["Group"]["Arn"]
        iam.attach_group_policy(GroupName=group_name, PolicyArn=policy_arn)

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_administrator_access_with_mfa.iam_administrator_access_with_mfa.iam_client",
                new=IAM(audit_info),
            ):
                from prowler.providers.aws.services.iam.iam_administrator_access_with_mfa.iam_administrator_access_with_mfa import (
                    iam_administrator_access_with_mfa,
                )

                check = iam_administrator_access_with_mfa()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == group_name
                assert result[0].resource_arn == arn
                assert search(
                    f"Group {group_name} provides non-administrative access.",
                    result[0].status_extended,
                )

    @mock_iam
    def test_admin_policy_no_users(self):
        iam = client("iam")
        group_name = "test-group"

        arn = iam.create_group(GroupName=group_name)["Group"]["Arn"]
        iam.attach_group_policy(
            GroupName=group_name,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        )

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_administrator_access_with_mfa.iam_administrator_access_with_mfa.iam_client",
                new=IAM(audit_info),
            ):
                from prowler.providers.aws.services.iam.iam_administrator_access_with_mfa.iam_administrator_access_with_mfa import (
                    iam_administrator_access_with_mfa,
                )

                check = iam_administrator_access_with_mfa()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == group_name
                assert result[0].resource_arn == arn
                assert search(
                    f"Group {group_name} provides administrative access but does not have users.",
                    result[0].status_extended,
                )

    @mock_iam
    def test_admin_policy_with_user_without_mfa(self):
        iam = client("iam")
        group_name = "test-group"
        user_name = "user-test"
        iam.create_user(UserName=user_name)
        arn = iam.create_group(GroupName=group_name)["Group"]["Arn"]
        iam.attach_group_policy(
            GroupName=group_name,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
        iam.add_user_to_group(GroupName=group_name, UserName=user_name)

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_administrator_access_with_mfa.iam_administrator_access_with_mfa.iam_client",
                new=IAM(audit_info),
            ):
                from prowler.providers.aws.services.iam.iam_administrator_access_with_mfa.iam_administrator_access_with_mfa import (
                    iam_administrator_access_with_mfa,
                )

                check = iam_administrator_access_with_mfa()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == group_name
                assert result[0].resource_arn == arn
                assert search(
                    f"Group {group_name} provides administrator access to User {user_name} with MFA disabled.",
                    result[0].status_extended,
                )

    @mock_iam
    def test_various_policies_with_users_with_and_without_mfa(self):
        iam = client("iam")
        group_name = "test-group"
        user_name_no_mfa = "user-no-mfa"
        user_name_mfa = "user-mfa"
        policy_name = "policy1"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "logs:CreateLogGroup", "Resource": "*"},
            ],
        }
        mfa_device_name = "mfa-test"
        mfa_serial_number = iam.create_virtual_mfa_device(
            VirtualMFADeviceName=mfa_device_name
        )["VirtualMFADevice"]["SerialNumber"]
        iam.create_user(UserName=user_name_no_mfa)
        iam.create_user(UserName=user_name_mfa)
        iam.enable_mfa_device(
            UserName=user_name_mfa,
            SerialNumber=mfa_serial_number,
            AuthenticationCode1="123456",
            AuthenticationCode2="123466",
        )
        policy_arn = iam.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document)
        )["Policy"]["Arn"]
        arn_group = iam.create_group(GroupName=group_name)["Group"]["Arn"]
        iam.attach_group_policy(GroupName=group_name, PolicyArn=policy_arn)
        iam.attach_group_policy(
            GroupName=group_name,
            PolicyArn="arn:aws:iam::aws:policy/AdministratorAccess",
        )
        iam.add_user_to_group(GroupName=group_name, UserName=user_name_no_mfa)
        iam.add_user_to_group(GroupName=group_name, UserName=user_name_mfa)

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_administrator_access_with_mfa.iam_administrator_access_with_mfa.iam_client",
                new=IAM(audit_info),
            ):
                from prowler.providers.aws.services.iam.iam_administrator_access_with_mfa.iam_administrator_access_with_mfa import (
                    iam_administrator_access_with_mfa,
                )

                check = iam_administrator_access_with_mfa()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert result[0].resource_id == group_name
                assert result[0].resource_arn == arn_group
                assert search(
                    f"Group {group_name} provides administrator access to User {user_name_no_mfa} with MFA disabled.",
                    result[0].status_extended,
                )
