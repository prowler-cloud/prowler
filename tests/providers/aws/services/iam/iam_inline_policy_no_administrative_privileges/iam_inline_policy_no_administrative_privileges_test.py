from json import dumps
from unittest import mock

from boto3 import client, session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"

INLINE_POLICY_ADMIN = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["*"], "Resource": "*"}],
}

INLINE_POLICY_NOT_ADMIN = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"}],
}

ASSUME_ROLE_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": {
        "Sid": "test",
        "Effect": "Allow",
        "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"},
        "Action": "sts:AssumeRole",
    },
}


class Test_iam_inline_policy_no_administrative_privileges:
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
            audited_regions=[AWS_REGION],
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

    # Groups
    @mock_iam
    def test_groups_no_inline_policies(self):
        # IAM Client
        iam_client = client("iam")
        # Create IAM Group
        group_name = "test_group"
        _ = iam_client.create_group(GroupName=group_name)

        # Audit Info
        current_audit_info = self.set_mocked_audit_info()

        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges import (
                iam_inline_policy_no_administrative_privileges,
            )

            check = iam_inline_policy_no_administrative_privileges()
            results = check.execute()
            assert len(results) == 0

    @mock_iam
    def test_groups_admin_inline_policy(self):
        # IAM Client
        iam_client = client("iam")
        # Create IAM Group
        group_name = "test_group"
        group_arn = iam_client.create_group(GroupName=group_name)["Group"]["Arn"]

        # Put Group Policy
        policy_name = "test_admin_inline_policy"
        _ = iam_client.put_group_policy(
            GroupName=group_name,
            PolicyName=policy_name,
            PolicyDocument=dumps(INLINE_POLICY_ADMIN),
        )
        # Audit Info
        current_audit_info = self.set_mocked_audit_info()

        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges import (
                iam_inline_policy_no_administrative_privileges,
            )

            check = iam_inline_policy_no_administrative_privileges()
            results = check.execute()
            assert len(results) == 1
            assert results[0].region == AWS_REGION
            assert results[0].resource_arn == group_arn
            assert results[0].resource_id == f"{group_name}/{policy_name}"
            assert results[0].resource_tags == []
            assert results[0].status == "FAIL"
            assert (
                results[0].status_extended
                == f"Inline policy {policy_name} for IAM identity {group_arn} allows '*:*' administrative privileges."
            )

    @mock_iam
    def test_groups_no_admin_inline_policy(self):
        # IAM Client
        iam_client = client("iam")
        # Create IAM Group
        group_name = "test_group"
        group_arn = iam_client.create_group(GroupName=group_name)["Group"]["Arn"]

        # Put Group Policy
        policy_name = "test_not_admin_inline_policy"
        _ = iam_client.put_group_policy(
            GroupName=group_name,
            PolicyName=policy_name,
            PolicyDocument=dumps(INLINE_POLICY_NOT_ADMIN),
        )
        # Audit Info
        current_audit_info = self.set_mocked_audit_info()

        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges import (
                iam_inline_policy_no_administrative_privileges,
            )

            check = iam_inline_policy_no_administrative_privileges()
            results = check.execute()
            assert len(results) == 1
            assert results[0].region == AWS_REGION
            assert results[0].resource_arn == group_arn
            assert results[0].resource_id == f"{group_name}/{policy_name}"
            assert results[0].resource_tags == []
            assert results[0].status == "PASS"
            assert (
                results[0].status_extended
                == f"Inline policy {policy_name} for IAM identity {group_arn} does not allow '*:*' administrative privileges."
            )

    @mock_iam
    def test_groups_admin_and_not_admin_inline_policies(self):
        # IAM Client
        iam_client = client("iam")
        # Create IAM Group
        group_name = "test_group"
        group_arn = iam_client.create_group(GroupName=group_name)["Group"]["Arn"]

        # Put Group Policy NOT ADMIN
        policy_name_not_admin = "test_not_admin_inline_policy"
        _ = iam_client.put_group_policy(
            GroupName=group_name,
            PolicyName=policy_name_not_admin,
            PolicyDocument=dumps(INLINE_POLICY_NOT_ADMIN),
        )

        # Put Group Policy ADMIN
        policy_name_admin = "test_admin_inline_policy"
        _ = iam_client.put_group_policy(
            GroupName=group_name,
            PolicyName=policy_name_admin,
            PolicyDocument=dumps(INLINE_POLICY_ADMIN),
        )
        # Audit Info
        current_audit_info = self.set_mocked_audit_info()

        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges import (
                iam_inline_policy_no_administrative_privileges,
            )

            check = iam_inline_policy_no_administrative_privileges()
            results = check.execute()
            assert len(results) == 2
            for result in results:
                if result.resource_id == policy_name_admin:
                    assert result.region == AWS_REGION
                    assert result.resource_arn == group_arn
                    assert result.resource_id == policy_name_admin
                    assert result.resource_tags == []
                    assert result.status == "FAIL"
                    assert (
                        result.status_extended
                        == f"Inline policy {policy_name_admin} for IAM identity {group_arn} allows '*:*' administrative privileges."
                    )

                elif result.resource_id == policy_name_not_admin:
                    assert result.region == AWS_REGION
                    assert result.resource_arn == group_arn
                    assert result.resource_id == policy_name_not_admin
                    assert result.resource_tags == []
                    assert result.status == "PASS"
                    assert (
                        result.status_extended
                        == f"Inline policy {policy_name_not_admin} for IAM identity {group_arn} does not allow '*:*' administrative privileges."
                    )

    # Roles
    @mock_iam
    def test_roles_no_inline_policies(self):
        # IAM Client
        iam_client = client("iam")
        # Create IAM Role
        role_name = "test_role"
        _ = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ASSUME_ROLE_POLICY_DOCUMENT),
        )

        # Audit Info
        current_audit_info = self.set_mocked_audit_info()

        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges import (
                iam_inline_policy_no_administrative_privileges,
            )

            check = iam_inline_policy_no_administrative_privileges()
            results = check.execute()
            assert len(results) == 0

    @mock_iam
    def test_roles_admin_inline_policy(self):
        # IAM Client
        iam_client = client("iam")
        # Create IAM Role
        role_name = "test_role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ASSUME_ROLE_POLICY_DOCUMENT),
        )["Role"]["Arn"]

        # Put Role Policy
        policy_name = "test_admin_inline_policy"
        _ = iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=dumps(INLINE_POLICY_ADMIN),
        )
        # Audit Info
        current_audit_info = self.set_mocked_audit_info()

        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges import (
                iam_inline_policy_no_administrative_privileges,
            )

            check = iam_inline_policy_no_administrative_privileges()
            results = check.execute()
            assert len(results) == 1
            assert results[0].region == AWS_REGION
            assert results[0].resource_arn == role_arn
            assert results[0].resource_id == f"{role_name}/{policy_name}"
            assert results[0].resource_tags == []
            assert results[0].status == "FAIL"
            assert (
                results[0].status_extended
                == f"Inline policy {policy_name} for IAM identity {role_arn} allows '*:*' administrative privileges."
            )

    @mock_iam
    def test_roles_no_admin_inline_policy(self):
        # IAM Client
        iam_client = client("iam")
        # Create IAM Role
        role_name = "test_role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ASSUME_ROLE_POLICY_DOCUMENT),
        )["Role"]["Arn"]

        # Put Role Policy
        policy_name = "test_not_admin_inline_policy"
        _ = iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name,
            PolicyDocument=dumps(INLINE_POLICY_NOT_ADMIN),
        )
        # Audit Info
        current_audit_info = self.set_mocked_audit_info()

        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges import (
                iam_inline_policy_no_administrative_privileges,
            )

            check = iam_inline_policy_no_administrative_privileges()
            results = check.execute()
            assert len(results) == 1
            assert results[0].region == AWS_REGION
            assert results[0].resource_arn == role_arn
            assert results[0].resource_id == role_name
            assert results[0].resource_tags == []
            assert results[0].status == "PASS"
            assert (
                results[0].status_extended
                == f"Inline policy {policy_name} for IAM identity {role_arn} does not allow '*:*' administrative privileges."
            )

    @mock_iam
    def test_roles_admin_and_not_admin_inline_policies(self):
        # IAM Client
        iam_client = client("iam")
        # Create IAM Role
        role_name = "test_role"
        role_arn = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(ASSUME_ROLE_POLICY_DOCUMENT),
        )["Role"]["Arn"]

        # Put Role Policy - NOT ADMIN
        policy_name_not_admin = "test_not_admin_inline_policy"
        _ = iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name_not_admin,
            PolicyDocument=dumps(INLINE_POLICY_NOT_ADMIN),
        )
        # Put Role Policy - ADMIN
        policy_name_admin = "test_admin_inline_policy"
        _ = iam_client.put_role_policy(
            RoleName=role_name,
            PolicyName=policy_name_admin,
            PolicyDocument=dumps(INLINE_POLICY_ADMIN),
        )
        # Audit Info
        current_audit_info = self.set_mocked_audit_info()

        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges import (
                iam_inline_policy_no_administrative_privileges,
            )

            check = iam_inline_policy_no_administrative_privileges()
            results = check.execute()
            assert len(results) == 2
            for result in results:
                if result.resource_id == policy_name_admin:
                    assert result.region == AWS_REGION
                    assert result.resource_arn == role_arn
                    assert result.resource_id == policy_name_admin
                    assert result.resource_tags == []
                    assert result.status == "FAIL"
                    assert (
                        result.status_extended
                        == f"Inline policy {policy_name_admin} for IAM identity {role_arn} allows '*:*' administrative privileges."
                    )

                elif result.resource_id == policy_name_not_admin:
                    assert result.region == AWS_REGION
                    assert result.resource_arn == role_arn
                    assert result.resource_id == policy_name_not_admin
                    assert result.resource_tags == []
                    assert result.status == "PASS"
                    assert (
                        result.status_extended
                        == f"Inline policy {policy_name_not_admin} for IAM identity {role_arn} does not allow '*:*' administrative privileges."
                    )

    # Users
    @mock_iam
    def test_users_no_inline_policies(self):
        # IAM Client
        iam_client = client("iam")
        # Create IAM User
        user_name = "test_user"
        _ = iam_client.create_user(
            UserName=user_name,
        )

        # Audit Info
        current_audit_info = self.set_mocked_audit_info()

        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges import (
                iam_inline_policy_no_administrative_privileges,
            )

            check = iam_inline_policy_no_administrative_privileges()
            results = check.execute()
            assert len(results) == 0

    @mock_iam
    def test_users_admin_inline_policy(self):
        # IAM Client
        iam_client = client("iam")
        # Create IAM User
        user_name = "test_user"
        user_arn = iam_client.create_user(UserName=user_name,)[
            "User"
        ]["Arn"]

        # Put User Policy
        policy_name = "test_admin_inline_policy"
        _ = iam_client.put_user_policy(
            UserName=user_name,
            PolicyName=policy_name,
            PolicyDocument=dumps(INLINE_POLICY_ADMIN),
        )
        # Audit Info
        current_audit_info = self.set_mocked_audit_info()

        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges import (
                iam_inline_policy_no_administrative_privileges,
            )

            check = iam_inline_policy_no_administrative_privileges()
            results = check.execute()
            assert len(results) == 1
            assert results[0].region == AWS_REGION
            assert results[0].resource_arn == user_arn
            assert results[0].resource_id == user_name
            assert results[0].resource_tags == []
            assert results[0].status == "FAIL"
            assert (
                results[0].status_extended
                == f"Inline policy {policy_name} for IAM identity {user_arn} allows '*:*' administrative privileges."
            )

    @mock_iam
    def test_users_no_admin_inline_policy(self):
        # IAM Client
        iam_client = client("iam")
        # Create IAM User
        user_name = "test_user"
        user_arn = iam_client.create_user(UserName=user_name,)[
            "User"
        ]["Arn"]

        # Put User Policy
        policy_name = "test_not_admin_inline_policy"
        _ = iam_client.put_user_policy(
            UserName=user_name,
            PolicyName=policy_name,
            PolicyDocument=dumps(INLINE_POLICY_NOT_ADMIN),
        )
        # Audit Info
        current_audit_info = self.set_mocked_audit_info()

        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges import (
                iam_inline_policy_no_administrative_privileges,
            )

            check = iam_inline_policy_no_administrative_privileges()
            results = check.execute()
            assert len(results) == 1
            assert results[0].region == AWS_REGION
            assert results[0].resource_arn == user_arn
            assert results[0].resource_id == f"{user_name}/{policy_name}"
            assert results[0].resource_tags == []
            assert results[0].status == "PASS"
            assert (
                results[0].status_extended
                == f"Inline policy {policy_name} for IAM identity {user_arn} does not allow '*:*' administrative privileges."
            )

    @mock_iam
    def test_users_admin_and_not_admin_inline_policies(self):
        # IAM Client
        iam_client = client("iam")
        # Create IAM User
        user_name = "test_user"
        user_arn = iam_client.create_user(UserName=user_name,)[
            "User"
        ]["Arn"]

        # Put Group Policy - NOT ADMIN
        policy_name_not_admin = "test_not_admin_inline_policy"
        _ = iam_client.put_user_policy(
            UserName=user_name,
            PolicyName=policy_name_not_admin,
            PolicyDocument=dumps(INLINE_POLICY_NOT_ADMIN),
        )
        # Put Group Policy - ADMIN
        policy_name_admin = "test_admin_inline_policy"
        _ = iam_client.put_user_policy(
            UserName=user_name,
            PolicyName=policy_name_admin,
            PolicyDocument=dumps(INLINE_POLICY_ADMIN),
        )
        # Audit Info
        current_audit_info = self.set_mocked_audit_info()

        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges.iam_client",
            new=IAM(current_audit_info),
        ):
            from prowler.providers.aws.services.iam.iam_inline_policy_no_administrative_privileges.iam_inline_policy_no_administrative_privileges import (
                iam_inline_policy_no_administrative_privileges,
            )

            check = iam_inline_policy_no_administrative_privileges()
            results = check.execute()
            assert len(results) == 2
            for result in results:
                if result.resource_id == policy_name_admin:
                    assert result.region == AWS_REGION
                    assert result.resource_arn == user_arn
                    assert result.resource_id == policy_name_admin
                    assert result.resource_tags == []
                    assert result.status == "FAIL"
                    assert (
                        result.status_extended
                        == f"Inline policy {policy_name_admin} for IAM identity {user_arn} allows '*:*' administrative privileges."
                    )

                elif result.resource_id == policy_name_not_admin:
                    assert result.region == AWS_REGION
                    assert result.resource_arn == user_arn
                    assert result.resource_id == policy_name_not_admin
                    assert result.resource_tags == []
                    assert result.status == "PASS"
                    assert (
                        result.status_extended
                        == f"Inline policy {policy_name_not_admin} for IAM identity {user_arn} does not allow '*:*' administrative privileges."
                    )
