from json import dumps
from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.iam.iam_service import IAM
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)


class Test_iam_policy_cloudshell_admin_not_attached:
    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_access_denied(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_policy_cloudshell_admin_not_attached.iam_policy_cloudshell_admin_not_attached.iam_client",
            new=IAM(aws_provider),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_policy_cloudshell_admin_not_attached.iam_policy_cloudshell_admin_not_attached import (
                iam_policy_cloudshell_admin_not_attached,
            )

            service_client.entities_attached_to_cloudshell_policy = None

            check = iam_policy_cloudshell_admin_not_attached()
            result = check.execute()
            assert len(result) == 0

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_nocloudshell_policy(self):
        iam = client("iam")
        role_name = "test_nocloudshell_policy"
        role_policy = {
            "Version": "2012-10-17",
        }
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(role_policy),
        )
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/SecurityAudit",
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_cloudshell_admin_not_attached.iam_policy_cloudshell_admin_not_attached.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_cloudshell_admin_not_attached.iam_policy_cloudshell_admin_not_attached import (
                    iam_policy_cloudshell_admin_not_attached,
                )

                check = iam_policy_cloudshell_admin_not_attached()
                result = check.execute()
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "AWS CloudShellFullAccess policy is not attached to any IAM entity."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_role_cloudshell_policy(self):
        iam = client("iam")
        role_name = "test_cloudshell_policy_role"
        role_policy = {
            "Version": "2012-10-17",
        }
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(role_policy),
        )
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/AWSCloudShellFullAccess",
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_cloudshell_admin_not_attached.iam_policy_cloudshell_admin_not_attached.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_cloudshell_admin_not_attached.iam_policy_cloudshell_admin_not_attached import (
                    iam_policy_cloudshell_admin_not_attached,
                )

                check = iam_policy_cloudshell_admin_not_attached()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"AWS CloudShellFullAccess policy attached to IAM Roles: {role_name}."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_user_cloudshell_policy(self):
        iam = client("iam")
        user_name = "test_cloudshell_policy_user"
        iam.create_user(
            UserName=user_name,
        )
        iam.attach_user_policy(
            UserName=user_name,
            PolicyArn="arn:aws:iam::aws:policy/AWSCloudShellFullAccess",
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_cloudshell_admin_not_attached.iam_policy_cloudshell_admin_not_attached.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_cloudshell_admin_not_attached.iam_policy_cloudshell_admin_not_attached import (
                    iam_policy_cloudshell_admin_not_attached,
                )

                check = iam_policy_cloudshell_admin_not_attached()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"AWS CloudShellFullAccess policy attached to IAM Users: {user_name}."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_group_cloudshell_policy(self):
        iam = client("iam")
        group_name = "test_cloudshell_policy_group"
        iam.create_group(
            GroupName=group_name,
        )
        iam.attach_group_policy(
            GroupName=group_name,
            PolicyArn="arn:aws:iam::aws:policy/AWSCloudShellFullAccess",
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_cloudshell_admin_not_attached.iam_policy_cloudshell_admin_not_attached.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_cloudshell_admin_not_attached.iam_policy_cloudshell_admin_not_attached import (
                    iam_policy_cloudshell_admin_not_attached,
                )

                check = iam_policy_cloudshell_admin_not_attached()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"AWS CloudShellFullAccess policy attached to IAM Groups: {group_name}."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws(config={"iam": {"load_aws_managed_policies": True}})
    def test_user_role_group_cloudshell_policy(self):
        iam = client("iam")
        user_name = "test_cloudshell_policy_user"
        iam.create_user(
            UserName=user_name,
        )
        iam.attach_user_policy(
            UserName=user_name,
            PolicyArn="arn:aws:iam::aws:policy/AWSCloudShellFullAccess",
        )
        group_name = "test_cloudshell_policy_group"
        iam.create_group(
            GroupName=group_name,
        )
        iam.attach_group_policy(
            GroupName=group_name,
            PolicyArn="arn:aws:iam::aws:policy/AWSCloudShellFullAccess",
        )
        role_name = "test_cloudshell_policy_role"
        role_policy = {
            "Version": "2012-10-17",
        }
        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(role_policy),
        )
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/AWSCloudShellFullAccess",
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_cloudshell_admin_not_attached.iam_policy_cloudshell_admin_not_attached.iam_client",
                new=IAM(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_cloudshell_admin_not_attached.iam_policy_cloudshell_admin_not_attached import (
                    iam_policy_cloudshell_admin_not_attached,
                )

                check = iam_policy_cloudshell_admin_not_attached()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"AWS CloudShellFullAccess policy attached to IAM Users: {user_name}, Groups: {group_name}, Roles: {role_name}."
                )
                assert result[0].resource_id == AWS_ACCOUNT_NUMBER
                assert (
                    result[0].resource_arn
                    == "arn:aws:iam::aws:policy/AWSCloudShellFullAccess"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1
