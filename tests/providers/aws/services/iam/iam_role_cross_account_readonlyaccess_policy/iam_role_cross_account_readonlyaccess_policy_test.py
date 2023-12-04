from json import dumps
from unittest import mock

from boto3 import client, session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.iam.iam_service import Role
from prowler.providers.common.models import Audit_Metadata
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_REGION = "us-east-1"
AWS_ACCOUNT_ID = "123456789012"


class Test_iam_role_cross_account_readonlyaccess_policy:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_ID,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:root",
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
    def test_no_roles(self):
        from prowler.providers.aws.services.iam.iam_service import IAM

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy import (
                iam_role_cross_account_readonlyaccess_policy,
            )

            check = iam_role_cross_account_readonlyaccess_policy()
            result = check.execute()
            assert len(result) == 0

    @mock_iam
    def test_role_without_readonlyaccess_policy(self):
        iam = client("iam")
        role_name = "test"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "test",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"},
                "Action": "sts:AssumeRole",
            },
        }
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(assume_role_policy_document),
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy import (
                iam_role_cross_account_readonlyaccess_policy,
            )

            check = iam_role_cross_account_readonlyaccess_policy()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "IAM Role test does not have ReadOnlyAccess policy."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]
            assert result[0].resource_tags == []

    @mock_iam
    def test_internal_role_with_readonlyaccess_policy(self):
        iam = client("iam")
        role_name = "test"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "test",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"},
                "Action": "sts:AssumeRole",
            },
        }
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(assume_role_policy_document),
        )
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess",
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy import (
                iam_role_cross_account_readonlyaccess_policy,
            )

            check = iam_role_cross_account_readonlyaccess_policy()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "IAM Role test has read-only access but is not cross account."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]
            assert result[0].resource_tags == []

    @mock_iam
    def test_cross_account_role_with_readonlyaccess_policy(self):
        iam = client("iam")
        role_name = "test"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "test",
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::012345678910:root"},
                "Action": "sts:AssumeRole",
            },
        }
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(assume_role_policy_document),
        )
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess",
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy import (
                iam_role_cross_account_readonlyaccess_policy,
            )

            check = iam_role_cross_account_readonlyaccess_policy()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "IAM Role test gives cross account read-only access."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]
            assert result[0].resource_tags == []

    @mock_iam
    def test_asterisk_cross_account_role_with_readonlyaccess_policy(self):
        iam = client("iam")
        role_name = "test"
        assume_role_policy_document = {
            "Version": "2012-10-17",
            "Statement": {
                "Sid": "test",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "sts:AssumeRole",
            },
        }
        response = iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=dumps(assume_role_policy_document),
        )
        iam.attach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/ReadOnlyAccess",
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy.iam_client",
            new=IAM(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy import (
                iam_role_cross_account_readonlyaccess_policy,
            )

            check = iam_role_cross_account_readonlyaccess_policy()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "IAM Role test gives cross account read-only access."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == response["Role"]["Arn"]
            assert result[0].resource_tags == []

    @mock_iam
    def test_only_aws_service_linked_roles(self):
        iam_client = mock.MagicMock
        iam_client.roles = []
        iam_client.roles.append(
            Role(
                name="AWSServiceRoleForAmazonGuardDuty",
                arn="arn:aws:iam::106908755756:role/aws-service-role/guardduty.amazonaws.com/AWSServiceRoleForAmazonGuardDuty",
                assume_role_policy={
                    "Version": "2008-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                },
                is_service_role=True,
            )
        )

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy.iam_client",
            new=iam_client,
        ):
            # Test Check
            from prowler.providers.aws.services.iam.iam_role_cross_account_readonlyaccess_policy.iam_role_cross_account_readonlyaccess_policy import (
                iam_role_cross_account_readonlyaccess_policy,
            )

            check = iam_role_cross_account_readonlyaccess_policy()
            result = check.execute()
            assert len(result) == 0
