from json import dumps
from unittest import mock

from boto3 import client, session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.audit_info import AWS_Audit_Info
from prowler.providers.aws.services.iam.iam_service import IAM


class Test_iam_policy_no_full_access_to_kms:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=None,
            audited_account_arn=None,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region="us-east-1",
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    @mock_iam
    def test_policy_full_access_to_kms(self):
        audit_info = self.set_mocked_audit_info()
        iam_client = client("iam")
        policy_name = "policy_kms_full"
        policy_document_full_access = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "kms:*", "Resource": "*"},
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document_full_access)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_no_full_access_to_kms.iam_policy_no_full_access_to_kms.iam_client",
                new=IAM(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_no_full_access_to_kms.iam_policy_no_full_access_to_kms import (
                    iam_policy_no_full_access_to_kms,
                )

                check = iam_policy_no_full_access_to_kms()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Custom Policy {policy_name} allows 'kms:*' privileges"
                )
                assert result[0].resource_id == "policy_kms_full"
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"

    @mock_iam
    def test_policy_no_full_access_to_kms(self):
        audit_info = self.set_mocked_audit_info()
        iam_client = client("iam")
        policy_name = "policy_no_kms_full"
        policy_document_full_access = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "ec2:*", "Resource": "*"},
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document_full_access)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_no_full_access_to_kms.iam_policy_no_full_access_to_kms.iam_client",
                new=IAM(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_no_full_access_to_kms.iam_policy_no_full_access_to_kms import (
                    iam_policy_no_full_access_to_kms,
                )

                check = iam_policy_no_full_access_to_kms()
                result = check.execute()
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Custom Policy {policy_name} does not allow 'kms:*' privileges"
                )
                assert result[0].resource_id == "policy_no_kms_full"
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"

    @mock_iam
    def test_policy_mixed(self):
        audit_info = self.set_mocked_audit_info()
        iam_client = client("iam")
        policy_name = "policy_mixed"
        policy_document_full_access = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["ec2:*", "kms:*"], "Resource": "*"},
            ],
        }
        arn = iam_client.create_policy(
            PolicyName=policy_name, PolicyDocument=dumps(policy_document_full_access)
        )["Policy"]["Arn"]

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_policy_no_full_access_to_kms.iam_policy_no_full_access_to_kms.iam_client",
                new=IAM(audit_info),
            ):
                # Test Check
                from prowler.providers.aws.services.iam.iam_policy_no_full_access_to_kms.iam_policy_no_full_access_to_kms import (
                    iam_policy_no_full_access_to_kms,
                )

                check = iam_policy_no_full_access_to_kms()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Custom Policy {policy_name} allows 'kms:*' privileges"
                )
                assert result[0].resource_id == "policy_mixed"
                assert result[0].resource_arn == arn
                assert result[0].region == "us-east-1"
