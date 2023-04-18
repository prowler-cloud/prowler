from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_iam_no_root_access_key_test:
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
    def test_iam_root_no_access_keys(self):
        iam_client = client("iam")
        user = "test"
        iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_no_root_access_key.iam_no_root_access_key.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_no_root_access_key.iam_no_root_access_key import (
                    iam_no_root_access_key,
                )

                service_client.credential_report[0]["user"] = "<root_account>"
                service_client.credential_report[0][
                    "arn"
                ] = "arn:aws:iam::123456789012:user/<root_account>"
                service_client.credential_report[0]["access_key_1_active"] = "false"
                service_client.credential_report[0]["access_key_2_active"] = "false"
                check = iam_no_root_access_key()
                result = check.execute()

                # raise Exception
                assert result[0].status == "PASS"
                assert search(
                    "User <root_account> does not have access keys.",
                    result[0].status_extended,
                )
                assert result[0].resource_id == "<root_account>"
                assert (
                    result[0].resource_arn
                    == "arn:aws:iam::123456789012:user/<root_account>"
                )

    @mock_iam
    def test_iam_root_access_key_1(self):
        iam_client = client("iam")
        user = "test"
        iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_no_root_access_key.iam_no_root_access_key.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_no_root_access_key.iam_no_root_access_key import (
                    iam_no_root_access_key,
                )

                service_client.credential_report[0]["user"] = "<root_account>"
                service_client.credential_report[0][
                    "arn"
                ] = "arn:aws:iam::123456789012:user/<root_account>"
                service_client.credential_report[0]["access_key_1_active"] = "true"
                service_client.credential_report[0]["access_key_2_active"] = "false"
                check = iam_no_root_access_key()
                result = check.execute()

                # raise Exception
                assert result[0].status == "FAIL"
                assert search(
                    "User <root_account> has one active access key.",
                    result[0].status_extended,
                )
                assert result[0].resource_id == "<root_account>"
                assert (
                    result[0].resource_arn
                    == "arn:aws:iam::123456789012:user/<root_account>"
                )

    @mock_iam
    def test_iam_root_access_key_2(self):
        iam_client = client("iam")
        user = "test"
        iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_no_root_access_key.iam_no_root_access_key.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_no_root_access_key.iam_no_root_access_key import (
                    iam_no_root_access_key,
                )

                service_client.credential_report[0]["user"] = "<root_account>"
                service_client.credential_report[0][
                    "arn"
                ] = "arn:aws:iam::123456789012:user/<root_account>"
                service_client.credential_report[0]["access_key_1_active"] = "false"
                service_client.credential_report[0]["access_key_2_active"] = "true"
                check = iam_no_root_access_key()
                result = check.execute()

                # raise Exception
                assert result[0].status == "FAIL"
                assert search(
                    "User <root_account> has one active access key.",
                    result[0].status_extended,
                )
                assert result[0].resource_id == "<root_account>"
                assert (
                    result[0].resource_arn
                    == "arn:aws:iam::123456789012:user/<root_account>"
                )

    @mock_iam
    def test_iam_root_both_access_keys(self):
        iam_client = client("iam")
        user = "test"
        iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_no_root_access_key.iam_no_root_access_key.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_no_root_access_key.iam_no_root_access_key import (
                    iam_no_root_access_key,
                )

                service_client.credential_report[0]["user"] = "<root_account>"
                service_client.credential_report[0][
                    "arn"
                ] = "arn:aws:iam::123456789012:user/<root_account>"
                service_client.credential_report[0]["access_key_1_active"] = "true"
                service_client.credential_report[0]["access_key_2_active"] = "true"
                check = iam_no_root_access_key()
                result = check.execute()

                # raise Exception
                assert result[0].status == "FAIL"
                assert search(
                    "User <root_account> has two active access key.",
                    result[0].status_extended,
                )
                assert result[0].resource_id == "<root_account>"
                assert (
                    result[0].resource_arn
                    == "arn:aws:iam::123456789012:user/<root_account>"
                )
