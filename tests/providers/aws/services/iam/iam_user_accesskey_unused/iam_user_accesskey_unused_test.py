import datetime
from unittest import mock

from boto3 import client, session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_iam_user_accesskey_unused_test:
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
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
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
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
            audit_config={"max_unused_access_keys_days": 30},
        )
        return audit_info

    @mock_iam
    def test_user_no_access_keys(self):
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused import (
                    iam_user_accesskey_unused,
                )

                service_client.credential_report[0][
                    "access_key_1_last_rotated"
                ] == "N/A"
                service_client.credential_report[0][
                    "access_key_2_last_rotated"
                ] == "N/A"

                check = iam_user_accesskey_unused()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"User {user} does not have access keys."
                )
                assert result[0].resource_id == user
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION

    @mock_iam
    def test_user_access_key_1_not_used(self):
        credentials_last_rotated = (
            datetime.datetime.now() - datetime.timedelta(days=100)
        ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused import (
                    iam_user_accesskey_unused,
                )

                service_client.credential_report[0]["access_key_1_active"] = "true"
                service_client.credential_report[0][
                    "access_key_1_last_used_date"
                ] = credentials_last_rotated

                check = iam_user_accesskey_unused()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"User {user} has not used access key 1 in the last 30 days (100 days)."
                )
                assert result[0].resource_id == user + "/AccessKey1"
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION

    @mock_iam
    def test_user_access_key_2_not_used(self):
        credentials_last_rotated = (
            datetime.datetime.now() - datetime.timedelta(days=100)
        ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused import (
                    iam_user_accesskey_unused,
                )

                service_client.credential_report[0]["access_key_2_active"] = "true"
                service_client.credential_report[0][
                    "access_key_2_last_used_date"
                ] = credentials_last_rotated

                check = iam_user_accesskey_unused()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"User {user} has not used access key 2 in the last 30 days (100 days)."
                )
                assert result[0].resource_id == user + "/AccessKey2"
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION

    @mock_iam
    def test_user_both_access_keys_not_used(self):
        credentials_last_rotated = (
            datetime.datetime.now() - datetime.timedelta(days=100)
        ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused import (
                    iam_user_accesskey_unused,
                )

                service_client.credential_report[0]["access_key_1_active"] = "true"
                service_client.credential_report[0][
                    "access_key_1_last_used_date"
                ] = credentials_last_rotated

                service_client.credential_report[0]["access_key_2_active"] = "true"
                service_client.credential_report[0][
                    "access_key_2_last_used_date"
                ] = credentials_last_rotated

                check = iam_user_accesskey_unused()
                result = check.execute()
                assert len(result) == 2
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"User {user} has not used access key 1 in the last 30 days (100 days)."
                )
                assert result[0].resource_id == user + "/AccessKey1"
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION

                assert result[1].status == "FAIL"
                assert (
                    result[1].status_extended
                    == f"User {user} has not used access key 2 in the last 30 days (100 days)."
                )
                assert result[1].resource_id == user + "/AccessKey2"
                assert result[1].resource_arn == arn
                assert result[1].region == AWS_REGION

    @mock_iam
    def test_user_both_access_keys_used(self):
        credentials_last_rotated = (
            datetime.datetime.now() - datetime.timedelta(days=10)
        ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        iam_client = client("iam")
        user = "test-user"
        arn = iam_client.create_user(UserName=user)["User"]["Arn"]

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_user_accesskey_unused.iam_user_accesskey_unused import (
                    iam_user_accesskey_unused,
                )

                service_client.credential_report[0]["access_key_1_active"] = "true"
                service_client.credential_report[0][
                    "access_key_1_last_used_date"
                ] = credentials_last_rotated

                service_client.credential_report[0]["access_key_2_active"] = "true"
                service_client.credential_report[0][
                    "access_key_2_last_used_date"
                ] = credentials_last_rotated

                check = iam_user_accesskey_unused()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"User {user} does not have unused access keys for 30 days."
                )
                assert result[0].resource_id == user
                assert result[0].resource_arn == arn
                assert result[0].region == AWS_REGION
