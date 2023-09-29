from csv import DictReader
from re import search
from unittest import mock

from boto3 import session
from moto import mock_iam

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_iam_user_no_setup_initial_access_key_test:
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
    def test_setup_access_key_1_fail(self):
        raw_credential_report = r"""user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
test_false_access_key_1,arn:aws:iam::123456789012:test_false_access_key_1,2022-04-17T14:59:38+00:00,true,no_information,not_supported,not_supported,false,true,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A"""
        credential_lines = raw_credential_report.split("\n")
        csv_reader = DictReader(credential_lines, delimiter=",")
        credential_list = list(csv_reader)

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_no_setup_initial_access_key.iam_user_no_setup_initial_access_key.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_user_no_setup_initial_access_key.iam_user_no_setup_initial_access_key import (
                iam_user_no_setup_initial_access_key,
            )

            service_client.credential_report = credential_list

            check = iam_user_no_setup_initial_access_key()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert search("has never used access key 1", result[0].status_extended)

    @mock_iam
    def test_setup_access_key_2_fail(self):
        raw_credential_report = r"""user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
test_false_access_key_2,arn:aws:iam::123456789012:test_false_access_key_2,2022-04-17T14:59:38+00:00,true,no_information,not_supported,not_supported,false,false,N/A,N/A,N/A,N/A,true,N/A,N/A,N/A,N/A,false,N/A,false,N/A"""
        credential_lines = raw_credential_report.split("\n")
        csv_reader = DictReader(credential_lines, delimiter=",")
        credential_list = list(csv_reader)

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_no_setup_initial_access_key.iam_user_no_setup_initial_access_key.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_user_no_setup_initial_access_key.iam_user_no_setup_initial_access_key import (
                iam_user_no_setup_initial_access_key,
            )

            service_client.credential_report = credential_list

            check = iam_user_no_setup_initial_access_key()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert search("has never used access key 2", result[0].status_extended)

    @mock_iam
    def test_setup_both_access_keys_fail(self):
        raw_credential_report = r"""user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
test_false_both_access_keys,arn:aws:iam::123456789012:test_false_both_access_keys,2022-04-17T14:59:38+00:00,true,no_information,not_supported,not_supported,false,true,N/A,N/A,N/A,N/A,true,N/A,N/A,N/A,N/A,false,N/A,false,N/A"""
        credential_lines = raw_credential_report.split("\n")
        csv_reader = DictReader(credential_lines, delimiter=",")
        credential_list = list(csv_reader)

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_no_setup_initial_access_key.iam_user_no_setup_initial_access_key.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_user_no_setup_initial_access_key.iam_user_no_setup_initial_access_key import (
                iam_user_no_setup_initial_access_key,
            )

            service_client.credential_report = credential_list

            check = iam_user_no_setup_initial_access_key()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert search("has never used access key 1", result[0].status_extended)
            assert result[1].status == "FAIL"
            assert search("has never used access key 2", result[1].status_extended)

    @mock_iam
    def test_setup_access_key_pass(self):
        raw_credential_report = r"""user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
test_pass,arn:aws:iam::123456789012:test_pass,2022-02-17T14:59:38+00:00,not_supported,no_information,not_supported,not_supported,false,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A"""
        credential_lines = raw_credential_report.split("\n")
        csv_reader = DictReader(credential_lines, delimiter=",")
        credential_list = list(csv_reader)

        current_audit_info = self.set_mocked_audit_info()
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_no_setup_initial_access_key.iam_user_no_setup_initial_access_key.iam_client",
            new=IAM(current_audit_info),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_user_no_setup_initial_access_key.iam_user_no_setup_initial_access_key import (
                iam_user_no_setup_initial_access_key,
            )

            service_client.credential_report = credential_list

            check = iam_user_no_setup_initial_access_key()
            result = check.execute()
            assert result[0].status == "PASS"
            assert search(
                "does not have access keys or uses the access keys configured",
                result[0].status_extended,
            )
