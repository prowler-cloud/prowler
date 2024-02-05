import datetime
from csv import DictReader
from re import search
from unittest import mock

from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_iam_avoid_root_usage:
    @mock_aws
    def test_root_not_used(self):
        raw_credential_report = r"""user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
<root_account>,arn:aws:iam::123456789012:<root_account>,2022-04-17T14:59:38+00:00,true,no_information,not_supported,not_supported,false,true,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A"""
        credential_lines = raw_credential_report.split("\n")
        csv_reader = DictReader(credential_lines, delimiter=",")
        credential_list = list(csv_reader)

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_avoid_root_usage.iam_avoid_root_usage.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_avoid_root_usage.iam_avoid_root_usage import (
                    iam_avoid_root_usage,
                )

                service_client.credential_report = credential_list
                check = iam_avoid_root_usage()
                result = check.execute()
                assert result[0].status == "PASS"
                assert search(
                    "Root user in the account wasn't accessed in the last",
                    result[0].status_extended,
                )
                assert result[0].resource_id == "<root_account>"
                assert (
                    result[0].resource_arn == "arn:aws:iam::123456789012:<root_account>"
                )

    @mock_aws
    def test_root_password_recently_used(self):
        password_last_used = (datetime.datetime.now()).strftime(
            "%Y-%m-%dT%H:%M:%S+00:00"
        )
        raw_credential_report = rf"""user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
<root_account>,arn:aws:iam::123456789012:<root_account>,2022-04-17T14:59:38+00:00,true,{password_last_used},not_supported,not_supported,false,true,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A"""
        credential_lines = raw_credential_report.split("\n")
        csv_reader = DictReader(credential_lines, delimiter=",")
        credential_list = list(csv_reader)

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_avoid_root_usage.iam_avoid_root_usage.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_avoid_root_usage.iam_avoid_root_usage import (
                    iam_avoid_root_usage,
                )

                service_client.credential_report = credential_list
                check = iam_avoid_root_usage()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert search(
                    "Root user in the account was last accessed",
                    result[0].status_extended,
                )
                assert result[0].resource_id == "<root_account>"
                assert (
                    result[0].resource_arn == "arn:aws:iam::123456789012:<root_account>"
                )

    @mock_aws
    def test_root_access_key_1_recently_used(self):
        access_key_1_last_used = (datetime.datetime.now()).strftime(
            "%Y-%m-%dT%H:%M:%S+00:00"
        )
        raw_credential_report = rf"""user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
<root_account>,arn:aws:iam::123456789012:<root_account>,2022-04-17T14:59:38+00:00,true,no_information,not_supported,not_supported,false,true,N/A,{access_key_1_last_used},N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A"""
        credential_lines = raw_credential_report.split("\n")
        csv_reader = DictReader(credential_lines, delimiter=",")
        credential_list = list(csv_reader)

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_avoid_root_usage.iam_avoid_root_usage.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_avoid_root_usage.iam_avoid_root_usage import (
                    iam_avoid_root_usage,
                )

                service_client.credential_report = credential_list
                check = iam_avoid_root_usage()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert search(
                    "Root user in the account was last accessed",
                    result[0].status_extended,
                )
                assert result[0].resource_id == "<root_account>"
                assert (
                    result[0].resource_arn == "arn:aws:iam::123456789012:<root_account>"
                )

    @mock_aws
    def test_root_access_key_2_recently_used(self):
        access_key_2_last_used = (datetime.datetime.now()).strftime(
            "%Y-%m-%dT%H:%M:%S+00:00"
        )
        raw_credential_report = rf"""user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
<root_account>,arn:aws:iam::123456789012:<root_account>,2022-04-17T14:59:38+00:00,true,no_information,not_supported,not_supported,false,true,N/A,N/A,N/A,N/A,false,N/A,{access_key_2_last_used},N/A,N/A,false,N/A,false,N/A"""
        credential_lines = raw_credential_report.split("\n")
        csv_reader = DictReader(credential_lines, delimiter=",")
        credential_list = list(csv_reader)

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_avoid_root_usage.iam_avoid_root_usage.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_avoid_root_usage.iam_avoid_root_usage import (
                    iam_avoid_root_usage,
                )

                service_client.credential_report = credential_list
                check = iam_avoid_root_usage()
                result = check.execute()
                assert result[0].status == "FAIL"
                assert search(
                    "Root user in the account was last accessed",
                    result[0].status_extended,
                )
                assert result[0].resource_id == "<root_account>"
                assert (
                    result[0].resource_arn == "arn:aws:iam::123456789012:<root_account>"
                )

    @mock_aws
    def test_root_password_used(self):
        password_last_used = (
            datetime.datetime.now() - datetime.timedelta(days=100)
        ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        raw_credential_report = rf"""user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
<root_account>,arn:aws:iam::123456789012:<root_account>,2022-04-17T14:59:38+00:00,true,{password_last_used},not_supported,not_supported,false,true,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A"""
        credential_lines = raw_credential_report.split("\n")
        csv_reader = DictReader(credential_lines, delimiter=",")
        credential_list = list(csv_reader)

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_avoid_root_usage.iam_avoid_root_usage.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_avoid_root_usage.iam_avoid_root_usage import (
                    iam_avoid_root_usage,
                )

                service_client.credential_report = credential_list
                check = iam_avoid_root_usage()
                result = check.execute()
                assert result[0].status == "PASS"
                assert search(
                    "Root user in the account wasn't accessed in the last 1 days",
                    result[0].status_extended,
                )
                assert result[0].resource_id == "<root_account>"
                assert (
                    result[0].resource_arn == "arn:aws:iam::123456789012:<root_account>"
                )

    @mock_aws
    def test_root_access_key_1_used(self):
        access_key_1_last_used = (
            datetime.datetime.now() - datetime.timedelta(days=100)
        ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        raw_credential_report = rf"""user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
<root_account>,arn:aws:iam::123456789012:<root_account>,2022-04-17T14:59:38+00:00,true,no_information,not_supported,not_supported,false,true,N/A,{access_key_1_last_used},N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A"""
        credential_lines = raw_credential_report.split("\n")
        csv_reader = DictReader(credential_lines, delimiter=",")
        credential_list = list(csv_reader)

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_avoid_root_usage.iam_avoid_root_usage.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_avoid_root_usage.iam_avoid_root_usage import (
                    iam_avoid_root_usage,
                )

                service_client.credential_report = credential_list
                check = iam_avoid_root_usage()
                result = check.execute()
                assert result[0].status == "PASS"
                assert search(
                    "Root user in the account wasn't accessed in the last 1 days",
                    result[0].status_extended,
                )
                assert result[0].resource_id == "<root_account>"
                assert (
                    result[0].resource_arn == "arn:aws:iam::123456789012:<root_account>"
                )

    @mock_aws
    def test_root_access_key_2_used(self):
        access_key_2_last_used = (
            datetime.datetime.now() - datetime.timedelta(days=100)
        ).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        raw_credential_report = rf"""user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
<root_account>,arn:aws:iam::123456789012:<root_account>,2022-04-17T14:59:38+00:00,true,no_information,not_supported,not_supported,false,true,N/A,N/A,N/A,N/A,false,N/A,{access_key_2_last_used},N/A,N/A,false,N/A,false,N/A"""
        credential_lines = raw_credential_report.split("\n")
        csv_reader = DictReader(credential_lines, delimiter=",")
        credential_list = list(csv_reader)

        from prowler.providers.aws.services.iam.iam_service import IAM

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.iam.iam_avoid_root_usage.iam_avoid_root_usage.iam_client",
                new=IAM(audit_info),
            ) as service_client:
                from prowler.providers.aws.services.iam.iam_avoid_root_usage.iam_avoid_root_usage import (
                    iam_avoid_root_usage,
                )

                service_client.credential_report = credential_list
                check = iam_avoid_root_usage()
                result = check.execute()
                assert result[0].status == "PASS"
                assert search(
                    "Root user in the account wasn't accessed in the last 1 days",
                    result[0].status_extended,
                )
                assert result[0].resource_id == "<root_account>"
                assert (
                    result[0].resource_arn == "arn:aws:iam::123456789012:<root_account>"
                )
