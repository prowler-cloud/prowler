from csv import DictReader
from re import search
from unittest import mock

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_iam_user_no_setup_initial_access_key_test:
    def test_setup_access_key_1_fail(self):
        raw_credential_report = r"""user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
test_false_access_key_1,arn:aws:iam::123456789012:test_false_access_key_1,2022-04-17T14:59:38+00:00,true,no_information,not_supported,not_supported,false,true,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A"""
        credential_lines = raw_credential_report.split("\n")
        csv_reader = DictReader(credential_lines, delimiter=",")
        credential_list = list(csv_reader)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_no_setup_initial_access_key.iam_user_no_setup_initial_access_key.iam_client",
            new=IAM(aws_provider),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_user_no_setup_initial_access_key.iam_user_no_setup_initial_access_key import (
                iam_user_no_setup_initial_access_key,
            )

            service_client.credential_report = credential_list
            service_client.users = [
                mock.MagicMock(
                    name="test_false_access_key_1",
                    arn="arn:aws:iam::123456789012:test_false_access_key_1",
                    tags=[{"Key": "Name", "Value": "test_false_access_key_1"}],
                )
            ]

            check = iam_user_no_setup_initial_access_key()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert search("has never used access key 1", result[0].status_extended)
            assert result[0].resource_id == "test_false_access_key_1"
            assert (
                result[0].resource_arn
                == "arn:aws:iam::123456789012:test_false_access_key_1"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [
                {"Key": "Name", "Value": "test_false_access_key_1"}
            ]

    def test_setup_access_key_2_fail(self):
        raw_credential_report = r"""user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
test_false_access_key_2,arn:aws:iam::123456789012:test_false_access_key_2,2022-04-17T14:59:38+00:00,true,no_information,not_supported,not_supported,false,false,N/A,N/A,N/A,N/A,true,N/A,N/A,N/A,N/A,false,N/A,false,N/A"""
        credential_lines = raw_credential_report.split("\n")
        csv_reader = DictReader(credential_lines, delimiter=",")
        credential_list = list(csv_reader)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_no_setup_initial_access_key.iam_user_no_setup_initial_access_key.iam_client",
            new=IAM(aws_provider),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_user_no_setup_initial_access_key.iam_user_no_setup_initial_access_key import (
                iam_user_no_setup_initial_access_key,
            )

            service_client.credential_report = credential_list
            service_client.users = [
                mock.MagicMock(
                    name="test_false_access_key_2",
                    arn="arn:aws:iam::123456789012:test_false_access_key_2",
                    tags=[{"Key": "Name", "Value": "test_false_access_key_2"}],
                )
            ]

            check = iam_user_no_setup_initial_access_key()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert search("has never used access key 2", result[0].status_extended)
            assert result[0].resource_id == "test_false_access_key_2"
            assert (
                result[0].resource_arn
                == "arn:aws:iam::123456789012:test_false_access_key_2"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [
                {"Key": "Name", "Value": "test_false_access_key_2"}
            ]

    def test_setup_both_access_keys_fail(self):
        raw_credential_report = r"""user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
test_false_both_access_keys,arn:aws:iam::123456789012:test_false_both_access_keys,2022-04-17T14:59:38+00:00,true,no_information,not_supported,not_supported,false,true,N/A,N/A,N/A,N/A,true,N/A,N/A,N/A,N/A,false,N/A,false,N/A"""
        credential_lines = raw_credential_report.split("\n")
        csv_reader = DictReader(credential_lines, delimiter=",")
        credential_list = list(csv_reader)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_no_setup_initial_access_key.iam_user_no_setup_initial_access_key.iam_client",
            new=IAM(aws_provider),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_user_no_setup_initial_access_key.iam_user_no_setup_initial_access_key import (
                iam_user_no_setup_initial_access_key,
            )

            service_client.credential_report = credential_list
            service_client.users = [
                mock.MagicMock(
                    name="test_false_both_access_keys",
                    arn="arn:aws:iam::123456789012:test_false_both_access_keys",
                    tags=[{"Key": "Name", "Value": "test_false_both_access_keys"}],
                )
            ]

            check = iam_user_no_setup_initial_access_key()
            result = check.execute()
            assert result[0].status == "FAIL"
            assert search("has never used access key 1", result[0].status_extended)
            assert result[0].resource_id == "test_false_both_access_keys"
            assert (
                result[0].resource_arn
                == "arn:aws:iam::123456789012:test_false_both_access_keys"
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [
                {"Key": "Name", "Value": "test_false_both_access_keys"}
            ]
            assert result[1].status == "FAIL"
            assert search("has never used access key 2", result[1].status_extended)
            assert result[1].resource_id == "test_false_both_access_keys"
            assert (
                result[1].resource_arn
                == "arn:aws:iam::123456789012:test_false_both_access_keys"
            )
            assert result[1].region == AWS_REGION_US_EAST_1
            assert result[1].resource_tags == [
                {"Key": "Name", "Value": "test_false_both_access_keys"}
            ]

    def test_setup_access_key_pass(self):
        raw_credential_report = r"""user,arn,user_creation_time,password_enabled,password_last_used,password_last_changed,password_next_rotation,mfa_active,access_key_1_active,access_key_1_last_rotated,access_key_1_last_used_date,access_key_1_last_used_region,access_key_1_last_used_service,access_key_2_active,access_key_2_last_rotated,access_key_2_last_used_date,access_key_2_last_used_region,access_key_2_last_used_service,cert_1_active,cert_1_last_rotated,cert_2_active,cert_2_last_rotated
test_pass,arn:aws:iam::123456789012:test_pass,2022-02-17T14:59:38+00:00,not_supported,no_information,not_supported,not_supported,false,false,N/A,N/A,N/A,N/A,false,N/A,N/A,N/A,N/A,false,N/A,false,N/A"""
        credential_lines = raw_credential_report.split("\n")
        csv_reader = DictReader(credential_lines, delimiter=",")
        credential_list = list(csv_reader)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        from prowler.providers.aws.services.iam.iam_service import IAM

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.iam.iam_user_no_setup_initial_access_key.iam_user_no_setup_initial_access_key.iam_client",
            new=IAM(aws_provider),
        ) as service_client:
            from prowler.providers.aws.services.iam.iam_user_no_setup_initial_access_key.iam_user_no_setup_initial_access_key import (
                iam_user_no_setup_initial_access_key,
            )

            service_client.credential_report = credential_list
            service_client.users = [
                mock.MagicMock(
                    name="test_pass",
                    arn="arn:aws:iam::123456789012:test_pass",
                    tags=[{"Key": "Name", "Value": "test_pass"}],
                )
            ]

            check = iam_user_no_setup_initial_access_key()
            result = check.execute()
            assert result[0].status == "PASS"
            assert search(
                "does not have access keys or uses the access keys configured",
                result[0].status_extended,
            )
            assert result[0].resource_id == "test_pass"
            assert result[0].resource_arn == "arn:aws:iam::123456789012:test_pass"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == [{"Key": "Name", "Value": "test_pass"}]
