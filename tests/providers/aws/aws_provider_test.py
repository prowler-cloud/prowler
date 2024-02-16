from re import search

import boto3
from mock import patch
from moto import mock_aws

from prowler.providers.aws.aws_provider import (
    AWS_Provider,
    assume_role,
    generate_regional_clients,
    get_available_aws_service_regions,
    get_default_region,
    get_global_region,
)
from prowler.providers.aws.lib.audit_info.models import AWS_Assume_Role
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_CHINA_PARTITION,
    AWS_GOV_CLOUD_PARTITION,
    AWS_ISO_PARTITION,
    AWS_REGION_CHINA_NORHT_1,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_GOV_CLOUD_US_EAST_1,
    AWS_REGION_ISO_GLOBAL,
    AWS_REGION_US_EAST_1,
    AWS_REGION_US_EAST_2,
    set_mocked_aws_audit_info,
)


class Test_AWS_Provider:
    @mock_aws
    def test_aws_provider_user_without_mfa(self):
        # sessionName = "ProwlerAssessmentSession"
        # Boto 3 client to create our user
        iam_client = boto3.client("iam", region_name=AWS_REGION_US_EAST_1)
        # IAM user
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]
        # New Boto3 session with the previously create user
        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=AWS_REGION_US_EAST_1,
        )

        audit_info = set_mocked_aws_audit_info(
            audited_regions=[AWS_REGION_EU_WEST_1],
            assumed_role_info=AWS_Assume_Role(
                role_arn=None,
                session_duration=None,
                external_id=None,
                mfa_enabled=False,
                role_session_name="ProwlerAssessmentSession",
            ),
            original_session=session,
        )

        # Call assume_role
        with patch(
            "prowler.providers.aws.aws_provider.input_role_mfa_token_and_code",
            return_value=(
                f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:mfa/test-role-mfa",
                "111111",
            ),
        ):
            aws_provider = AWS_Provider(audit_info)
            assert aws_provider.aws_session.region_name == "us-east-1"
            assert aws_provider.role_info == AWS_Assume_Role(
                role_arn=None,
                session_duration=None,
                external_id=None,
                mfa_enabled=False,
                role_session_name="ProwlerAssessmentSession",
            )

    @mock_aws
    def test_aws_provider_user_with_mfa(self):
        # Boto 3 client to create our user
        iam_client = boto3.client("iam", region_name=AWS_REGION_US_EAST_1)
        # IAM user
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]
        # New Boto3 session with the previously create user
        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=AWS_REGION_US_EAST_1,
        )

        audit_info = set_mocked_aws_audit_info(
            audited_regions=[AWS_REGION_EU_WEST_1],
            assumed_role_info=AWS_Assume_Role(
                role_arn=None,
                session_duration=None,
                external_id=None,
                mfa_enabled=False,
                role_session_name="ProwlerAssessmentSession",
            ),
            original_session=session,
            profile_region=AWS_REGION_US_EAST_1,
        )

        # Call assume_role
        with patch(
            "prowler.providers.aws.aws_provider.input_role_mfa_token_and_code",
            return_value=(
                f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:mfa/test-role-mfa",
                "111111",
            ),
        ):
            aws_provider = AWS_Provider(audit_info)
            assert aws_provider.aws_session.region_name == "us-east-1"
            assert aws_provider.role_info == AWS_Assume_Role(
                role_arn=None,
                session_duration=None,
                external_id=None,
                mfa_enabled=False,
                role_session_name="ProwlerAssessmentSession",
            )

    @mock_aws
    def test_aws_provider_assume_role_with_mfa(self):
        # Variables
        role_name = "test-role"
        role_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/{role_name}"
        session_duration_seconds = 900
        sessionName = "ProwlerAssessmentSession"

        # Boto 3 client to create our user
        iam_client = boto3.client("iam", region_name=AWS_REGION_US_EAST_1)
        # IAM user
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]
        # New Boto3 session with the previously create user
        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=AWS_REGION_US_EAST_1,
        )

        audit_info = set_mocked_aws_audit_info(
            audited_regions=[AWS_REGION_EU_WEST_1],
            assumed_role_info=AWS_Assume_Role(
                role_arn=role_arn,
                session_duration=session_duration_seconds,
                external_id=None,
                mfa_enabled=True,
                role_session_name="ProwlerAssessmentSession",
            ),
            original_session=session,
            profile_region=AWS_REGION_US_EAST_1,
        )

        aws_provider = AWS_Provider(audit_info)
        # Patch MFA
        with patch(
            "prowler.providers.aws.aws_provider.input_role_mfa_token_and_code",
            return_value=(
                f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:mfa/test-role-mfa",
                "111111",
            ),
        ):
            assume_role_response = assume_role(
                aws_provider.aws_session, aws_provider.role_info
            )
            # Recover credentials for the assume role operation
            credentials = assume_role_response["Credentials"]
            # Test the response
            # SessionToken
            assert len(credentials["SessionToken"]) == 356
            assert search(r"^FQoGZXIvYXdzE.*$", credentials["SessionToken"])
            # AccessKeyId
            assert len(credentials["AccessKeyId"]) == 20
            assert search(r"^ASIA.*$", credentials["AccessKeyId"])
            # SecretAccessKey
            assert len(credentials["SecretAccessKey"]) == 40
            # Assumed Role
            assert (
                assume_role_response["AssumedRoleUser"]["Arn"]
                == f"arn:aws:sts::{AWS_ACCOUNT_NUMBER}:assumed-role/{role_name}/{sessionName}"
            )

            # AssumedRoleUser
            assert search(
                r"^AROA.*$", assume_role_response["AssumedRoleUser"]["AssumedRoleId"]
            )
            assert search(
                rf"^.*:{sessionName}$",
                assume_role_response["AssumedRoleUser"]["AssumedRoleId"],
            )
            assert len(
                assume_role_response["AssumedRoleUser"]["AssumedRoleId"]
            ) == 21 + 1 + len(sessionName)

    @mock_aws
    def test_aws_provider_assume_role_without_mfa(self):
        # Variables
        role_name = "test-role"
        role_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/{role_name}"
        session_duration_seconds = 900
        sessionName = "ProwlerAssessmentSession"

        # Boto 3 client to create our user
        iam_client = boto3.client("iam", region_name=AWS_REGION_US_EAST_1)
        # IAM user
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]
        # New Boto3 session with the previously create user
        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=AWS_REGION_US_EAST_1,
        )

        audit_info = set_mocked_aws_audit_info(
            audited_regions=[AWS_REGION_EU_WEST_1],
            assumed_role_info=AWS_Assume_Role(
                role_arn=role_arn,
                session_duration=session_duration_seconds,
                external_id=None,
                mfa_enabled=False,
                role_session_name="ProwlerAssessmentSession",
            ),
            original_session=session,
            profile_region=AWS_REGION_US_EAST_1,
        )

        aws_provider = AWS_Provider(audit_info)
        assume_role_response = assume_role(
            aws_provider.aws_session, aws_provider.role_info
        )
        # Recover credentials for the assume role operation
        credentials = assume_role_response["Credentials"]
        # Test the response
        # SessionToken
        assert len(credentials["SessionToken"]) == 356
        assert search(r"^FQoGZXIvYXdzE.*$", credentials["SessionToken"])
        # AccessKeyId
        assert len(credentials["AccessKeyId"]) == 20
        assert search(r"^ASIA.*$", credentials["AccessKeyId"])
        # SecretAccessKey
        assert len(credentials["SecretAccessKey"]) == 40
        # Assumed Role
        assert (
            assume_role_response["AssumedRoleUser"]["Arn"]
            == f"arn:aws:sts::{AWS_ACCOUNT_NUMBER}:assumed-role/{role_name}/{sessionName}"
        )

        # AssumedRoleUser
        assert search(
            r"^AROA.*$", assume_role_response["AssumedRoleUser"]["AssumedRoleId"]
        )
        assert search(
            rf"^.*:{sessionName}$",
            assume_role_response["AssumedRoleUser"]["AssumedRoleId"],
        )
        assert len(
            assume_role_response["AssumedRoleUser"]["AssumedRoleId"]
        ) == 21 + 1 + len(sessionName)

    @mock_aws
    def test_assume_role_with_sts_endpoint_region(self):
        # Variables
        role_name = "test-role"
        role_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/{role_name}"
        session_duration_seconds = 900
        AWS_REGION_US_EAST_1 = AWS_REGION_EU_WEST_1
        sts_endpoint_region = AWS_REGION_US_EAST_1
        sessionName = "ProwlerAssessmentSession"

        # Boto 3 client to create our user
        iam_client = boto3.client("iam", region_name=AWS_REGION_US_EAST_1)
        # IAM user
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]
        # New Boto3 session with the previously create user
        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=AWS_REGION_US_EAST_1,
        )

        audit_info = set_mocked_aws_audit_info(
            audited_regions=[AWS_REGION_EU_WEST_1],
            assumed_role_info=AWS_Assume_Role(
                role_arn=role_arn,
                session_duration=session_duration_seconds,
                external_id=None,
                mfa_enabled=False,
                role_session_name="ProwlerAssessmentSession",
            ),
            original_session=session,
            profile_region=AWS_REGION_US_EAST_1,
        )

        aws_provider = AWS_Provider(audit_info)
        assume_role_response = assume_role(
            aws_provider.aws_session, aws_provider.role_info, sts_endpoint_region
        )
        # Recover credentials for the assume role operation
        credentials = assume_role_response["Credentials"]
        # Test the response
        # SessionToken
        assert len(credentials["SessionToken"]) == 356
        assert search(r"^FQoGZXIvYXdzE.*$", credentials["SessionToken"])
        # AccessKeyId
        assert len(credentials["AccessKeyId"]) == 20
        assert search(r"^ASIA.*$", credentials["AccessKeyId"])
        # SecretAccessKey
        assert len(credentials["SecretAccessKey"]) == 40
        # Assumed Role
        assert (
            assume_role_response["AssumedRoleUser"]["Arn"]
            == f"arn:aws:sts::{AWS_ACCOUNT_NUMBER}:assumed-role/{role_name}/{sessionName}"
        )

        # AssumedRoleUser
        assert search(
            r"^AROA.*$", assume_role_response["AssumedRoleUser"]["AssumedRoleId"]
        )
        assert search(
            rf"^.*:{sessionName}$",
            assume_role_response["AssumedRoleUser"]["AssumedRoleId"],
        )
        assert len(
            assume_role_response["AssumedRoleUser"]["AssumedRoleId"]
        ) == 21 + 1 + len(sessionName)

    def test_generate_regional_clients(self):
        audited_regions = [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        audit_info = set_mocked_aws_audit_info(
            audited_regions=audited_regions,
            audit_session=boto3.session.Session(
                region_name=AWS_REGION_US_EAST_1,
            ),
            enabled_regions=audited_regions,
        )

        generate_regional_clients_response = generate_regional_clients(
            "ec2", audit_info
        )

        assert set(generate_regional_clients_response.keys()) == set(audited_regions)

    def test_generate_regional_clients_cn_partition(self):
        audited_regions = ["cn-northwest-1", "cn-north-1"]
        audit_info = set_mocked_aws_audit_info(
            audited_regions=audited_regions,
            audit_session=boto3.session.Session(
                region_name=AWS_REGION_US_EAST_1,
            ),
            enabled_regions=audited_regions,
        )
        generate_regional_clients_response = generate_regional_clients(
            "shield", audit_info
        )

        # Shield does not exist in China
        assert generate_regional_clients_response == {}

    def test_get_default_region(self):
        audit_info = set_mocked_aws_audit_info(
            profile_region=AWS_REGION_EU_WEST_1,
            audited_regions=[AWS_REGION_EU_WEST_1],
        )
        assert get_default_region("ec2", audit_info) == AWS_REGION_EU_WEST_1

    def test_get_default_region_profile_region_not_audited(self):
        audit_info = set_mocked_aws_audit_info(
            profile_region=AWS_REGION_US_EAST_2,
            audited_regions=[AWS_REGION_EU_WEST_1],
        )
        assert get_default_region("ec2", audit_info) == AWS_REGION_EU_WEST_1

    def test_get_default_region_non_profile_region(self):
        audit_info = set_mocked_aws_audit_info(
            audited_regions=[AWS_REGION_EU_WEST_1],
        )
        assert get_default_region("ec2", audit_info) == AWS_REGION_EU_WEST_1

    def test_get_default_region_non_profile_or_audited_region(self):
        audit_info = set_mocked_aws_audit_info()
        assert get_default_region("ec2", audit_info) == AWS_REGION_US_EAST_1

    def test_aws_gov_get_global_region(self):
        audit_info = set_mocked_aws_audit_info(
            audited_partition=AWS_GOV_CLOUD_PARTITION
        )
        assert get_global_region(audit_info) == AWS_REGION_GOV_CLOUD_US_EAST_1

    def test_aws_cn_get_global_region(self):
        audit_info = set_mocked_aws_audit_info(audited_partition=AWS_CHINA_PARTITION)
        assert get_global_region(audit_info) == AWS_REGION_CHINA_NORHT_1

    def test_aws_iso_get_global_region(self):
        audit_info = set_mocked_aws_audit_info(audited_partition=AWS_ISO_PARTITION)
        assert get_global_region(audit_info) == AWS_REGION_ISO_GLOBAL

    def test_get_available_aws_service_regions_with_us_east_1_audited(self):
        audit_info = set_mocked_aws_audit_info(audited_regions=[AWS_REGION_US_EAST_1])

        with patch(
            "prowler.providers.aws.aws_provider.parse_json_file",
            return_value={
                "services": {
                    "ec2": {
                        "regions": {
                            "aws": [
                                "af-south-1",
                                "ca-central-1",
                                "eu-central-1",
                                "eu-central-2",
                                "eu-north-1",
                                "eu-south-1",
                                "eu-south-2",
                                AWS_REGION_EU_WEST_1,
                                "eu-west-2",
                                "eu-west-3",
                                "me-central-1",
                                "me-south-1",
                                "sa-east-1",
                                "us-east-1",
                                "us-east-2",
                                "us-west-1",
                                "us-west-2",
                            ],
                        }
                    }
                }
            },
        ):
            assert get_available_aws_service_regions("ec2", audit_info) == {
                AWS_REGION_US_EAST_1
            }

    def test_get_available_aws_service_regions_with_all_regions_audited(self):
        audit_info = set_mocked_aws_audit_info()

        with patch(
            "prowler.providers.aws.aws_provider.parse_json_file",
            return_value={
                "services": {
                    "ec2": {
                        "regions": {
                            "aws": [
                                "af-south-1",
                                "ca-central-1",
                                "eu-central-1",
                                "eu-central-2",
                                "eu-north-1",
                                "eu-south-1",
                                "eu-south-2",
                                AWS_REGION_EU_WEST_1,
                                "eu-west-2",
                                "eu-west-3",
                                "me-central-1",
                                "me-south-1",
                                "sa-east-1",
                                "us-east-1",
                                "us-east-2",
                                "us-west-1",
                                "us-west-2",
                            ],
                        }
                    }
                }
            },
        ):
            assert len(get_available_aws_service_regions("ec2", audit_info)) == 17
