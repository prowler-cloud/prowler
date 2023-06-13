import boto3
import sure  # noqa
from mock import patch
from moto import mock_iam, mock_sts

from prowler.providers.aws.aws_provider import (
    AWS_Provider,
    assume_role,
    generate_regional_clients,
)
from prowler.providers.aws.lib.audit_info.models import AWS_Assume_Role, AWS_Audit_Info

ACCOUNT_ID = 123456789012


class Test_AWS_Provider:
    @mock_iam
    @mock_sts
    def test_assume_role_without_mfa(self):
        # Variables
        role_name = "test-role"
        role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/{role_name}"
        session_duration_seconds = 900
        audited_regions = "eu-west-1"
        sessionName = "ProwlerAsessmentSession"
        # Boto 3 client to create our user
        iam_client = boto3.client("iam", region_name="us-east-1")
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
            region_name="us-east-1",
        )

        # Fulfil the input session object for Prowler
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=session,
            audit_session=None,
            audited_account=None,
            audited_partition=None,
            audited_identity_arn=None,
            audited_user_id=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=AWS_Assume_Role(
                role_arn=role_arn,
                session_duration=session_duration_seconds,
                external_id=None,
                mfa_enabled=False,
            ),
            audited_regions=audited_regions,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
        )

        # Call assume_role
        aws_provider = AWS_Provider(audit_info)
        assume_role_response = assume_role(
            aws_provider.aws_session, aws_provider.role_info
        )
        # Recover credentials for the assume role operation
        credentials = assume_role_response["Credentials"]
        # Test the response
        # SessionToken
        credentials["SessionToken"].should.have.length_of(356)
        credentials["SessionToken"].startswith("FQoGZXIvYXdzE")
        # AccessKeyId
        credentials["AccessKeyId"].should.have.length_of(20)
        credentials["AccessKeyId"].startswith("ASIA")
        # SecretAccessKey
        credentials["SecretAccessKey"].should.have.length_of(40)
        # Assumed Role
        assume_role_response["AssumedRoleUser"]["Arn"].should.equal(
            f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/{role_name}/{sessionName}"
        )
        # AssumedRoleUser
        assert assume_role_response["AssumedRoleUser"]["AssumedRoleId"].startswith(
            "AROA"
        )
        assert assume_role_response["AssumedRoleUser"]["AssumedRoleId"].endswith(
            ":" + sessionName
        )
        assume_role_response["AssumedRoleUser"]["AssumedRoleId"].should.have.length_of(
            21 + 1 + len(sessionName)
        )

    @mock_iam
    @mock_sts
    def test_assume_role_with_mfa(self):
        # Variables
        role_name = "test-role"
        role_arn = f"arn:aws:iam::{ACCOUNT_ID}:role/{role_name}"
        session_duration_seconds = 900
        audited_regions = "eu-west-1"
        sessionName = "ProwlerAsessmentSession"
        # Boto 3 client to create our user
        iam_client = boto3.client("iam", region_name="us-east-1")
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
            region_name="us-east-1",
        )

        # Fulfil the input session object for Prowler
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=session,
            audit_session=None,
            audited_account=None,
            audited_partition=None,
            audited_identity_arn=None,
            audited_user_id=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=AWS_Assume_Role(
                role_arn=role_arn,
                session_duration=session_duration_seconds,
                external_id=None,
                mfa_enabled=True,
            ),
            audited_regions=audited_regions,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
        )

        # Call assume_role
        aws_provider = AWS_Provider(audit_info)
        # Patch MFA
        with patch(
            "prowler.providers.aws.aws_provider.input_role_mfa_token_and_code",
            return_value=(f"arn:aws:iam::{ACCOUNT_ID}:mfa/test-role-mfa", "111111"),
        ):
            assume_role_response = assume_role(
                aws_provider.aws_session, aws_provider.role_info
            )
            # Recover credentials for the assume role operation
            credentials = assume_role_response["Credentials"]
            # Test the response
            # SessionToken
            credentials["SessionToken"].should.have.length_of(356)
            credentials["SessionToken"].startswith("FQoGZXIvYXdzE")
            # AccessKeyId
            credentials["AccessKeyId"].should.have.length_of(20)
            credentials["AccessKeyId"].startswith("ASIA")
            # SecretAccessKey
            credentials["SecretAccessKey"].should.have.length_of(40)
            # Assumed Role
            assume_role_response["AssumedRoleUser"]["Arn"].should.equal(
                f"arn:aws:sts::{ACCOUNT_ID}:assumed-role/{role_name}/{sessionName}"
            )
            # AssumedRoleUser
            assert assume_role_response["AssumedRoleUser"]["AssumedRoleId"].startswith(
                "AROA"
            )
            assert assume_role_response["AssumedRoleUser"]["AssumedRoleId"].endswith(
                ":" + sessionName
            )
            assume_role_response["AssumedRoleUser"][
                "AssumedRoleId"
            ].should.have.length_of(21 + 1 + len(sessionName))

    def test_generate_regional_clients(self):
        # New Boto3 session with the previously create user
        session = boto3.session.Session(
            region_name="us-east-1",
        )
        audited_regions = ["eu-west-1", "us-east-1"]
        # Fulfil the input session object for Prowler
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session,
            audited_account=None,
            audited_account_arn=None,
            audited_partition="aws",
            audited_identity_arn=None,
            audited_user_id=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=audited_regions,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
        )
        generate_regional_clients_response = generate_regional_clients(
            "ec2", audit_info
        )

        assert set(generate_regional_clients_response.keys()) == set(audited_regions)

    def test_generate_regional_clients_global_service(self):
        # New Boto3 session with the previously create user
        session = boto3.session.Session(
            region_name="us-east-1",
        )
        audited_regions = ["eu-west-1", "us-east-1"]
        profile_region = "us-east-1"
        # Fulfil the input session object for Prowler
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session,
            audited_account=None,
            audited_account_arn=None,
            audited_partition="aws",
            audited_identity_arn=None,
            audited_user_id=None,
            profile=None,
            profile_region=profile_region,
            credentials=None,
            assumed_role_info=None,
            audited_regions=audited_regions,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
        )
        generate_regional_clients_response = generate_regional_clients(
            "route53", audit_info, global_service=True
        )

        assert list(generate_regional_clients_response.keys()) == [profile_region]

    def test_generate_regional_clients_cn_partition(self):
        # New Boto3 session with the previously create user
        session = boto3.session.Session(
            region_name="us-east-1",
        )
        audited_regions = ["cn-northwest-1", "cn-north-1"]
        # Fulfil the input session object for Prowler
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session,
            audited_account=None,
            audited_account_arn=None,
            audited_partition="aws-cn",
            audited_identity_arn=None,
            audited_user_id=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=audited_regions,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
        )
        generate_regional_clients_response = generate_regional_clients(
            "shield", audit_info, global_service=True
        )

        # Shield does not exist in China
        assert generate_regional_clients_response == {}
