import json
import os
import re
import tempfile
from datetime import datetime, timedelta
from json import dumps
from re import search
from unittest import mock

import botocore
import botocore.exceptions
import pytest
from boto3 import client, resource, session
from mock import patch
from moto import mock_aws
from pytest import raises
from tzlocal import get_localzone

from prowler.providers.aws.aws_provider import AwsProvider, get_aws_region_for_sts
from prowler.providers.aws.config import (
    AWS_STS_GLOBAL_ENDPOINT_REGION,
    BOTO3_USER_AGENT_EXTRA,
    ROLE_SESSION_NAME,
)
from prowler.providers.aws.exceptions.exceptions import (
    AWSArgumentTypeValidationError,
    AWSIAMRoleARNInvalidResourceTypeError,
    AWSInvalidPartitionError,
    AWSInvalidProviderIdError,
    AWSNoCredentialsError,
)
from prowler.providers.aws.lib.arn.models import ARN
from prowler.providers.aws.lib.mutelist.mutelist import AWSMutelist
from prowler.providers.aws.models import (
    AWSAssumeRoleInfo,
    AWSCallerIdentity,
    AWSCredentials,
    AWSMFAInfo,
    AWSOrganizationsInfo,
)
from prowler.providers.common.models import Connection
from prowler.providers.common.provider import Provider
from tests.providers.aws.utils import (
    AWS_ACCOUNT_ARN,
    AWS_ACCOUNT_NUMBER,
    AWS_CHINA_PARTITION,
    AWS_COMMERCIAL_PARTITION,
    AWS_GOV_CLOUD_ACCOUNT_ARN,
    AWS_GOV_CLOUD_PARTITION,
    AWS_ISO_PARTITION,
    AWS_REGION_CN_NORTH_1,
    AWS_REGION_CN_NORTHWEST_1,
    AWS_REGION_EU_CENTRAL_1,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_GOV_CLOUD_US_EAST_1,
    AWS_REGION_ISO_GLOBAL,
    AWS_REGION_US_EAST_1,
    AWS_REGION_US_EAST_2,
    EXAMPLE_AMI_ID,
    create_role,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call


def mock_get_caller_identity_china(self, operation_name, kwarg):
    if operation_name == "GetCallerIdentity":
        return {
            "UserId": "XXXXXXXXXXXXXXXXXXXXX",
            "Account": AWS_ACCOUNT_NUMBER,
            "Arn": f"arn:{AWS_CHINA_PARTITION}:iam::{AWS_ACCOUNT_NUMBER}:user/test-user",
        }

    return make_api_call(self, operation_name, kwarg)


def mock_get_caller_identity_gov_cloud(self, operation_name, kwarg):
    if operation_name == "GetCallerIdentity":
        return {
            "UserId": "XXXXXXXXXXXXXXXXXXXXX",
            "Account": AWS_ACCOUNT_NUMBER,
            "Arn": f"arn:{AWS_GOV_CLOUD_PARTITION}:iam::{AWS_ACCOUNT_NUMBER}:user/test-user",
        }

    return make_api_call(self, operation_name, kwarg)


def mock_recover_checks_from_aws_provider(*_):
    return [
        (
            "accessanalyzer_enabled_without_findings",
            "/root_dir/fake_path/accessanalyzer/accessanalyzer_enabled_without_findings",
        ),
        (
            "awslambda_function_url_cors_policy",
            "/root_dir/fake_path/awslambda/awslambda_function_url_cors_policy",
        ),
        (
            "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
            "/root_dir/fake_path/ec2/ec2_securitygroup_allow_ingress_from_internet_to_any_port",
        ),
    ]


def mock_recover_checks_from_aws_provider_lambda_service(*_):
    return [
        (
            "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
            "/root_dir/fake_path/awslambda/awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
        ),
        (
            "awslambda_function_url_cors_policy",
            "/root_dir/fake_path/awslambda/awslambda_function_url_cors_policy",
        ),
        (
            "awslambda_function_no_secrets_in_code",
            "/root_dir/fake_path/awslambda/awslambda_function_no_secrets_in_code",
        ),
    ]


def mock_recover_checks_from_aws_provider_elb_service(*_):
    return [
        (
            "elb_insecure_ssl_ciphers",
            "/root_dir/fake_path/elb/elb_insecure_ssl_ciphers",
        ),
        (
            "elb_internet_facing",
            "/root_dir/fake_path/elb/elb_internet_facing",
        ),
        (
            "elb_logging_enabled",
            "/root_dir/fake_path/elb/elb_logging_enabled",
        ),
    ]


def mock_recover_checks_from_aws_provider_efs_service(*_):
    return [
        (
            "efs_encryption_at_rest_enabled",
            "/root_dir/fake_path/efs/efs_encryption_at_rest_enabled",
        ),
        (
            "efs_have_backup_enabled",
            "/root_dir/fake_path/efs/efs_have_backup_enabled",
        ),
        (
            "efs_not_publicly_accessible",
            "/root_dir/fake_path/efs/efs_not_publicly_accessible",
        ),
    ]


def mock_recover_checks_from_aws_provider_iam_service(*_):
    return [
        (
            "iam_customer_attached_policy_no_administrative_privileges",
            "/root_dir/fake_path/iam/iam_customer_attached_policy_no_administrative_privileges",
        ),
        (
            "iam_check_saml_providers_sts",
            "/root_dir/fake_path/iam/iam_check_saml_providers_sts",
        ),
        (
            "iam_password_policy_minimum_length_14",
            "/root_dir/fake_path/iam/iam_password_policy_minimum_length_14",
        ),
    ]


def mock_recover_checks_from_aws_provider_s3_service(*_):
    return [
        (
            "s3_account_level_public_access_blocks",
            "/root_dir/fake_path/s3/s3_account_level_public_access_blocks",
        ),
        (
            "s3_bucket_acl_prohibited",
            "/root_dir/fake_path/s3/s3_bucket_acl_prohibited",
        ),
        (
            "s3_bucket_policy_public_write_access",
            "/root_dir/fake_path/s3/s3_bucket_policy_public_write_access",
        ),
    ]


def mock_recover_checks_from_aws_provider_cloudwatch_service(*_):
    return [
        (
            "cloudwatch_changes_to_network_acls_alarm_configured",
            "/root_dir/fake_path/cloudwatch/cloudwatch_changes_to_network_acls_alarm_configured",
        ),
        (
            "cloudwatch_changes_to_network_gateways_alarm_configured",
            "/root_dir/cloudwatch/cloudwatch_changes_to_network_gateways_alarm_configured",
        ),
        (
            "cloudwatch_changes_to_network_route_tables_alarm_configured",
            "/root_dir/fake_path/cloudwatch/cloudwatch_changes_to_network_route_tables_alarm_configured",
        ),
    ]


def mock_recover_checks_from_aws_provider_ec2_service(*_):
    return [
        (
            "ec2_securitygroup_allow_ingress_from_internet_to_any_port",
            "/root_dir/fake_path/ec2/ec2_securitygroup_allow_ingress_from_internet_to_any_port",
        ),
        (
            "ec2_networkacl_allow_ingress_any_port",
            "/root_dir/fake_path/ec2/ec2_networkacl_allow_ingress_any_port",
        ),
        (
            "ec2_ami_public",
            "/root_dir/fake_path/ec2/ec2_ami_public",
        ),
    ]


def mock_recover_checks_from_aws_provider_rds_service(*_):
    return [
        (
            "rds_instance_backup_enabled",
            "/root_dir/fake_path/rds/rds_instance_backup_enabled",
        ),
        (
            "rds_instance_deletion_protection",
            "/root_dir/fake_path/rds/rds_instance_deletion_protection",
        ),
        (
            "rds_snapshots_public_access",
            "/root_dir/fake_path/rds/rds_snapshots_public_access",
        ),
    ]


def mock_recover_checks_from_aws_provider_cognito_service(*_):
    return []


class TestAWSProvider:
    @mock_aws
    def test_aws_provider_default(self):
        mfa = False
        scan_unused_services = True
        aws_provider = AwsProvider(
            mfa=mfa,
            scan_unused_services=scan_unused_services,
        )

        assert aws_provider.type == "aws"
        assert aws_provider.scan_unused_services is True
        assert aws_provider.audit_config
        assert aws_provider.session.current_session.region_name == AWS_REGION_US_EAST_1

    @mock_aws
    def test_aws_provider_with_static_credentials(self):
        # Create a mock IAM user
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        username = "test-user"
        iam_user = iam_client.create_user(UserName=username)["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]

        credentials = {
            "aws_access_key_id": access_key["AccessKeyId"],
            "aws_secret_access_key": access_key["SecretAccessKey"],
        }

        aws_provider = AwsProvider(**credentials)
        assert aws_provider.type == "aws"
        # Session
        assert aws_provider.session.current_session.region_name == AWS_REGION_US_EAST_1
        assert aws_provider.session.current_session.profile_name == "default"
        assert aws_provider.session.original_session.region_name == AWS_REGION_US_EAST_1
        assert aws_provider.session.original_session.profile_name == "default"

        # Identity
        assert aws_provider.identity.account == AWS_ACCOUNT_NUMBER
        assert aws_provider.identity.account_arn == AWS_ACCOUNT_ARN
        assert (
            aws_provider.identity.identity_arn
            == f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:user/{username}"
        )
        assert aws_provider.identity.partition == AWS_COMMERCIAL_PARTITION
        assert aws_provider.identity.profile is None
        assert aws_provider.identity.profile_region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_aws_provider_with_session_credentials(self):
        sts_client = client("sts", region_name=AWS_REGION_EU_WEST_1)
        session_token = sts_client.get_session_token()

        session_credentials = {
            "aws_access_key_id": session_token["Credentials"]["AccessKeyId"],
            "aws_secret_access_key": session_token["Credentials"]["SecretAccessKey"],
            "aws_session_token": session_token["Credentials"]["SessionToken"],
        }

        aws_provider = AwsProvider(**session_credentials)
        assert aws_provider.type == "aws"
        # Session
        assert aws_provider.session.current_session.region_name == AWS_REGION_US_EAST_1
        assert aws_provider.session.current_session.profile_name == "default"
        assert aws_provider.session.original_session.region_name == AWS_REGION_US_EAST_1
        assert aws_provider.session.original_session.profile_name == "default"

        # Identity
        assert aws_provider.identity.account == AWS_ACCOUNT_NUMBER
        assert aws_provider.identity.account_arn == AWS_ACCOUNT_ARN
        # moto is the default user created by moto
        assert (
            aws_provider.identity.identity_arn
            == f"arn:aws:sts::{AWS_ACCOUNT_NUMBER}:user/moto"
        )
        assert aws_provider.identity.partition == AWS_COMMERCIAL_PARTITION
        assert aws_provider.identity.profile is None
        assert aws_provider.identity.profile_region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_aws_provider_organizations_delegated_administrator(self):
        organizations_client = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        organization = organizations_client.create_organization()["Organization"]
        organizations_client.tag_resource(
            ResourceId=AWS_ACCOUNT_NUMBER,
            Tags=[
                {"Key": "tagged", "Value": "true"},
            ],
        )

        aws_provider = AwsProvider()

        assert isinstance(aws_provider.organizations_metadata, AWSOrganizationsInfo)
        assert aws_provider.organizations_metadata.account_email == "master@example.com"
        assert aws_provider.organizations_metadata.account_name == "master"
        assert aws_provider.organizations_metadata.account_tags == {"tagged": "true"}
        assert (
            aws_provider.organizations_metadata.organization_account_arn
            == f"arn:aws:organizations::{AWS_ACCOUNT_NUMBER}:account/{organization['Id']}/{AWS_ACCOUNT_NUMBER}"
        )
        assert aws_provider.organizations_metadata.organization_id == organization["Id"]
        assert (
            aws_provider.organizations_metadata.organization_arn == organization["Arn"]
        )

    @mock_aws
    def test_aws_provider_organizations_none_organizations_metadata(self):

        aws_provider = AwsProvider()

        assert isinstance(aws_provider.organizations_metadata, AWSOrganizationsInfo)
        assert aws_provider.organizations_metadata.account_email == ""
        assert aws_provider.organizations_metadata.account_name == ""
        assert aws_provider.organizations_metadata.account_tags == []
        assert aws_provider.organizations_metadata.organization_account_arn == ""
        assert aws_provider.organizations_metadata.organization_id == ""
        assert aws_provider.organizations_metadata.organization_arn == ""

    @mock_aws
    def test_aws_provider_organizations_with_role(self):
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        policy_name = "describe_organizations_policy"
        policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "organizations:DescribeAccount",
                        "organizations:ListTagsForResource",
                    ],
                    "Resource": "*",
                },
            ],
        }

        policy = iam_client.create_policy(
            PolicyName=policy_name,
            PolicyDocument=dumps(policy_document),
        )["Policy"]

        assume_policy_document = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        role_name = "organizations_role"
        organizations_role = iam_client.create_role(
            RoleName=role_name, AssumeRolePolicyDocument=dumps(assume_policy_document)
        )["Role"]
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn=policy["Arn"],
        )
        organizations_client = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        organization = organizations_client.create_organization()["Organization"]
        organizations_client.tag_resource(
            ResourceId=AWS_ACCOUNT_NUMBER,
            Tags=[
                {"Key": "tagged", "Value": "true"},
            ],
        )

        organizations_role = organizations_role["Arn"]
        session_duration = 900
        aws_provider = AwsProvider(
            organizations_role_arn=organizations_role,
            session_duration=session_duration,
        )

        assert isinstance(aws_provider.organizations_metadata, AWSOrganizationsInfo)
        assert aws_provider.organizations_metadata.account_email == "master@example.com"
        assert aws_provider.organizations_metadata.account_name == "master"
        assert aws_provider.organizations_metadata.account_tags == {"tagged": "true"}
        assert (
            aws_provider.organizations_metadata.organization_account_arn
            == f"arn:aws:organizations::{AWS_ACCOUNT_NUMBER}:account/{organization['Id']}/{AWS_ACCOUNT_NUMBER}"
        )
        assert aws_provider.organizations_metadata.organization_id == organization["Id"]
        assert (
            aws_provider.organizations_metadata.organization_arn == organization["Arn"]
        )

    @mock_aws
    def test_aws_provider_session_with_mfa(self):
        mfa = True

        with patch(
            "prowler.providers.aws.aws_provider.AwsProvider.input_role_mfa_token_and_code",
            return_value=AWSMFAInfo(
                arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:mfa/test-role-mfa",
                totp="111111",
            ),
        ):

            aws_provider = AwsProvider(mfa=mfa)

            assert aws_provider.type == "aws"
            assert aws_provider.scan_unused_services is False
            assert aws_provider.audit_config != {}
            assert (
                aws_provider.session.current_session.region_name == AWS_REGION_US_EAST_1
            )
            assert (
                aws_provider.session.current_session.region_name == AWS_REGION_US_EAST_1
            )

    @mock_aws
    def test_aws_provider_assume_role_with_mfa(self):
        # Variables
        mfa = True
        role_name = "test-role"
        role_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/{role_name}"
        session_duration = 900
        role_session_name = "ProwlerAssessmentSession"
        external_id = "test-external-id"

        with patch(
            "prowler.providers.aws.aws_provider.AwsProvider.input_role_mfa_token_and_code",
            return_value=AWSMFAInfo(
                arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:mfa/test-role-mfa",
                totp="111111",
            ),
        ):
            aws_provider = AwsProvider(
                mfa=mfa,
                role_arn=role_arn,
                session_duration=session_duration,
                role_session_name=role_session_name,
                external_id=external_id,
            )
            assert (
                aws_provider.session.current_session.region_name == AWS_REGION_US_EAST_1
            )
            assert aws_provider.identity.account == AWS_ACCOUNT_NUMBER
            assert aws_provider.identity.account_arn == AWS_ACCOUNT_ARN
            assert aws_provider.identity.partition == AWS_COMMERCIAL_PARTITION
            assert isinstance(
                aws_provider._assumed_role_configuration.info, AWSAssumeRoleInfo
            )
            assert aws_provider._assumed_role_configuration.info == AWSAssumeRoleInfo(
                role_arn=ARN(arn=role_arn),
                session_duration=session_duration,
                external_id=external_id,
                mfa_enabled=True,  # <- MFA configuration
                role_session_name=role_session_name,
                sts_region=AWS_REGION_US_EAST_1,
            )

            credentials = aws_provider._assumed_role_configuration.credentials
            assert isinstance(credentials, AWSCredentials)

            assert credentials.aws_access_key_id
            assert len(credentials.aws_access_key_id) == 20
            assert search(r"^ASIA.*$", credentials.aws_access_key_id)

            assert credentials.aws_session_token
            assert len(credentials.aws_session_token) == 356
            assert search(r"^FQoGZXIvYXdzE.*$", credentials.aws_session_token)

            assert credentials.aws_secret_access_key
            assert len(credentials.aws_secret_access_key) == 40

            assert credentials.expiration
            # assert credentials.expiration == datetime.now(tzinfo=tzutc())

    @mock_aws
    def test_aws_provider_assume_role_without_mfa(self):
        # Variables
        mfa = False
        role_name = "test-role"
        role_arn = (
            f"arn:{AWS_COMMERCIAL_PARTITION}:iam::{AWS_ACCOUNT_NUMBER}:role/{role_name}"
        )
        session_duration = 900
        role_session_name = "ProwlerAssessmentSession"

        aws_provider = AwsProvider(
            mfa=mfa,
            role_arn=role_arn,
            session_duration=session_duration,
            role_session_name=role_session_name,
        )
        assert aws_provider.session.current_session.region_name == AWS_REGION_US_EAST_1
        assert aws_provider.identity.account == AWS_ACCOUNT_NUMBER
        assert aws_provider.identity.account_arn == AWS_ACCOUNT_ARN
        assert aws_provider.identity.partition == AWS_COMMERCIAL_PARTITION
        assert isinstance(
            aws_provider._assumed_role_configuration.info, AWSAssumeRoleInfo
        )
        assert aws_provider._assumed_role_configuration.info == AWSAssumeRoleInfo(
            role_arn=ARN(arn=role_arn),
            session_duration=session_duration,
            external_id=None,
            mfa_enabled=False,  # <- MFA configuration
            role_session_name=role_session_name,
            sts_region=AWS_REGION_US_EAST_1,
        )

        credentials = aws_provider._assumed_role_configuration.credentials
        assert isinstance(credentials, AWSCredentials)

        assert credentials.aws_access_key_id
        assert len(credentials.aws_access_key_id) == 20
        assert search(r"^ASIA.*$", credentials.aws_access_key_id)

        assert credentials.aws_session_token
        assert len(credentials.aws_session_token) == 356
        assert search(r"^FQoGZXIvYXdzE.*$", credentials.aws_session_token)

        assert credentials.aws_secret_access_key
        assert len(credentials.aws_secret_access_key) == 40

        assert credentials.expiration
        # assert credentials.expiration == datetime.now(tzinfo=tzutc())

    @mock_aws
    def test_aws_provider_assume_role_without_mfa_gov_cloud(self, monkeypatch):
        # Set AWS_DEFAULT_REGION = 'us-gov-east-1' since is set by default to 'us-east-1
        monkeypatch.setenv("AWS_DEFAULT_REGION", AWS_REGION_GOV_CLOUD_US_EAST_1)

        # Variables
        mfa = False
        role_name = "test-role"
        role_arn = (
            f"arn:{AWS_GOV_CLOUD_PARTITION}:iam::{AWS_ACCOUNT_NUMBER}:role/{role_name}"
        )
        session_duration = 900
        role_session_name = "ProwlerAssessmentSession"

        aws_provider = AwsProvider(
            mfa=mfa,
            role_arn=role_arn,
            session_duration=session_duration,
            role_session_name=role_session_name,
        )
        assert (
            aws_provider.session.current_session.region_name
            == AWS_REGION_GOV_CLOUD_US_EAST_1
        )
        assert aws_provider.identity.account == AWS_ACCOUNT_NUMBER
        assert aws_provider.identity.account_arn == AWS_GOV_CLOUD_ACCOUNT_ARN
        assert aws_provider.identity.partition == AWS_GOV_CLOUD_PARTITION
        assert isinstance(
            aws_provider._assumed_role_configuration.info, AWSAssumeRoleInfo
        )
        assert aws_provider._assumed_role_configuration.info == AWSAssumeRoleInfo(
            role_arn=ARN(arn=role_arn),
            session_duration=session_duration,
            external_id=None,
            mfa_enabled=False,  # <- MFA configuration
            role_session_name=role_session_name,
            sts_region=AWS_REGION_GOV_CLOUD_US_EAST_1,
        )

        credentials = aws_provider._assumed_role_configuration.credentials
        assert isinstance(credentials, AWSCredentials)

        assert credentials.aws_access_key_id
        assert len(credentials.aws_access_key_id) == 20
        assert search(r"^ASIA.*$", credentials.aws_access_key_id)

        assert credentials.aws_session_token
        assert len(credentials.aws_session_token) == 356
        assert search(r"^FQoGZXIvYXdzE.*$", credentials.aws_session_token)

        assert credentials.aws_secret_access_key
        assert len(credentials.aws_secret_access_key) == 40

        assert credentials.expiration
        # assert credentials.expiration == datetime.now(tzinfo=tzutc())

    @mock_aws
    def test_aws_provider_config(self):
        config = """
aws:
    test_key: value"""

        config_file_input = tempfile.NamedTemporaryFile(delete=False)
        config_file_input.write(bytes(config, encoding="raw_unicode_escape"))
        config_file_input.close()
        config_file_input = config_file_input.name
        aws_provider = AwsProvider(
            config_path=config_file_input,
        )

        os.remove(config_file_input)

        assert aws_provider.audit_config == {"test_key": "value"}

    @mock_aws
    def test_aws_provider_mutelist(self):
        mutelist = {
            "Mutelist": {
                "Accounts": {
                    AWS_ACCOUNT_NUMBER: {
                        "Checks": {
                            "test-check": {
                                "Regions": [],
                                "Resources": [],
                                "Tags": [],
                                "Exceptions": {
                                    "Accounts": [],
                                    "Regions": [],
                                    "Resources": [],
                                    "Tags": [],
                                },
                            }
                        }
                    }
                }
            }
        }

        mutelist_file = tempfile.NamedTemporaryFile(delete=False)
        with open(mutelist_file.name, "w") as mutelist_file:
            mutelist_file.write(json.dumps(mutelist, indent=4))

        aws_provider = AwsProvider(mutelist_path=mutelist_file.name)

        os.remove(mutelist_file.name)

        assert isinstance(aws_provider.mutelist, AWSMutelist)
        assert aws_provider.mutelist.mutelist == mutelist["Mutelist"]
        assert aws_provider.mutelist.mutelist_file_path == mutelist_file.name

    @mock_aws
    def test_aws_provider_mutelist_none(self):

        with patch(
            "prowler.providers.aws.aws_provider.get_default_mute_file_path",
            return_value=None,
        ):
            aws_provider = AwsProvider(mutelist_path=None)

        assert isinstance(aws_provider.mutelist, AWSMutelist)
        assert aws_provider.mutelist.mutelist == {}
        assert aws_provider.mutelist.mutelist_file_path is None

    @mock_aws
    def test_aws_provider_mutelist_s3(self):
        # Create mutelist temp file
        mutelist = {
            "Mutelist": {
                "Accounts": {
                    AWS_ACCOUNT_NUMBER: {
                        "Checks": {
                            "test-check": {
                                "Regions": [],
                                "Resources": [],
                                "Tags": [],
                                "Exceptions": {
                                    "Accounts": [],
                                    "Regions": [],
                                    "Resources": [],
                                    "Tags": [],
                                },
                            }
                        }
                    }
                }
            }
        }

        mutelist_file = tempfile.NamedTemporaryFile(delete=False)
        with open(mutelist_file.name, "w") as mutelist_file:
            mutelist_file.write(json.dumps(mutelist, indent=4))

        # Create bucket and upload mutelist yaml
        s3_resource = resource("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "test-mutelist"
        mutelist_file_name = "mutelist.yaml"
        mutelist_bucket_object_uri = f"s3://{bucket_name}/{mutelist_file_name}"
        s3_resource.create_bucket(Bucket=bucket_name)
        s3_resource.Object(bucket_name, "mutelist.yaml").put(
            Body=open(
                mutelist_file.name,
                "rb",
            )
        )

        aws_provider = AwsProvider(mutelist_path=mutelist_bucket_object_uri)

        os.remove(mutelist_file.name)

        assert isinstance(aws_provider.mutelist, AWSMutelist)
        assert aws_provider.mutelist.mutelist == mutelist["Mutelist"]
        assert aws_provider.mutelist.mutelist_file_path == mutelist_bucket_object_uri

    @mock_aws
    def test_aws_provider_mutelist_lambda(self):
        # Create mutelist temp file
        mutelist = {
            "Mutelist": {
                "Accounts": {
                    AWS_ACCOUNT_NUMBER: {
                        "Checks": {
                            "test-check": {
                                "Regions": [],
                                "Resources": [],
                                "Tags": [],
                                "Exceptions": {
                                    "Accounts": [],
                                    "Regions": [],
                                    "Resources": [],
                                    "Tags": [],
                                },
                            }
                        }
                    }
                }
            }
        }
        lambda_mutelist_path = f"arn:aws:lambda:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:function:lambda-mutelist"
        aws_provider = AwsProvider()

        with patch(
            "prowler.providers.aws.lib.mutelist.mutelist.AWSMutelist.get_mutelist_file_from_lambda",
            return_value=mutelist["Mutelist"],
        ):
            aws_provider = AwsProvider(mutelist_path=lambda_mutelist_path)

        assert isinstance(aws_provider.mutelist, AWSMutelist)
        assert aws_provider.mutelist.mutelist == mutelist["Mutelist"]
        assert aws_provider.mutelist.mutelist_file_path == lambda_mutelist_path

    @mock_aws
    def test_aws_provider_mutelist_dynamodb(self):
        # Create mutelist temp file
        mutelist = {
            "Mutelist": {
                "Accounts": {
                    AWS_ACCOUNT_NUMBER: {
                        "Checks": {
                            "test-check": {
                                "Regions": [],
                                "Resources": [],
                                "Tags": [],
                                "Exceptions": {
                                    "Accounts": [],
                                    "Regions": [],
                                    "Resources": [],
                                    "Tags": [],
                                },
                            }
                        }
                    }
                }
            }
        }
        dynamodb_mutelist_path = f"arn:aws:dynamodb:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:table/mutelist-dynamo"
        aws_provider = AwsProvider()

        with patch(
            "prowler.providers.aws.lib.mutelist.mutelist.AWSMutelist.get_mutelist_file_from_dynamodb",
            return_value=mutelist["Mutelist"],
        ):
            aws_provider = AwsProvider(mutelist_path=dynamodb_mutelist_path)

        assert isinstance(aws_provider.mutelist, AWSMutelist)
        assert aws_provider.mutelist.mutelist == mutelist["Mutelist"]
        assert aws_provider.mutelist.mutelist_file_path == dynamodb_mutelist_path

    @mock_aws
    def test_empty_input_regions_in_arguments(self):
        aws_provider = AwsProvider(regions=None)

        assert isinstance(aws_provider, AwsProvider)

    @mock_aws
    def test_generate_regional_clients_all_enabled_regions(self):
        aws_provider = AwsProvider()
        response = aws_provider.generate_regional_clients("ec2")

        assert len(response.keys()) == 30

    @mock_aws
    def test_generate_regional_clients_with_enabled_regions(self):

        aws_provider = AwsProvider()
        enabled_regions = [AWS_REGION_EU_WEST_1]
        aws_provider._enabled_regions = enabled_regions

        response = aws_provider.generate_regional_clients("ec2")

        assert list(response.keys()) == enabled_regions

    @mock_aws
    def test_generate_regional_clients_with_enabled_regions_and_input_regions(self):
        region = [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        aws_provider = AwsProvider(
            regions=region,
        )

        enabled_regions = [AWS_REGION_EU_WEST_1]
        aws_provider._enabled_regions = enabled_regions

        response = aws_provider.generate_regional_clients("ec2")

        assert list(response.keys()) == enabled_regions

    @mock_aws
    def test_generate_regional_clients_cn_partition(self):
        region = [AWS_REGION_CN_NORTH_1, AWS_REGION_CN_NORTHWEST_1]
        aws_provider = AwsProvider(
            regions=region,
        )

        response = aws_provider.generate_regional_clients("ec2")
        assert AWS_REGION_CN_NORTH_1 in response.keys()
        assert AWS_REGION_CN_NORTHWEST_1 in response.keys()

    @mock_aws
    def test_generate_regional_clients_cn_partition_not_present_service(self):
        region = ["cn-northwest-1", "cn-north-1"]
        aws_provider = AwsProvider(
            regions=region,
        )

        response = aws_provider.generate_regional_clients("shield")

        assert response == {}

    @mock_aws
    def test_get_default_region(self):
        region = [AWS_REGION_EU_WEST_1]
        aws_provider = AwsProvider(
            regions=region,
        )
        aws_provider._identity.profile_region = AWS_REGION_EU_WEST_1

        assert aws_provider.get_default_region("ec2") == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_get_default_region_profile_region_not_audited(self):
        region = [AWS_REGION_EU_WEST_1]
        aws_provider = AwsProvider(
            regions=region,
        )
        aws_provider._identity.profile_region = AWS_REGION_US_EAST_2

        assert aws_provider.get_default_region("ec2") == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_get_default_region_non_profile_region(self):
        region = [AWS_REGION_EU_WEST_1]
        aws_provider = AwsProvider(
            regions=region,
        )
        aws_provider._identity.profile_region = None

        assert aws_provider.get_default_region("ec2") == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_get_default_region_non_profile_or_audited_region(self):
        aws_provider = AwsProvider()
        aws_provider._identity.profile_region = None
        assert aws_provider.get_default_region("ec2") == AWS_REGION_US_EAST_1

    @mock_aws
    def test_get_default_region_profile_region_not_present_in_service(self):
        region = [AWS_REGION_EU_WEST_1]
        aws_provider = AwsProvider(
            regions=region,
        )
        aws_provider._identity.profile_region = "non-existent-region"
        assert aws_provider.get_default_region("ec2") == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_aws_gov_get_global_region(self):
        aws_provider = AwsProvider()
        aws_provider._identity.partition = AWS_GOV_CLOUD_PARTITION

        assert aws_provider.get_global_region() == AWS_REGION_GOV_CLOUD_US_EAST_1

    @mock_aws
    def test_aws_cn_get_global_region(self):
        aws_provider = AwsProvider()
        aws_provider._identity.partition = AWS_CHINA_PARTITION

        assert aws_provider.get_global_region() == AWS_REGION_CN_NORTH_1

    @mock_aws
    def test_aws_iso_get_global_region(self):
        aws_provider = AwsProvider()
        aws_provider._identity.partition = AWS_ISO_PARTITION

        assert aws_provider.get_global_region() == AWS_REGION_ISO_GLOBAL

    @mock_aws
    def test_get_available_aws_service_regions_with_us_east_1_audited(self):
        region = [AWS_REGION_US_EAST_1]
        aws_provider = AwsProvider(
            regions=region,
        )

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
                                AWS_REGION_US_EAST_1,
                                "us-east-2",
                                "us-west-1",
                                "us-west-2",
                            ],
                        }
                    }
                }
            },
        ):
            assert aws_provider.get_available_aws_service_regions(
                "ec2", "aws", {AWS_REGION_US_EAST_1}
            ) == {AWS_REGION_US_EAST_1}

    @mock_aws
    def test_get_available_aws_service_regions_with_all_regions_audited(self):

        aws_provider = AwsProvider()

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
                                AWS_REGION_US_EAST_1,
                                "us-east-2",
                                "us-west-1",
                                "us-west-2",
                            ],
                        }
                    }
                }
            },
        ):
            assert (
                len(aws_provider.get_available_aws_service_regions("ec2", "aws")) == 17
            )

    @mock_aws
    def test_get_tagged_resources(self):
        ec2_client = client("ec2", region_name=AWS_REGION_EU_CENTRAL_1)
        instances = ec2_client.run_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            InstanceType="t2.micro",
            TagSpecifications=[
                {
                    "ResourceType": "instance",
                    "Tags": [
                        {"Key": "MY_TAG1", "Value": "MY_VALUE1"},
                        {"Key": "MY_TAG2", "Value": "MY_VALUE2"},
                    ],
                },
                {
                    "ResourceType": "instance",
                    "Tags": [{"Key": "ami", "Value": "test"}],
                },
            ],
        )
        instance_id = instances["Instances"][0]["InstanceId"]
        instance_arn = f"arn:aws:ec2:{AWS_REGION_EU_CENTRAL_1}:{AWS_ACCOUNT_NUMBER}:ec2:instance/{instance_id}"
        image_id = ec2_client.create_image(Name="testami", InstanceId=instance_id)[
            "ImageId"
        ]
        image_arn = f"arn:aws:ec2:{AWS_REGION_EU_CENTRAL_1}:{AWS_ACCOUNT_NUMBER}:ec2:image/{image_id}"
        ec2_client.create_tags(
            Resources=[image_id], Tags=[{"Key": "ami", "Value": "test"}]
        )

        # Through the AWS provider
        region = [AWS_REGION_EU_CENTRAL_1]
        resource_tags = ["ami=test"]
        aws_provider = AwsProvider(
            regions=region,
            resource_tags=resource_tags,
        )

        tagged_resources = aws_provider.audit_resources
        assert len(tagged_resources) == 2
        assert image_arn in tagged_resources
        assert instance_arn in tagged_resources

        # Calling directly the function
        tagged_resources = aws_provider.get_tagged_resources(["MY_TAG1=MY_VALUE1"])

        assert len(tagged_resources) == 1
        assert instance_arn in tagged_resources

    @mock_aws
    def test_aws_provider_resource_tags(self):
        resource_arn = [AWS_ACCOUNT_ARN]
        aws_provider = AwsProvider(
            resource_arn=resource_arn,
        )

        assert aws_provider.audit_resources == [AWS_ACCOUNT_ARN]

    @mock_aws
    def test_validate_credentials_commercial_partition_with_regions(self):
        # Create a mock IAM user
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]

        # Create AWS session to validate
        current_session = session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=AWS_REGION_EU_WEST_1,
        )

        get_caller_identity = AwsProvider.validate_credentials(
            session=current_session, aws_region=AWS_REGION_EU_WEST_1
        )

        assert isinstance(get_caller_identity, AWSCallerIdentity)

        assert re.match("[0-9a-zA-Z]{20}", get_caller_identity.user_id)
        assert get_caller_identity.account == AWS_ACCOUNT_NUMBER
        assert get_caller_identity.region == AWS_REGION_EU_WEST_1

        assert isinstance(get_caller_identity.arn, ARN)
        assert get_caller_identity.arn.partition == AWS_COMMERCIAL_PARTITION
        assert get_caller_identity.arn.region is None
        assert get_caller_identity.arn.resource == "test-user"
        assert get_caller_identity.arn.resource_type == "user"

    @mock_aws
    @patch(
        "botocore.client.BaseClient._make_api_call", new=mock_get_caller_identity_china
    )
    def test_validate_credentials_china_partition(self):
        # Create a mock IAM user
        iam_client = client("iam", region_name=AWS_REGION_CN_NORTH_1)
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]

        # Create AWS session to validate
        current_session = session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=AWS_REGION_CN_NORTH_1,
        )

        # To use GovCloud or China it is either required:
        # - Set the AWS profile region with a valid partition region
        # - Use the -f/--region with a valid partition region
        get_caller_identity = AwsProvider.validate_credentials(
            session=current_session, aws_region=AWS_REGION_CN_NORTH_1
        )

        assert isinstance(get_caller_identity, AWSCallerIdentity)

        assert re.match("[0-9a-zA-Z]{20}", get_caller_identity.user_id)
        assert get_caller_identity.account == AWS_ACCOUNT_NUMBER
        assert get_caller_identity.region == AWS_REGION_CN_NORTH_1

        assert isinstance(get_caller_identity.arn, ARN)
        assert get_caller_identity.arn.partition == AWS_CHINA_PARTITION
        assert get_caller_identity.arn.region is None
        assert get_caller_identity.arn.resource == "test-user"
        assert get_caller_identity.arn.resource_type == "user"

    @mock_aws
    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_get_caller_identity_gov_cloud,
    )
    def test_validate_credentials_gov_cloud_partition(self):
        # Create a mock IAM user
        iam_client = client("iam", region_name=AWS_REGION_GOV_CLOUD_US_EAST_1)
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]

        # Create AWS session to validate
        current_session = session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=AWS_REGION_GOV_CLOUD_US_EAST_1,
        )

        # To use GovCloud or China it is either required:
        # - Set the AWS profile region with a valid partition region
        # - Use the -f/--region with a valid partition region
        get_caller_identity = AwsProvider.validate_credentials(
            session=current_session, aws_region=AWS_REGION_GOV_CLOUD_US_EAST_1
        )

        assert isinstance(get_caller_identity, AWSCallerIdentity)

        assert re.match("[0-9a-zA-Z]{20}", get_caller_identity.user_id)
        assert get_caller_identity.account == AWS_ACCOUNT_NUMBER
        assert get_caller_identity.region == AWS_REGION_GOV_CLOUD_US_EAST_1

        assert isinstance(get_caller_identity.arn, ARN)
        assert get_caller_identity.arn.partition == AWS_GOV_CLOUD_PARTITION
        assert get_caller_identity.arn.region is None
        assert get_caller_identity.arn.resource == "test-user"
        assert get_caller_identity.arn.resource_type == "user"

    @mock_aws
    def test_test_connection_with_env_credentials(self, monkeypatch):
        # Create a mock IAM user
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]

        monkeypatch.delenv("AWS_ACCESS_KEY_ID")
        monkeypatch.delenv("AWS_SECRET_ACCESS_KEY")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", access_key["AccessKeyId"])
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", access_key["SecretAccessKey"])
        connection = AwsProvider.test_connection()

        assert isinstance(connection, Connection)
        assert connection.is_connected
        assert connection.error is None

    def test_test_connection_without_credentials(self):
        with mock.patch("boto3.Session.get_credentials", return_value=None), mock.patch(
            "botocore.session.Session.get_scoped_config", return_value={}
        ), mock.patch(
            "botocore.credentials.EnvProvider.load", return_value=None
        ), mock.patch(
            "botocore.credentials.SharedCredentialProvider.load", return_value=None
        ), mock.patch(
            "botocore.credentials.InstanceMetadataProvider.load", return_value=None
        ), mock.patch.dict(
            "os.environ",
            {
                "AWS_ACCESS_KEY_ID": "",
                "AWS_SECRET_ACCESS_KEY": "",
                "AWS_SESSION_TOKEN": "",
                "AWS_PROFILE": "",
            },
            clear=True,
        ):

            with raises(AWSNoCredentialsError) as exception:
                AwsProvider.test_connection(
                    profile=None
                )  # No profile to avoid ProfileNotFound error

            assert exception.type == AWSNoCredentialsError
            assert "AWSNoCredentialsError[1002]: No AWS credentials found" in str(
                exception.value
            )

    @mock_aws
    def test_test_connection_with_role_from_env(self, monkeypatch):
        # Create a mock IAM user
        iam_client = client("iam", region_name=AWS_REGION_US_EAST_1)
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]

        monkeypatch.setenv("AWS_ACCESS_KEY_ID", access_key["AccessKeyId"])
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", access_key["SecretAccessKey"])

        role_name = "test-role"
        role_arn = (
            f"arn:{AWS_COMMERCIAL_PARTITION}:iam::{AWS_ACCOUNT_NUMBER}:role/{role_name}"
        )

        connection = AwsProvider.test_connection(
            role_arn=role_arn, role_session_name=ROLE_SESSION_NAME
        )

        assert isinstance(connection, Connection)
        assert connection.is_connected
        assert connection.error is None

    @mock_aws
    def test_test_connection_with_role_from_env_invalid_session_duration(self):
        role_name = "test-role"
        role_arn = (
            f"arn:{AWS_COMMERCIAL_PARTITION}:iam::{AWS_ACCOUNT_NUMBER}:role/{role_name}"
        )
        with raises(AWSArgumentTypeValidationError) as exception:
            AwsProvider.test_connection(role_arn=role_arn, session_duration=899)

        assert exception.type == AWSArgumentTypeValidationError
        assert (
            exception.value.args[0]
            == "[1003] Session Duration must be between 900 and 43200 seconds."
        )

    @mock_aws
    def test_test_connection_with_role_from_env_invalid_session_duration_not_raise(
        self,
    ):
        role_name = "test-role"
        role_arn = (
            f"arn:{AWS_COMMERCIAL_PARTITION}:iam::{AWS_ACCOUNT_NUMBER}:role/{role_name}"
        )
        connection = AwsProvider.test_connection(
            role_arn=role_arn, session_duration=899, raise_on_exception=False
        )

        assert isinstance(connection, Connection)
        assert not connection.is_connected
        assert isinstance(connection.error, AWSArgumentTypeValidationError)
        assert (
            connection.error.args[0]
            == "[1003] Session Duration must be between 900 and 43200 seconds."
        )

    @mock_aws
    def test_test_connection_with_role_from_env_invalid_session_name(self):
        role_name = "test-role"
        role_arn = (
            f"arn:{AWS_COMMERCIAL_PARTITION}:iam::{AWS_ACCOUNT_NUMBER}:role/{role_name}"
        )

        with raises(AWSArgumentTypeValidationError) as exception:
            AwsProvider.test_connection(role_arn=role_arn, role_session_name="???")

        assert exception.type == AWSArgumentTypeValidationError
        assert (
            exception.value.args[0]
            == "[1003] Role Session Name must be between 2 and 64 characters and may contain alphanumeric characters, periods, hyphens, and underscores."
        )

    @mock_aws
    def test_test_connection_with_role_from_env_invalid_role_arn(self):
        role_name = "test-role"
        role_arn = f"arn:{AWS_COMMERCIAL_PARTITION}:iam::{AWS_ACCOUNT_NUMBER}:not-role/{role_name}"

        with raises(AWSIAMRoleARNInvalidResourceTypeError) as exception:
            AwsProvider.test_connection(role_arn=role_arn)

        assert exception.type == AWSIAMRoleARNInvalidResourceTypeError
        assert (
            exception.value.args[0]
            == "[1010] AWS IAM Role ARN resource type is invalid"
        )

    @mock_aws
    def test_test_connection_with_static_credentials(self):
        # Create a mock IAM user
        iam_client = client("iam", region_name=AWS_REGION_EU_WEST_1)
        username = "test-user"
        iam_user = iam_client.create_user(UserName=username)["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]

        credentials = {
            "aws_access_key_id": access_key["AccessKeyId"],
            "aws_secret_access_key": access_key["SecretAccessKey"],
        }

        connection = AwsProvider.test_connection(**credentials)

        assert isinstance(connection, Connection)
        assert connection.is_connected
        assert connection.error is None

    @mock_aws
    def test_test_connection_with_session_credentials(self):
        sts_client = client("sts", region_name=AWS_REGION_EU_WEST_1)
        session_token = sts_client.get_session_token()

        session_credentials = {
            "aws_access_key_id": session_token["Credentials"]["AccessKeyId"],
            "aws_secret_access_key": session_token["Credentials"]["SecretAccessKey"],
            "aws_session_token": session_token["Credentials"]["SessionToken"],
        }

        connection = AwsProvider.test_connection(**session_credentials)

        assert isinstance(connection, Connection)
        assert connection.is_connected
        assert connection.error is None

    @mock_aws
    def test_test_connection_with_own_account(self):
        sts_client = client("sts", region_name=AWS_REGION_EU_WEST_1)
        session_token = sts_client.get_session_token()

        session_credentials = {
            "aws_access_key_id": session_token["Credentials"]["AccessKeyId"],
            "aws_secret_access_key": session_token["Credentials"]["SecretAccessKey"],
            "aws_session_token": session_token["Credentials"]["SessionToken"],
            "provider_id": AWS_ACCOUNT_NUMBER,
        }

        connection = AwsProvider.test_connection(**session_credentials)

        assert isinstance(connection, Connection)
        assert connection.is_connected
        assert connection.error is None

    @mock_aws
    def test_test_connection_with_different_account(self):
        sts_client = client("sts", region_name=AWS_REGION_EU_WEST_1)
        session_token = sts_client.get_session_token()

        session_credentials = {
            "aws_access_key_id": session_token["Credentials"]["AccessKeyId"],
            "aws_secret_access_key": session_token["Credentials"]["SecretAccessKey"],
            "aws_session_token": session_token["Credentials"]["SessionToken"],
            "provider_id": "111122223333",
        }

        with raises(AWSInvalidProviderIdError) as exception:
            AwsProvider.test_connection(**session_credentials)

        assert exception.type == AWSInvalidProviderIdError
        assert (
            exception.value.args[0]
            == "[1015] The provided AWS credentials belong to a different account"
        )

    @mock_aws
    def test_test_connection_with_different_account_dont_raise(self):
        sts_client = client("sts", region_name=AWS_REGION_EU_WEST_1)
        session_token = sts_client.get_session_token()

        session_credentials = {
            "aws_access_key_id": session_token["Credentials"]["AccessKeyId"],
            "aws_secret_access_key": session_token["Credentials"]["SecretAccessKey"],
            "aws_session_token": session_token["Credentials"]["SessionToken"],
            "provider_id": "111122223333",
        }

        connection = AwsProvider.test_connection(
            **session_credentials, raise_on_exception=False
        )

        assert isinstance(connection, Connection)
        assert not connection.is_connected
        assert isinstance(connection.error, AWSInvalidProviderIdError)
        assert (
            connection.error.message
            == "The provided AWS credentials belong to a different account"
        )
        assert connection.error.code == 1015

    @mock_aws
    def test_test_connection_generic_exception(self):
        with patch(
            "prowler.providers.aws.aws_provider.AwsProvider.setup_session",
            side_effect=Exception(),
        ):
            connection = AwsProvider.test_connection(raise_on_exception=False)

        assert isinstance(connection, Connection)
        assert not connection.is_connected
        assert isinstance(connection.error, Exception)

    @mock_aws
    def test_create_sts_session(self):
        current_session = session.Session()
        aws_region = AWS_REGION_US_EAST_1
        sts_session = AwsProvider.create_sts_session(current_session, aws_region)

        assert sts_session._service_model.service_name == "sts"
        assert sts_session._client_config.region_name == aws_region
        assert sts_session._endpoint._endpoint_prefix == "sts"
        assert sts_session._endpoint.host == f"https://sts.{aws_region}.amazonaws.com"

    @mock_aws
    def test_create_sts_session_gov_cloud(self):
        current_session = session.Session()
        aws_region = AWS_REGION_GOV_CLOUD_US_EAST_1
        sts_session = AwsProvider.create_sts_session(current_session, aws_region)

        assert sts_session._service_model.service_name == "sts"
        assert sts_session._client_config.region_name == aws_region
        assert sts_session._endpoint._endpoint_prefix == "sts"
        assert sts_session._endpoint.host == f"https://sts.{aws_region}.amazonaws.com"

    @mock_aws
    def test_create_sts_session_china(self):
        current_session = session.Session()
        aws_region = AWS_REGION_CN_NORTH_1
        sts_session = AwsProvider.create_sts_session(current_session, aws_region)

        assert sts_session._service_model.service_name == "sts"
        assert sts_session._client_config.region_name == aws_region
        assert sts_session._endpoint._endpoint_prefix == "sts"
        assert (
            sts_session._endpoint.host == f"https://sts.{aws_region}.amazonaws.com.cn"
        )

    @mock_aws
    @patch(
        "prowler.lib.check.utils.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_elb_service,
    )
    def test_get_checks_from_input_arn_elb(self):

        expected_checks = [
            "elb_insecure_ssl_ciphers",
            "elb_internet_facing",
            "elb_logging_enabled",
        ]

        aws_provider = AwsProvider()
        aws_provider._audit_resources = [
            f"arn:aws:elasticloadbalancing:us-east-1:{AWS_ACCOUNT_NUMBER}:loadbalancer/test"
        ]
        recovered_checks = aws_provider.get_checks_from_input_arn()

        assert recovered_checks == expected_checks

    @mock_aws
    @patch(
        "prowler.lib.check.utils.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_efs_service,
    )
    def test_get_checks_from_input_arn_efs(self):

        expected_checks = [
            "efs_encryption_at_rest_enabled",
            "efs_have_backup_enabled",
            "efs_not_publicly_accessible",
        ]

        aws_provider = AwsProvider()
        aws_provider._audit_resources = [
            f"arn:aws:elasticfilesystem:us-east-1:{AWS_ACCOUNT_NUMBER}:file-system/fs-01234567"
        ]
        recovered_checks = aws_provider.get_checks_from_input_arn()

        assert recovered_checks == expected_checks

    @mock_aws
    @patch(
        "prowler.lib.check.utils.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_lambda_service,
    )
    def test_get_checks_from_input_arn_lambda(self):
        expected_checks = [
            "awslambda_function_invoke_api_operations_cloudtrail_logging_enabled",
            "awslambda_function_no_secrets_in_code",
            "awslambda_function_url_cors_policy",
        ]

        aws_provider = AwsProvider()
        aws_provider._audit_resources = [
            "arn:aws:lambda:us-east-1:123456789:function:test-lambda"
        ]
        recovered_checks = aws_provider.get_checks_from_input_arn()

        assert recovered_checks == expected_checks

    @mock_aws
    @patch(
        "prowler.lib.check.utils.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_iam_service,
    )
    def test_get_checks_from_input_arn_iam(self):

        expected_checks = [
            "iam_check_saml_providers_sts",
            "iam_customer_attached_policy_no_administrative_privileges",
            "iam_password_policy_minimum_length_14",
        ]

        aws_provider = AwsProvider()
        aws_provider._audit_resources = [
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:user/user-name"
        ]
        recovered_checks = aws_provider.get_checks_from_input_arn()

        assert recovered_checks == expected_checks

    @mock_aws
    @mock_aws
    @patch(
        "prowler.lib.check.utils.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_s3_service,
    )
    def test_get_checks_from_input_arn_s3(self):

        expected_checks = [
            "s3_account_level_public_access_blocks",
            "s3_bucket_acl_prohibited",
            "s3_bucket_policy_public_write_access",
        ]

        aws_provider = AwsProvider()
        aws_provider._audit_resources = ["arn:aws:s3:::bucket-name"]
        recovered_checks = aws_provider.get_checks_from_input_arn()

        assert recovered_checks == expected_checks

    @mock_aws
    @patch(
        "prowler.lib.check.utils.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_cloudwatch_service,
    )
    def test_get_checks_from_input_arn_cloudwatch(self):
        expected_checks = [
            "cloudwatch_changes_to_network_acls_alarm_configured",
            "cloudwatch_changes_to_network_gateways_alarm_configured",
            "cloudwatch_changes_to_network_route_tables_alarm_configured",
        ]

        aws_provider = AwsProvider()
        aws_provider._audit_resources = [
            f"arn:aws:logs:us-east-1:{AWS_ACCOUNT_NUMBER}:destination:testDestination"
        ]
        recovered_checks = aws_provider.get_checks_from_input_arn()

        assert recovered_checks == expected_checks

    @mock_aws
    @patch(
        "prowler.lib.check.utils.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_cognito_service,
    )
    def test_get_checks_from_input_arn_cognito(self):
        expected_checks = []

        aws_provider = AwsProvider()
        aws_provider._audit_resources = [
            f"arn:aws:cognito-idp:us-east-1:{AWS_ACCOUNT_NUMBER}:userpool/test"
        ]
        recovered_checks = aws_provider.get_checks_from_input_arn()

        assert recovered_checks == expected_checks

    @mock_aws
    @patch(
        "prowler.lib.check.utils.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_ec2_service,
    )
    def test_get_checks_from_input_arn_ec2_security_group(self):
        expected_checks = ["ec2_securitygroup_allow_ingress_from_internet_to_any_port"]

        aws_provider = AwsProvider()
        aws_provider._audit_resources = [
            f"arn:aws:ec2:us-east-1:{AWS_ACCOUNT_NUMBER}:security-group/sg-1111111111"
        ]
        recovered_checks = aws_provider.get_checks_from_input_arn()

        assert recovered_checks == expected_checks

    @mock_aws
    @patch(
        "prowler.lib.check.utils.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_ec2_service,
    )
    def test_get_checks_from_input_arn_ec2_acl(self):
        expected_checks = ["ec2_networkacl_allow_ingress_any_port"]

        aws_provider = AwsProvider()
        aws_provider._audit_resources = [
            f"arn:aws:ec2:us-west-2:{AWS_ACCOUNT_NUMBER}:network-acl/acl-1"
        ]
        recovered_checks = aws_provider.get_checks_from_input_arn()

        assert recovered_checks == expected_checks

    @mock_aws
    @patch(
        "prowler.lib.check.utils.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_rds_service,
    )
    def test_get_checks_from_input_arn_rds_snapshots(self):
        expected_checks = ["rds_snapshots_public_access"]

        aws_provider = AwsProvider()
        aws_provider._audit_resources = [
            f"arn:aws:rds:us-east-2:{AWS_ACCOUNT_NUMBER}:snapshot:rds:snapshot-1",
        ]
        recovered_checks = aws_provider.get_checks_from_input_arn()

        assert recovered_checks == expected_checks

    @mock_aws
    @patch(
        "prowler.lib.check.utils.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_ec2_service,
    )
    def test_get_checks_from_input_arn_ec2_ami(self):
        expected_checks = ["ec2_ami_public"]

        aws_provider = AwsProvider()
        aws_provider._audit_resources = [
            f"arn:aws:ec2:us-west-2:{AWS_ACCOUNT_NUMBER}:image/ami-1"
        ]
        recovered_checks = aws_provider.get_checks_from_input_arn()

        assert recovered_checks == expected_checks

    @mock_aws
    def test_get_regions_from_audit_resources_with_regions(self):
        audit_resources = [
            f"arn:aws:lambda:us-east-1:{AWS_ACCOUNT_NUMBER}:function:test-lambda",
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:policy/test",
            f"arn:aws:ec2:eu-west-1:{AWS_ACCOUNT_NUMBER}:security-group/sg-test",
            "arn:aws:s3:::bucket-name",
            "arn:aws:apigateway:us-east-2::/restapis/api-id/stages/stage-name",
        ]
        expected_regions = {"us-east-1", "eu-west-1", "us-east-2"}

        aws_provider = AwsProvider()
        recovered_regions = aws_provider.get_regions_from_audit_resources(
            audit_resources
        )
        assert recovered_regions == expected_regions

    @mock_aws
    def test_get_regions_from_audit_resources_without_regions(self):
        audit_resources = ["arn:aws:s3:::bucket-name"]

        aws_provider = AwsProvider()
        recovered_regions = aws_provider.get_regions_from_audit_resources(
            audit_resources
        )
        assert not recovered_regions

    def test_get_regions_all_count(self):
        assert len(AwsProvider.get_regions(partition=None)) == 34

    def test_get_regions_cn_count(self):
        assert len(AwsProvider.get_regions("aws-cn")) == 2

    def test_get_regions_aws_count(self):
        assert len(AwsProvider.get_regions(partition="aws")) == 30

    def test_get_all_regions(self):
        with patch(
            "prowler.providers.aws.aws_provider.read_aws_regions_file",
            return_value={
                "services": {
                    "acm": {
                        "regions": {
                            "aws": [
                                "af-south-1",
                            ],
                            "aws-cn": [
                                "cn-north-1",
                            ],
                            "aws-us-gov": [
                                "us-gov-west-1",
                            ],
                        }
                    }
                }
            },
        ):
            assert AwsProvider.get_regions(partition=None) == {
                "af-south-1",
                "cn-north-1",
                "us-gov-west-1",
            }

    def test_get_regions_with_us_gov_partition(self):
        with patch(
            "prowler.providers.aws.aws_provider.read_aws_regions_file",
            return_value={
                "services": {
                    "acm": {
                        "regions": {
                            "aws": [
                                "af-south-1",
                            ],
                            "aws-cn": [
                                "cn-north-1",
                            ],
                            "aws-us-gov": [
                                "us-gov-west-1",
                            ],
                        }
                    }
                }
            },
        ):
            assert AwsProvider.get_regions("aws-us-gov") == {
                "us-gov-west-1",
            }

    def test_get_regions_with_aws_partition(self):
        with patch(
            "prowler.providers.aws.aws_provider.read_aws_regions_file",
            return_value={
                "services": {
                    "acm": {
                        "regions": {
                            "aws": [
                                "af-south-1",
                            ],
                            "aws-cn": [
                                "cn-north-1",
                            ],
                            "aws-us-gov": [
                                "us-gov-west-1",
                            ],
                        }
                    }
                }
            },
        ):
            assert AwsProvider.get_regions("aws") == {
                "af-south-1",
            }

    def test_get_regions_with_cn_partition(self):
        with patch(
            "prowler.providers.aws.aws_provider.read_aws_regions_file",
            return_value={
                "services": {
                    "acm": {
                        "regions": {
                            "aws": [
                                "af-south-1",
                            ],
                            "aws-cn": [
                                "cn-north-1",
                            ],
                            "aws-us-gov": [
                                "us-gov-west-1",
                            ],
                        }
                    }
                }
            },
        ):
            assert AwsProvider.get_regions("aws-cn") == {
                "cn-north-1",
            }

    def test_get_regions_with_unknown_partition(self):
        with patch(
            "prowler.providers.aws.aws_provider.read_aws_regions_file",
            return_value={
                "services": {
                    "acm": {
                        "regions": {
                            "aws": [
                                "af-south-1",
                            ],
                            "aws-cn": [
                                "cn-north-1",
                            ],
                            "aws-us-gov": [
                                "us-gov-west-1",
                            ],
                        }
                    }
                }
            },
        ):
            partition = "unknown"
            with pytest.raises(AWSInvalidPartitionError) as exception:
                AwsProvider.get_regions(partition)

            assert exception.type == AWSInvalidPartitionError
        assert f"Invalid partition: {partition}" in exception.value.args[0]

    def test_get_aws_region_for_sts_input_regions_none_session_region_none(self):
        input_regions = None
        session_region = None
        assert (
            get_aws_region_for_sts(session_region, input_regions)
            == AWS_STS_GLOBAL_ENDPOINT_REGION
        )

    def test_get_aws_region_for_sts_input_regions_none_session_region_ireland(self):
        input_regions = None
        session_region = AWS_REGION_EU_WEST_1
        assert (
            get_aws_region_for_sts(session_region, input_regions)
            == AWS_REGION_EU_WEST_1
        )

    def test_get_aws_region_for_sts_input_regions_empty_session_region_none(self):
        input_regions = set()
        session_region = None
        assert (
            get_aws_region_for_sts(session_region, input_regions)
            == AWS_STS_GLOBAL_ENDPOINT_REGION
        )

    def test_get_aws_region_for_sts_input_regions_empty_session_region_ireland(self):
        input_regions = set()
        session_region = AWS_REGION_EU_WEST_1
        assert (
            get_aws_region_for_sts(session_region, input_regions)
            == AWS_REGION_EU_WEST_1
        )

    def test_get_aws_region_for_sts_input_regions_ireland_and_virgninia(self):
        input_regions = [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        session_region = None
        assert (
            get_aws_region_for_sts(session_region, input_regions)
            == AWS_REGION_EU_WEST_1
        )

    @mock_aws
    def test_set_session_config_default(self):

        aws_provider = AwsProvider()
        session_config = aws_provider.set_session_config(None)

        assert session_config.user_agent_extra == BOTO3_USER_AGENT_EXTRA
        assert session_config.retries == {"max_attempts": 3, "mode": "standard"}

    @mock_aws
    def test_set_session_config_10_max_attempts(self):

        aws_provider = AwsProvider()
        session_config = aws_provider.set_session_config(10)

        assert session_config.user_agent_extra == BOTO3_USER_AGENT_EXTRA
        assert session_config.retries == {"max_attempts": 10, "mode": "standard"}

    @mock_aws
    @patch(
        "prowler.lib.check.utils.recover_checks_from_provider",
        new=mock_recover_checks_from_aws_provider_ec2_service,
    )
    def test_get_checks_to_execute_by_audit_resources(self):

        aws_provider = AwsProvider()
        aws_provider._audit_resources = [
            f"arn:aws:ec2:us-west-2:{AWS_ACCOUNT_NUMBER}:network-acl/acl-1"
        ]
        aws_provider.get_checks_to_execute_by_audit_resources() == {
            "ec2_networkacl_allow_ingress_any_port"
        }

    def test_update_provider_config_aws(self):
        aws_provider = set_mocked_aws_provider(
            audit_config={"shodan_api_key": "DEFAULT-KEY"}
        )

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):

            assert {
                "shodan_api_key": "TEST-API-KEY"
            } == Provider.update_provider_config(
                aws_provider.audit_config, "shodan_api_key", "TEST-API-KEY"
            )

    def test_update_provider_config_aws_not_present(self):
        aws_provider = set_mocked_aws_provider(
            audit_config={"shodan_api_key": "DEFAULT-KEY"}
        )

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):

            assert {"shodan_api_key": "DEFAULT-KEY"} == Provider.update_provider_config(
                aws_provider.audit_config, "not_found", "not_value"
            )

    @mock_aws
    def test_refresh_credentials_before_expiration(self):
        role_arn = create_role(AWS_REGION_EU_WEST_1)
        session_duration = 900
        aws_provider = AwsProvider(role_arn=role_arn, session_duration=session_duration)

        current_credentials = (
            aws_provider._assumed_role_configuration.credentials.__dict__
        )
        refreshed_credentials = {
            "access_key": current_credentials["aws_access_key_id"],
            "secret_key": current_credentials["aws_secret_access_key"],
            "token": current_credentials["aws_session_token"],
            "expiry_time": current_credentials.get(
                "expiration", current_credentials.get("expiry_time")
            ).isoformat(),
        }

        assert aws_provider.refresh_credentials() == refreshed_credentials

    @mock_aws
    def test_refresh_credentials_after_expiration(self):
        role_arn = create_role(AWS_REGION_EU_WEST_1)
        session_duration_in_seconds = 900
        session_duration = session_duration_in_seconds
        aws_provider = AwsProvider(role_arn=role_arn, session_duration=session_duration)

        # Manually expire credentials
        aws_provider._assumed_role_configuration.credentials.expiration = datetime.now(
            get_localzone()
        ) - timedelta(seconds=session_duration_in_seconds)

        current_credentials = aws_provider._assumed_role_configuration.credentials

        # Refresh credentials
        refreshed_credentials = aws_provider.refresh_credentials()

        # Assert that the refreshed credentials are different
        access_key = refreshed_credentials.get("access_key")
        assert access_key != current_credentials.aws_access_key_id

        secret_key = refreshed_credentials.get("secret_key")
        assert secret_key != current_credentials.aws_secret_access_key

        session_token = refreshed_credentials.get("token")
        assert session_token != current_credentials.aws_session_token

        expiry_time = refreshed_credentials.get("expiry_time")
        expiry_time_formatted = datetime.fromisoformat(expiry_time)
        assert expiry_time != current_credentials.expiration
        assert datetime.now(get_localzone()) < expiry_time_formatted

        # Assert credentials format
        assert len(access_key) == 20
        assert search(r"^ASIA.*$", access_key)

        assert len(secret_key) == 40

        assert len(session_token) == 356
        assert search(r"^FQoGZXIvYXdzE.*$", session_token)
