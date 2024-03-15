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
from tests.providers.aws.utils import (
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


def mock_print_audit_credentials(*_):
    pass


# Mocking GetCallerIdentity for China and GovCloud
make_api_call = botocore.client.BaseClient._make_api_call


def mock_get_caller_identity_china(self, operation_name, kwarg):
    if operation_name == "GetCallerIdentity":
        return {
            "UserId": "XXXXXXXXXXXXXXXXXXXXX",
            "Account": AWS_ACCOUNT_NUMBER,
            "Arn": f"arn:aws-cn:iam::{AWS_ACCOUNT_NUMBER}:user/test-user",
        }

    return make_api_call(self, operation_name, kwarg)


def mock_get_caller_identity_gov_cloud(self, operation_name, kwarg):
    if operation_name == "GetCallerIdentity":
        return {
            "UserId": "XXXXXXXXXXXXXXXXXXXXX",
            "Account": AWS_ACCOUNT_NUMBER,
            "Arn": f"arn:aws-us-gov:iam::{AWS_ACCOUNT_NUMBER}:user/test-user",
        }

    return make_api_call(self, operation_name, kwarg)


def mock_validate_credentials(*_):
    caller_identity = {
        "Arn": "arn:aws:iam::123456789012:user/test",
        "Account": "123456789012",
        "UserId": "test",
    }
    return caller_identity


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
            assert aws_provider.aws_session.region_name == AWS_REGION_US_EAST_1
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
            assert aws_provider.aws_session.region_name == AWS_REGION_US_EAST_1
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
            assert len(get_available_aws_service_regions("ec2", audit_info)) == 17

    @mock_aws
    def test_get_tagged_resources(self):
        with patch(
            "prowler.providers.common.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ) as mock_audit_info:
            client = boto3.client("ec2", region_name="eu-central-1")
            instances = client.run_instances(
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
            image_id = client.create_image(Name="testami", InstanceId=instance_id)[
                "ImageId"
            ]
            client.create_tags(
                Resources=[image_id], Tags=[{"Key": "ami", "Value": "test"}]
            )

            mock_audit_info.audited_regions = ["eu-central-1"]
            mock_audit_info.audit_session = boto3.session.Session()
            assert len(get_tagged_resources(["ami=test"], mock_audit_info)) == 2
            assert image_id in str(get_tagged_resources(["ami=test"], mock_audit_info))
            assert instance_id in str(
                get_tagged_resources(["ami=test"], mock_audit_info)
            )
            assert (
                len(get_tagged_resources(["MY_TAG1=MY_VALUE1"], mock_audit_info)) == 1
            )
            assert instance_id in str(
                get_tagged_resources(["MY_TAG1=MY_VALUE1"], mock_audit_info)
            )

    @mock_aws
    @patch(
        "prowler.providers.common.audit_info.validate_aws_credentials",
        new=mock_validate_credentials,
    )
    @patch(
        "prowler.providers.common.audit_info.print_aws_credentials",
        new=mock_print_audit_credentials,
    )
    def test_set_audit_info_aws(self):
        with patch(
            "prowler.providers.common.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ):
            provider = "aws"
            arguments = {
                "profile": None,
                "role": None,
                "session_duration": None,
                "external_id": None,
                "regions": None,
                "organizations_role": None,
                "config_file": default_config_file_path,
            }

            audit_info = set_provider_audit_info(provider, arguments)
            # TODO(Audit_Info): use provider here
            assert isinstance(audit_info, AWS_Audit_Info)

    def test_set_audit_info_aws_bad_session_duration(self):
        with patch(
            "prowler.providers.common.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ):
            provider = "aws"
            arguments = {
                "profile": None,
                "role": None,
                "session_duration": 100,
                "external_id": None,
                "regions": None,
                "organizations_role": None,
            }

            with pytest.raises(SystemExit) as exception:
                _ = set_provider_audit_info(provider, arguments)
            # assert exception == "Value for -T option must be between 900 and 43200"
            assert isinstance(exception, pytest.ExceptionInfo)

    def test_set_audit_info_aws_session_duration_without_role(self):
        with patch(
            "prowler.providers.common.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ):
            provider = "aws"
            arguments = {
                "profile": None,
                "role": None,
                "session_duration": 1000,
                "external_id": None,
                "regions": None,
                "organizations_role": None,
            }

            with pytest.raises(SystemExit) as exception:
                _ = set_provider_audit_info(provider, arguments)
            # assert exception == "To use -I/--external-id, -T/--session-duration or --role-session-name options -R/--role option is needed"
            assert isinstance(exception, pytest.ExceptionInfo)

    def test_set_audit_info_external_id_without_role(self):
        with patch(
            "prowler.providers.common.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ):
            provider = "aws"
            arguments = {
                "profile": None,
                "role": None,
                "session_duration": 3600,
                "external_id": "test-external-id",
                "regions": None,
                "organizations_role": None,
            }

            with pytest.raises(SystemExit) as exception:
                _ = set_provider_audit_info(provider, arguments)
            # assert exception == "To use -I/--external-id, -T/--session-duration or --role-session-name options -R/--role option is needed"
            assert isinstance(exception, pytest.ExceptionInfo)

    def test_set_provider_output_options_aws_no_output_filename(self):
        #  Set the cloud provider
        provider = "aws"
        # Set the arguments passed
        arguments = Namespace()
        arguments.quiet = True
        arguments.output_modes = ["csv"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.security_hub = True
        arguments.shodan = "test-api-key"
        arguments.only_logs = False
        arguments.unix_timestamp = False
        arguments.send_sh_only_fails = True

        # Mock AWS Audit Info
        audit_info = self.set_mocked_aws_audit_info()

        mutelist_file = ""
        bulk_checks_metadata = {}
        output_options = set_provider_output_options(
            provider, arguments, audit_info, mutelist_file, bulk_checks_metadata
        )
        assert isinstance(output_options, Aws_Output_Options)
        assert output_options.security_hub_enabled
        assert output_options.send_sh_only_fails
        assert output_options.is_quiet
        assert output_options.output_modes == ["csv", "json-asff"]
        assert output_options.output_directory == arguments.output_directory
        assert output_options.mutelist_file == ""
        assert output_options.bulk_checks_metadata == {}
        assert output_options.verbose
        assert (
            output_options.output_filename
            == f"prowler-output-{AWS_ACCOUNT_NUMBER}-{DATETIME}"
        )

        # Delete testing directory
        rmdir(arguments.output_directory)

    def test_set_provider_output_options_aws(self):
        #  Set the cloud provider
        provider = "aws"
        # Set the arguments passed
        arguments = Namespace()
        arguments.quiet = True
        arguments.output_modes = ["csv"]
        arguments.output_directory = "output_test_directory"
        arguments.verbose = True
        arguments.output_filename = "output_test_filename"
        arguments.security_hub = True
        arguments.shodan = "test-api-key"
        arguments.only_logs = False
        arguments.unix_timestamp = False
        arguments.send_sh_only_fails = True

        audit_info = self.set_mocked_aws_audit_info()
        mutelist_file = ""
        bulk_checks_metadata = {}
        output_options = set_provider_output_options(
            provider, arguments, audit_info, mutelist_file, bulk_checks_metadata
        )
        assert isinstance(output_options, Aws_Output_Options)
        assert output_options.security_hub_enabled
        assert output_options.send_sh_only_fails
        assert output_options.is_quiet
        assert output_options.output_modes == ["csv", "json-asff"]
        assert output_options.output_directory == arguments.output_directory
        assert output_options.mutelist_file == ""
        assert output_options.bulk_checks_metadata == {}
        assert output_options.verbose
        assert output_options.output_filename == arguments.output_filename

        # Delete testing directory
        rmdir(arguments.output_directory)
