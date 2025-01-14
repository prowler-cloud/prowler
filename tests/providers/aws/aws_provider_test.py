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
<<<<<<< HEAD
            assert len(get_available_aws_service_regions("ec2", audit_info)) == 17
=======
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
        with (
            mock.patch("boto3.Session.get_credentials", return_value=None),
            mock.patch("botocore.session.Session.get_scoped_config", return_value={}),
            mock.patch("botocore.credentials.EnvProvider.load", return_value=None),
            mock.patch(
                "botocore.credentials.SharedCredentialProvider.load", return_value=None
            ),
            mock.patch(
                "botocore.credentials.InstanceMetadataProvider.load", return_value=None
            ),
            mock.patch.dict(
                "os.environ",
                {
                    "AWS_ACCESS_KEY_ID": "",
                    "AWS_SECRET_ACCESS_KEY": "",
                    "AWS_SESSION_TOKEN": "",
                    "AWS_PROFILE": "",
                },
                clear=True,
            ),
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
        assert len(AwsProvider.get_regions(partition=None)) == 36

    def test_get_regions_cn_count(self):
        assert len(AwsProvider.get_regions("aws-cn")) == 2

    def test_get_regions_aws_count(self):
        assert len(AwsProvider.get_regions(partition="aws")) == 32

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
>>>>>>> ca262a679 (chore(regions_update): Changes in regions for AWS services (#6495))
