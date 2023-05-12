import json
import re

import boto3
import botocore
import sure  # noqa
from boto3 import session
from mock import patch
from moto import (
    mock_ec2,
    mock_iam,
    mock_organizations,
    mock_resourcegroupstaggingapi,
    mock_sts,
)

from prowler.providers.aws.lib.arn.arn import parse_iam_credentials_arn
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.azure.azure_provider import Azure_Provider
from prowler.providers.azure.lib.audit_info.models import (
    Azure_Audit_Info,
    Azure_Identity_Info,
)
from prowler.providers.common.audit_info import (
    Audit_Info,
    get_tagged_resources,
    set_provider_audit_info,
)
from prowler.providers.gcp.gcp_provider import GCP_Provider
from prowler.providers.gcp.lib.audit_info.models import GCP_Audit_Info

EXAMPLE_AMI_ID = "ami-12c6146b"
AWS_ACCOUNT_NUMBER = "123456789012"


mock_azure_audit_info = Azure_Audit_Info(
    credentials=None,
    identity=Azure_Identity_Info(),
    audit_metadata=None,
    audit_resources=None,
)

mock_set_audit_info = Audit_Info()

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


def mock_print_audit_credentials(*_):
    pass


def mock_set_identity_info(*_):
    return Azure_Identity_Info()


def mock_set_azure_credentials(*_):
    return {}


def mock_set_gcp_credentials(*_):
    return (None, "project")


class Test_Set_Audit_Info:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn="arn:aws:iam::123456789012:user/test",
            profile=None,
            profile_region="eu-west-1",
            credentials=None,
            assumed_role_info=None,
            audited_regions=["eu-west-2", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    @mock_sts
    @mock_iam
    def test_validate_credentials_commercial_partition_with_regions(self):
        with patch(
            "prowler.providers.common.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ):
            # AWS Region for AWS COMMERCIAL
            aws_region = "eu-west-1"
            aws_partition = "aws"
            # Create a mock IAM user
            iam_client = boto3.client("iam", region_name=aws_region)
            iam_user = iam_client.create_user(UserName="test-user")["User"]
            # Create a mock IAM access keys
            access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
                "AccessKey"
            ]
            access_key_id = access_key["AccessKeyId"]
            secret_access_key = access_key["SecretAccessKey"]

            # Create AWS session to validate
            session = boto3.session.Session(
                aws_access_key_id=access_key_id,
                aws_secret_access_key=secret_access_key,
                region_name=aws_region,
            )
            audit_info = Audit_Info()
            get_caller_identity = audit_info.validate_credentials(session, [aws_region])

            assert get_caller_identity["region"] == aws_region

            caller_identity_arn = parse_iam_credentials_arn(get_caller_identity["Arn"])

            assert caller_identity_arn.partition == aws_partition
            assert caller_identity_arn.region is None
            assert caller_identity_arn.resource == "test-user"
            assert caller_identity_arn.resource_type == "user"
            assert re.match("[0-9a-zA-Z]{20}", get_caller_identity["UserId"])
            assert get_caller_identity["Account"] == AWS_ACCOUNT_NUMBER

    @mock_sts
    @mock_iam
    def test_validate_credentials_commercial_partition_with_regions_none_and_profile_region_so_profile_region(
        self,
    ):
        # AWS Region for AWS COMMERCIAL
        aws_region = "eu-west-1"
        aws_partition = "aws"
        # Create a mock IAM user
        iam_client = boto3.client("iam", region_name=aws_region)
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]

        # Create AWS session to validate
        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=aws_region,
        )
        audit_info = Audit_Info()
        get_caller_identity = audit_info.validate_credentials(session, None)

        assert get_caller_identity["region"] == aws_region

        caller_identity_arn = parse_iam_credentials_arn(get_caller_identity["Arn"])

        assert caller_identity_arn.partition == aws_partition
        assert caller_identity_arn.region is None
        assert caller_identity_arn.resource == "test-user"
        assert caller_identity_arn.resource_type == "user"
        assert re.match("[0-9a-zA-Z]{20}", get_caller_identity["UserId"])
        assert get_caller_identity["Account"] == AWS_ACCOUNT_NUMBER

    @mock_sts
    @mock_iam
    def test_validate_credentials_commercial_partition_with_0_regions_and_profile_region_so_profile_region(
        self,
    ):
        # AWS Region for AWS COMMERCIAL
        aws_region = "eu-west-1"
        aws_partition = "aws"
        # Create a mock IAM user
        iam_client = boto3.client("iam", region_name=aws_region)
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]

        # Create AWS session to validate
        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=aws_region,
        )
        audit_info = Audit_Info()
        get_caller_identity = audit_info.validate_credentials(session, [])

        assert get_caller_identity["region"] == aws_region

        caller_identity_arn = parse_iam_credentials_arn(get_caller_identity["Arn"])

        assert caller_identity_arn.partition == aws_partition
        assert caller_identity_arn.region is None
        assert caller_identity_arn.resource == "test-user"
        assert caller_identity_arn.resource_type == "user"
        assert re.match("[0-9a-zA-Z]{20}", get_caller_identity["UserId"])
        assert get_caller_identity["Account"] == AWS_ACCOUNT_NUMBER

    @mock_sts
    @mock_iam
    def test_validate_credentials_commercial_partition_without_regions_and_profile_region_so_us_east_1(
        self,
    ):
        # AWS Region for AWS COMMERCIAL
        aws_region = "eu-west-1"
        aws_partition = "aws"
        # Create a mock IAM user
        iam_client = boto3.client("iam", region_name=aws_region)
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]

        # Create AWS session to validate
        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=None,
        )
        audit_info = Audit_Info()
        get_caller_identity = audit_info.validate_credentials(session, [])

        assert get_caller_identity["region"] == "us-east-1"

        caller_identity_arn = parse_iam_credentials_arn(get_caller_identity["Arn"])

        assert caller_identity_arn.partition == aws_partition
        assert caller_identity_arn.region is None
        assert caller_identity_arn.resource == "test-user"
        assert caller_identity_arn.resource_type == "user"
        assert re.match("[0-9a-zA-Z]{20}", get_caller_identity["UserId"])
        assert get_caller_identity["Account"] == AWS_ACCOUNT_NUMBER

    @mock_sts
    @mock_iam
    def test_validate_credentials_china_partition_without_regions_and_profile_region_so_us_east_1(
        self,
    ):
        # AWS Region for AWS COMMERCIAL
        aws_region = "eu-west-1"
        aws_partition = "aws"
        # Create a mock IAM user
        iam_client = boto3.client("iam", region_name=aws_region)
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]

        # Create AWS session to validate
        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=None,
        )
        audit_info = Audit_Info()
        get_caller_identity = audit_info.validate_credentials(session, [])

        assert get_caller_identity["region"] == "us-east-1"

        caller_identity_arn = parse_iam_credentials_arn(get_caller_identity["Arn"])

        assert caller_identity_arn.partition == aws_partition
        assert caller_identity_arn.region is None
        assert caller_identity_arn.resource == "test-user"
        assert caller_identity_arn.resource_type == "user"
        assert re.match("[0-9a-zA-Z]{20}", get_caller_identity["UserId"])
        assert get_caller_identity["Account"] == AWS_ACCOUNT_NUMBER

    @mock_sts
    @mock_iam
    @patch(
        "botocore.client.BaseClient._make_api_call", new=mock_get_caller_identity_china
    )
    def test_validate_credentials_china_partition(self):
        # AWS Region for AWS CHINA
        aws_region = "cn-north-1"
        aws_partition = "aws-cn"
        # Create a mock IAM user
        iam_client = boto3.client("iam", region_name=aws_region)
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]

        # Create AWS session to validate
        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=aws_region,
        )
        audit_info = Audit_Info()
        get_caller_identity = audit_info.validate_credentials(session, [aws_region])

        # To use GovCloud or China it is either required:
        # - Set the AWS profile region with a valid partition region
        # - Use the -f/--region with a valid partition region
        assert get_caller_identity["region"] == aws_region

        caller_identity_arn = parse_iam_credentials_arn(get_caller_identity["Arn"])

        assert caller_identity_arn.partition == aws_partition
        assert caller_identity_arn.region is None
        assert caller_identity_arn.resource == "test-user"
        assert caller_identity_arn.resource_type == "user"
        assert re.match("[0-9a-zA-Z]{20}", get_caller_identity["UserId"])
        assert get_caller_identity["Account"] == AWS_ACCOUNT_NUMBER

    @mock_sts
    @mock_iam
    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_get_caller_identity_gov_cloud,
    )
    def test_validate_credentials_gov_cloud_partition(self):
        # AWS Region for US GOV CLOUD
        aws_region = "us-gov-east-1"
        aws_partition = "aws-us-gov"
        # Create a mock IAM user
        iam_client = boto3.client("iam", region_name=aws_region)
        iam_user = iam_client.create_user(UserName="test-user")["User"]
        # Create a mock IAM access keys
        access_key = iam_client.create_access_key(UserName=iam_user["UserName"])[
            "AccessKey"
        ]
        access_key_id = access_key["AccessKeyId"]
        secret_access_key = access_key["SecretAccessKey"]

        # Create AWS session to validate
        session = boto3.session.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
            region_name=aws_region,
        )
        audit_info = Audit_Info()
        get_caller_identity = audit_info.validate_credentials(session, [aws_region])

        # To use GovCloud or China it is either required:
        # - Set the AWS profile region with a valid partition region
        # - Use the -f/--region with a valid partition region
        assert get_caller_identity["region"] == aws_region

        caller_identity_arn = parse_iam_credentials_arn(get_caller_identity["Arn"])

        assert caller_identity_arn.partition == aws_partition
        assert caller_identity_arn.region is None
        assert caller_identity_arn.resource == "test-user"
        assert caller_identity_arn.resource_type == "user"
        assert re.match("[0-9a-zA-Z]{20}", get_caller_identity["UserId"])
        assert get_caller_identity["Account"] == AWS_ACCOUNT_NUMBER

    @mock_organizations
    @mock_sts
    @mock_iam
    def test_organizations(self):
        with patch(
            "prowler.providers.common.audit_info.current_audit_info",
            new=self.set_mocked_audit_info(),
        ):
            client = boto3.client("organizations", region_name="us-east-1")
            iam_client = boto3.client("iam", region_name="us-east-1")
            sts_client = boto3.client("sts", region_name="us-east-1")

            mockname = "mock-account"
            mockdomain = "moto-example.org"
            mockemail = "@".join([mockname, mockdomain])

            org_id = client.create_organization(FeatureSet="ALL")["Organization"]["Id"]
            account_id = client.create_account(AccountName=mockname, Email=mockemail)[
                "CreateAccountStatus"
            ]["AccountId"]

            client.tag_resource(
                ResourceId=account_id, Tags=[{"Key": "key", "Value": "value"}]
            )

            trust_policy_document = {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"},
                    "Action": "sts:AssumeRole",
                },
            }
            iam_role_arn = iam_client.role_arn = iam_client.create_role(
                RoleName="test-role",
                AssumeRolePolicyDocument=json.dumps(trust_policy_document),
            )["Role"]["Arn"]
            session_name = "new-session"
            assumed_role = sts_client.assume_role(
                RoleArn=iam_role_arn, RoleSessionName=session_name
            )

            audit_info = Audit_Info()
            org = audit_info.get_organizations_metadata(account_id, assumed_role)

            org.account_details_email.should.equal(mockemail)
            org.account_details_name.should.equal(mockname)
            org.account_details_arn.should.equal(
                f"arn:aws:organizations::{AWS_ACCOUNT_NUMBER}:account/{org_id}/{account_id}"
            )
            org.account_details_org.should.equal(org_id)
            org.account_details_tags.should.equal("key:value,")

    @patch.object(Audit_Info, "validate_credentials", new=mock_validate_credentials)
    @patch.object(Audit_Info, "print_aws_credentials", new=mock_print_audit_credentials)
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
                "subscriptions": None,
                "az_cli_auth": None,
                "sp_env_auth": None,
                "browser_auth": None,
                "managed_entity_auth": None,
            }

            audit_info = set_provider_audit_info(provider, arguments)
            assert isinstance(audit_info, AWS_Audit_Info)

    @patch(
        "prowler.providers.common.audit_info.azure_audit_info",
        new=mock_azure_audit_info,
    )
    @patch.object(Azure_Provider, "__set_credentials__", new=mock_set_azure_credentials)
    @patch.object(Azure_Provider, "__set_identity_info__", new=mock_set_identity_info)
    def test_set_audit_info_azure(self):
        provider = "azure"
        arguments = {
            "profile": None,
            "role": None,
            "session_duration": None,
            "external_id": None,
            "regions": None,
            "organizations_role": None,
            "subscriptions": None,
            # We need to set exactly one auth method
            "az_cli_auth": True,
            "sp_env_auth": None,
            "browser_auth": None,
            "managed_entity_auth": None,
        }

        audit_info = set_provider_audit_info(provider, arguments)
        assert isinstance(audit_info, Azure_Audit_Info)

    @patch.object(GCP_Provider, "__set_credentials__", new=mock_set_gcp_credentials)
    @patch.object(Audit_Info, "print_gcp_credentials", new=mock_print_audit_credentials)
    def test_set_audit_info_gcp(self):
        provider = "gcp"
        arguments = {
            "profile": None,
            "role": None,
            "session_duration": None,
            "external_id": None,
            "regions": None,
            "organizations_role": None,
            "subscriptions": None,
            # We need to set exactly one auth method
            "credentials_file": None,
        }

        audit_info = set_provider_audit_info(provider, arguments)
        assert isinstance(audit_info, GCP_Audit_Info)

    @mock_resourcegroupstaggingapi
    @mock_ec2
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
