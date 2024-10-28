from argparse import Namespace
from json import dumps

from boto3 import client, session
from botocore.config import Config
from moto import mock_aws

from prowler.config.config import (
    default_config_file_path,
    default_fixer_config_file_path,
    get_default_mute_file_path,
)
from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.common.models import Audit_Metadata

# AWS Partitions
AWS_COMMERCIAL_PARTITION = "aws"
AWS_GOV_CLOUD_PARTITION = "aws-us-gov"
AWS_CHINA_PARTITION = "aws-cn"
AWS_ISO_PARTITION = "aws-iso"

# Root AWS Account
AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:{AWS_COMMERCIAL_PARTITION}:iam::{AWS_ACCOUNT_NUMBER}:root"
AWS_GOV_CLOUD_ACCOUNT_ARN = (
    f"arn:{AWS_GOV_CLOUD_PARTITION}:iam::{AWS_ACCOUNT_NUMBER}:root"
)


# Commercial Regions
AWS_REGION_US_EAST_1 = "us-east-1"
AWS_REGION_US_EAST_1_AZA = "us-east-1a"
AWS_REGION_US_EAST_1_AZB = "us-east-1b"
AWS_REGION_EU_WEST_1 = "eu-west-1"
AWS_REGION_EU_WEST_1_AZA = "eu-west-1a"
AWS_REGION_EU_WEST_1_AZB = "eu-west-1b"
AWS_REGION_EU_WEST_2 = "eu-west-2"
AWS_REGION_EU_SOUTH_2 = "eu-south-2"
AWS_REGION_EU_SOUTH_3 = "eu-south-3"
AWS_REGION_US_WEST_2 = "us-west-2"
AWS_REGION_US_EAST_2 = "us-east-2"
AWS_REGION_EU_CENTRAL_1 = "eu-central-1"


# China Regions
AWS_REGION_CN_NORTHWEST_1 = "cn-northwest-1"
AWS_REGION_CN_NORTH_1 = "cn-north-1"

# Gov Cloud Regions
AWS_REGION_GOV_CLOUD_US_EAST_1 = "us-gov-east-1"

# Iso Regions
AWS_REGION_ISO_GLOBAL = "aws-iso-global"

# EC2
EXAMPLE_AMI_ID = "ami-12c6146b"

# Lightsail
BASE_LIGHTSAIL_ARN = f"arn:aws:lightsail:{AWS_REGION_US_EAST_1}:0000000000000:"


# Administrator Policy
ADMINISTRATOR_POLICY_NAME = "AdministratorPolicy"
ADMINISTRATOR_POLICY_DOCUMENT = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "*",
            ],
            "Resource": "*",
        },
    ],
}

# Administrator Role
ADMINISTRATOR_ROLE_NAME = "AdministratorRole"
ADMINISTRATOR_ROLE_ASSUME_ROLE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"},
            "Action": "sts:AssumeRole",
        }
    ],
}


# Mocked AWS Provider
# This here causes to call this function mocking the AWS calls
@mock_aws
def set_mocked_aws_provider(
    audited_regions: list[str] = [],
    audited_account: str = AWS_ACCOUNT_NUMBER,
    audited_account_arn: str = AWS_ACCOUNT_ARN,
    audited_partition: str = AWS_COMMERCIAL_PARTITION,
    expected_checks: list[str] = [],
    profile_region: str = None,
    audit_config: dict = {},
    fixer_config: dict = {},
    mutelist: dict = None,
    scan_unused_services: bool = True,
    audit_session: session.Session = session.Session(
        profile_name=None,
        botocore_session=None,
    ),
    original_session: session.Session = None,
    enabled_regions: set = None,
    arguments: Namespace = Namespace(),
    status: list[str] = [],
    create_default_organization: bool = True,
) -> AwsProvider:
    if create_default_organization:
        # Create default AWS Organization
        create_default_aws_organization()

    # Default arguments
    arguments = set_default_provider_arguments(arguments, status)

    # AWS Provider
    provider = AwsProvider()

    # Mock Session
    provider._session.session_config = None
    provider._session.original_session = original_session
    provider._session.current_session = audit_session
    provider._session.session_config = Config()
    # Mock Identity
    provider._identity.account = audited_account
    provider._identity.account_arn = audited_account_arn
    provider._identity.user_id = None
    provider._identity.partition = audited_partition
    provider._identity.identity_arn = None
    provider._identity.profile = None
    provider._identity.profile_region = profile_region
    provider._identity.audited_regions = audited_regions
    # Mock Configiration
    provider._scan_unused_services = scan_unused_services
    provider._enabled_regions = (
        enabled_regions if enabled_regions else set(audited_regions)
    )
    # TODO: we can create the organizations metadata here with moto
    provider._organizations_metadata = None
    provider._audit_resources = []
    provider._audit_config = audit_config
    provider._fixer_config = fixer_config
    provider._mutelist = mutelist
    provider.audit_metadata = Audit_Metadata(
        services_scanned=0,
        expected_checks=expected_checks,
        completed_checks=0,
        audit_progress=0,
    )

    return provider


def set_default_provider_arguments(
    arguments: Namespace, status: list = []
) -> Namespace:
    arguments.status = status
    arguments.output_formats = []
    arguments.output_directory = ""
    arguments.verbose = False
    arguments.only_logs = False
    arguments.unix_timestamp = False
    arguments.shodan = None
    arguments.security_hub = False
    arguments.send_sh_only_fails = False
    arguments.config_file = default_config_file_path
    arguments.fixer_config = default_fixer_config_file_path
    arguments.mutelist_file = get_default_mute_file_path("aws")

    return arguments


@mock_aws
def create_default_aws_organization():
    # Create default AWS Organization
    organizations_client = client("organizations", region_name=AWS_REGION_US_EAST_1)

    mockname = "mock-account"
    mockdomain = "moto-example.org"
    mockemail = "@".join([mockname, mockdomain])

    _ = organizations_client.create_organization(FeatureSet="ALL")["Organization"]["Id"]
    account_id = organizations_client.create_account(
        AccountName=mockname, Email=mockemail
    )["CreateAccountStatus"]["AccountId"]

    _ = organizations_client.tag_resource(
        ResourceId=account_id, Tags=[{"Key": "test", "Value": "aws-provider"}]
    )


def create_role(
    region: str,
    policy_name: str = ADMINISTRATOR_POLICY_NAME,
    policy_document: dict = ADMINISTRATOR_POLICY_DOCUMENT,
    role_name: str = ADMINISTRATOR_ROLE_NAME,
    assume_role_policy_document: dict = ADMINISTRATOR_ROLE_ASSUME_ROLE_POLICY,
) -> str:
    iam_client = client("iam", region_name=region)
    policy = iam_client.create_policy(
        PolicyName=policy_name,
        PolicyDocument=dumps(policy_document),
    )["Policy"]

    administrator_role = iam_client.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=dumps(assume_role_policy_document),
    )["Role"]
    iam_client.attach_role_policy(
        RoleName=role_name,
        PolicyArn=policy["Arn"],
    )
    return administrator_role["Arn"]
