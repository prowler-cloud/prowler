from argparse import Namespace

from boto3 import session
from botocore.config import Config
from moto import mock_aws

from prowler.providers.aws.aws_provider import AwsProvider
from prowler.providers.common.models import Audit_Metadata

# Root AWS Account
AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
AWS_COMMERCIAL_PARTITION = "aws"

# Commercial Regions
AWS_REGION_US_EAST_1 = "us-east-1"
AWS_REGION_US_EAST_1_AZA = "us-east-1a"
AWS_REGION_US_EAST_1_AZB = "us-east-1b"
AWS_REGION_EU_WEST_1 = "eu-west-1"
AWS_REGION_EU_WEST_1_AZA = "eu-west-1a"
AWS_REGION_EU_WEST_1_AZB = "eu-west-1b"
AWS_REGION_EU_WEST_2 = "eu-west-2"
AWS_REGION_CN_NORTHWEST_1 = "cn-northwest-1"
AWS_REGION_CN_NORTH_1 = "cn-north-1"
AWS_REGION_EU_SOUTH_2 = "eu-south-2"
AWS_REGION_EU_SOUTH_3 = "eu-south-3"
AWS_REGION_US_WEST_2 = "us-west-2"
AWS_REGION_US_EAST_2 = "us-east-2"
AWS_REGION_EU_CENTRAL_1 = "eu-central-1"


# China Regions
AWS_REGION_CHINA_NORHT_1 = "cn-north-1"

# Gov Cloud Regions
AWS_REGION_GOV_CLOUD_US_EAST_1 = "us-gov-east-1"

# Iso Regions
AWS_REGION_ISO_GLOBAL = "aws-iso-global"

# AWS Partitions
AWS_COMMERCIAL_PARTITION = "aws"
AWS_GOV_CLOUD_PARTITION = "aws-us-gov"
AWS_CHINA_PARTITION = "aws-cn"
AWS_ISO_PARTITION = "aws-iso"

# Commercial Regions
AWS_REGION_US_EAST_1 = "us-east-1"
AWS_REGION_US_EAST_1_AZA = "us-east-1a"
AWS_REGION_US_EAST_1_AZB = "us-east-1b"
AWS_REGION_EU_WEST_1 = "eu-west-1"
AWS_REGION_EU_WEST_1_AZA = "eu-west-1a"
AWS_REGION_EU_WEST_1_AZB = "eu-west-1b"
AWS_REGION_EU_WEST_2 = "eu-west-2"
AWS_REGION_CN_NORTHWEST_1 = "cn-northwest-1"
AWS_REGION_CN_NORTH_1 = "cn-north-1"
AWS_REGION_EU_SOUTH_2 = "eu-south-2"
AWS_REGION_EU_SOUTH_3 = "eu-south-3"
AWS_REGION_US_WEST_2 = "us-west-2"
AWS_REGION_US_EAST_2 = "us-east-2"
AWS_REGION_EU_CENTRAL_1 = "eu-central-1"


# China Regions
AWS_REGION_CHINA_NORHT_1 = "cn-north-1"

# Gov Cloud Regions
AWS_REGION_GOV_CLOUD_US_EAST_1 = "us-gov-east-1"

# Iso Regions
AWS_REGION_ISO_GLOBAL = "aws-iso-global"

# AWS Partitions
AWS_COMMERCIAL_PARTITION = "aws"
AWS_GOV_CLOUD_PARTITION = "aws-us-gov"
AWS_CHINA_PARTITION = "aws-cn"
AWS_ISO_PARTITION = "aws-iso"


# Mocked AWS Provider
# This here causes to call this function mocking the AWS calls
@mock_aws
def set_mocked_aws_audit_info(
    # def set_mocked_aws_provider(
    audited_regions: list[str] = [],
    audited_account: str = AWS_ACCOUNT_NUMBER,
    audited_account_arn: str = AWS_ACCOUNT_ARN,
    audited_partition: str = AWS_COMMERCIAL_PARTITION,
    expected_checks: list[str] = [],
    profile_region: str = None,
    audit_config: dict = {},
    ignore_unused_services: bool = False,
    # assumed_role_info: AWSAssumeRole = None,
    audit_session: session.Session = session.Session(
        profile_name=None,
        botocore_session=None,
    ),
    original_session: session.Session = None,
    enabled_regions: set = None,
) -> AwsProvider:
    # Create default AWS Provider
    provider = AwsProvider(Namespace())
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
    provider._ignore_unused_services = ignore_unused_services
    provider._enabled_regions = (
        enabled_regions if enabled_regions else set(audited_regions)
    )
    # TODO: we can create the organizations metadata here with moto
    provider._organizations_metadata = None
    provider._audit_resources = []
    provider._audit_config = audit_config
    provider.audit_metadata = Audit_Metadata(
        services_scanned=0,
        expected_checks=expected_checks,
        completed_checks=0,
        audit_progress=0,
    )

    return provider
