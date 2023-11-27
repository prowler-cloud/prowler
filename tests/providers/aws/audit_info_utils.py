from boto3 import session

from prowler.providers.aws.lib.audit_info.models import AWS_Assume_Role, AWS_Audit_Info
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
AWS_REGION_US_WEST_2 = "us-west-2"
AWS_REGION_US_EAST_2 = "us-east-2"

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


# Mocked AWS Audit Info
def set_mocked_aws_audit_info(
    audited_regions: [str] = [],
    audited_account: str = AWS_ACCOUNT_NUMBER,
    audited_account_arn: str = AWS_ACCOUNT_ARN,
    audited_partition: str = AWS_COMMERCIAL_PARTITION,
    expected_checks: [str] = [],
    profile_region: str = None,
    audit_config: dict = {},
    ignore_unused_services: bool = False,
    assumed_role_info: AWS_Assume_Role = None,
    audit_session: session.Session = session.Session(
        profile_name=None,
        botocore_session=None,
    ),
    original_session: session.Session = None,
    enabled_regions: set = None,
):
    audit_info = AWS_Audit_Info(
        session_config=None,
        original_session=original_session,
        audit_session=audit_session,
        audited_account=audited_account,
        audited_account_arn=audited_account_arn,
        audited_user_id=None,
        audited_partition=audited_partition,
        audited_identity_arn=None,
        profile=None,
        profile_region=profile_region,
        credentials=None,
        assumed_role_info=assumed_role_info,
        audited_regions=audited_regions,
        organizations_metadata=None,
        audit_resources=[],
        mfa_enabled=False,
        audit_metadata=Audit_Metadata(
            services_scanned=0,
            expected_checks=expected_checks,
            completed_checks=0,
            audit_progress=0,
        ),
        audit_config=audit_config,
        ignore_unused_services=ignore_unused_services,
        enabled_regions=enabled_regions if enabled_regions else set(audited_regions),
    )
    return audit_info
