from boto3 import session

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_REGION_US_EAST_1 = "us-east-1"
AWS_REGION_US_EAST_1_AZA = "us-east-1a"
AWS_REGION_US_EAST_1_AZB = "us-east-1b"
AWS_REGION_EU_WEST_1 = "eu-west-1"
AWS_REGION_EU_WEST_1_AZA = "eu-west-1a"
AWS_REGION_EU_WEST_1_AZB = "eu-west-1b"
AWS_REGION_EU_WEST_2 = "eu-west-2"
AWS_REGION_EU_SOUTH_2 = "eu-south-2"
AWS_PARTITION = "aws"
AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
AWS_COMMERCIAL_PARTITION = "aws"


# Mocked AWS Audit Info
def set_mocked_aws_audit_info(
    audited_regions: [str] = [],
    audited_account: str = AWS_ACCOUNT_NUMBER,
    audited_account_arn: str = AWS_ACCOUNT_ARN,
    expected_checks: [str] = [],
    profile_region: str = None,
    audit_config: dict = {},
):
    audit_info = AWS_Audit_Info(
        session_config=None,
        original_session=None,
        audit_session=session.Session(
            profile_name=None,
            botocore_session=None,
        ),
        audited_account=audited_account,
        audited_account_arn=audited_account_arn,
        audited_user_id=None,
        audited_partition=AWS_PARTITION,
        audited_identity_arn=None,
        profile=None,
        profile_region=profile_region,
        credentials=None,
        assumed_role_info=None,
        audited_regions=audited_regions,
        organizations_metadata=None,
        audit_resources=None,
        mfa_enabled=False,
        audit_metadata=Audit_Metadata(
            services_scanned=0,
            expected_checks=expected_checks,
            completed_checks=0,
            audit_progress=0,
        ),
        audit_config=audit_config,
    )
    return audit_info
