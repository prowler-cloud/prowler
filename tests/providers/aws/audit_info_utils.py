from boto3 import session

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_REGION_US_EAST_1 = "us-east-1"
AWS_REGION_EU_WEST_1 = "eu-west-1"
AWS_PARTITION = "aws"
AWS_ACCOUNT_NUMBER = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"


# Mocked AWS Audit Info
def set_mocked_aws_audit_info(
    audited_regions: [str] = [],
    audited_account: str = AWS_ACCOUNT_NUMBER,
    audited_account_arn: str = AWS_ACCOUNT_ARN,
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
        profile_region=None,
        credentials=None,
        assumed_role_info=None,
        audited_regions=audited_regions,
        organizations_metadata=None,
        audit_resources=None,
        mfa_enabled=False,
        audit_metadata=Audit_Metadata(
            services_scanned=0,
            expected_checks=[],
            completed_checks=0,
            audit_progress=0,
        ),
    )
    return audit_info
