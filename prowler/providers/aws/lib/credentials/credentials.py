import sys

from boto3 import session
from colorama import Fore, Style

from prowler.lib.logger import logger
from prowler.providers.aws.config import AWS_STS_GLOBAL_ENDPOINT_REGION
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info


def validate_AWSCredentials(
    session: session, input_regions: list, sts_endpoint_region: str = None
) -> dict:
    try:
        # If there is no region passed with -f/--region/--filter-region
        if input_regions is None or len(input_regions) == 0:
            # If you have a region configured in your AWS config or credentials file
            if session.region_name is not None:
                aws_region = session.region_name
            else:
                # If there is no region set passed with -f/--region
                # we use the Global STS Endpoint Region, us-east-1
                aws_region = AWS_STS_GLOBAL_ENDPOINT_REGION
        else:
            # Get the first region passed to the -f/--region
            aws_region = input_regions[0]

        validate_credentials_client = create_sts_session(session, aws_region)
        caller_identity = validate_credentials_client.get_caller_identity()
        # Include the region where the caller_identity has validated the credentials
        caller_identity["region"] = aws_region
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        sys.exit(1)
    else:
        return caller_identity


def print_AWSCredentials(audit_info: AWS_Audit_Info):
    # Beautify audited regions, set "all" if there is no filter region
    regions = (
        ", ".join(audit_info.audited_regions)
        if audit_info.audited_regions is not None
        else "all"
    )
    # Beautify audited profile, set "default" if there is no profile set
    profile = audit_info.profile if audit_info.profile is not None else "default"

    report = f"""
This report is being generated using credentials below:

AWS-CLI Profile: {Fore.YELLOW}[{profile}]{Style.RESET_ALL} AWS Filter Region: {Fore.YELLOW}[{regions}]{Style.RESET_ALL}
AWS Account: {Fore.YELLOW}[{audit_info.audited_account}]{Style.RESET_ALL} UserId: {Fore.YELLOW}[{audit_info.audited_user_id}]{Style.RESET_ALL}
Caller Identity ARN: {Fore.YELLOW}[{audit_info.audited_identity_arn}]{Style.RESET_ALL}
"""
    # If -A is set, print Assumed Role ARN
    if audit_info.assumed_role_info.role_arn is not None:
        report += f"""Assumed Role ARN: {Fore.YELLOW}[{audit_info.assumed_role_info.role_arn}]{Style.RESET_ALL}
"""
    print(report)


def create_sts_session(
    session: session.Session, aws_region: str
) -> session.Session.client:
    return session.client(
        "sts", aws_region, endpoint_url=f"https://sts.{aws_region}.amazonaws.com"
    )
