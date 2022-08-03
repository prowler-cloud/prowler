from dataclasses import dataclass
from datetime import datetime

from boto3 import session


@dataclass
class AWS_Credentials:
    aws_access_key_id: str
    aws_session_token: str
    aws_secret_access_key: str
    expiration: datetime


@dataclass
class AWS_Assume_Role:
    role_arn: str
    session_duration: int
    external_id: str


@dataclass
class AWS_Organizations_Info:
    account_details_email: str
    account_details_name: str
    account_details_arn: str
    account_details_org: str
    account_details_tags: str


@dataclass
class AWS_Audit_Info:
    original_session: session.Session
    audit_session: session.Session
    audited_account: int
    audited_identity_arn: str
    audited_user_id: str
    audited_partition: str
    profile: str
    profile_region: str
    credentials: AWS_Credentials
    assumed_role_info: AWS_Assume_Role
    audited_regions: list
    organizations_metadata: AWS_Organizations_Info
