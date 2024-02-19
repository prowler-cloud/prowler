from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from boto3 import session
from botocore.config import Config


@dataclass
class AWSCredentials:
    aws_access_key_id: str
    aws_session_token: str
    aws_secret_access_key: str
    expiration: datetime


@dataclass
class AWSAssumeRole:
    role_arn: str
    session_duration: int
    external_id: str
    mfa_enabled: bool


@dataclass
class AWSOrganizationsInfo:
    account_details_email: str
    account_details_name: str
    account_details_arn: str
    account_details_org: str
    account_details_tags: str


@dataclass
class AWS_Audit_Info:
    original_session: session.Session
    audit_session: session.Session
    # https://boto3.amazonaws.com/v1/documentation/api/latest/guide/retries.html
    session_config: Config
    audited_account: int
    audited_account_arn: str
    audited_identity_arn: str
    audited_user_id: str
    audited_partition: str
    profile: str
    profile_region: str
    credentials: AWSCredentials
    mfa_enabled: bool
    assumed_role_info: AWSAssumeRole
    audited_regions: list
    audit_resources: list
    organizations_metadata: AWSOrganizationsInfo
    audit_metadata: Optional[Any]
    audit_config: Optional[dict] = None
    ignore_unused_services: bool = False
