from dataclasses import dataclass
from datetime import datetime

from boto3.session import Session
from botocore.config import Config


@dataclass
class AWSOrganizationsInfo:
    account_details_email: str
    account_details_name: str
    account_details_arn: str
    account_details_org: str
    account_details_tags: str


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
class AWSAssumeRoleConfiguration:
    assumed_role_info: AWSAssumeRole
    assumed_role_credentials: AWSCredentials


@dataclass
class AWSIdentityInfo:
    account: str
    account_arn: str
    user_id: str
    partition: str
    identity_arn: str
    profile: str
    profile_region: str
    audited_regions: list


@dataclass
class AWSSession:
    session: Session
    session_config: Config
    original_session: None
