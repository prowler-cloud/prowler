from dataclasses import dataclass
from datetime import datetime

from boto3.session import Session
from botocore.config import Config

from prowler.providers.aws.lib.arn.models import ARN


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
class AWSAssumeRoleInfo:
    role_arn: ARN
    session_duration: int
    external_id: str
    mfa_enabled: bool
    role_session_name: str


@dataclass
class AWSAssumeRoleConfiguration:
    info: AWSAssumeRoleInfo
    credentials: AWSCredentials


@dataclass
class AWSIdentityInfo:
    account: str
    account_arn: str
    user_id: str
    partition: str
    identity_arn: str
    profile: str
    profile_region: str
    audited_regions: set


@dataclass
class AWSSession:
    """
    AWSSession stores the AWS session's configuration. We store the original_session in the case we need to setup a new one with different credentials and the restore to the original one.

    """

    current_session: Session
    original_session: Session
    session_config: Config
