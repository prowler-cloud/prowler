from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from boto3.session import Session
from botocore.config import Config

from prowler.config.config import output_file_timestamp
from prowler.providers.aws.config import AWS_STS_GLOBAL_ENDPOINT_REGION
from prowler.providers.aws.lib.arn.models import ARN
from prowler.providers.common.models import ProviderOutputOptions


@dataclass
class AWSOrganizationsInfo:
    account_email: str
    account_name: str
    organization_account_arn: str
    organization_arn: str
    organization_id: str
    account_tags: list[str]


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
    sts_region: str = AWS_STS_GLOBAL_ENDPOINT_REGION


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


@dataclass
class AWSCallerIdentity:
    user_id: str
    account: str
    arn: ARN
    region: str


@dataclass
class AWSMFAInfo:
    arn: str
    totp: str


class Partition(str, Enum):
    """
    Enum class representing different AWS partitions.

    Attributes:
        aws (str): Represents the standard AWS commercial regions.
        aws_cn (str): Represents the AWS China regions.
        aws_us_gov (str): Represents the AWS GovCloud (US) Regions.
        aws_iso (str): Represents the AWS ISO (US) Regions.
        aws_iso_b (str): Represents the AWS ISOB (US) Regions.
        aws_iso_e (str): Represents the AWS ISOE (Europe) Regions.
        aws_iso_f (str): Represents the AWS ISOF Regions.
    """

    aws = "aws"
    aws_cn = "aws-cn"
    aws_us_gov = "aws-us-gov"
    aws_iso = "aws-iso"
    aws_iso_b = "aws-iso-b"
    aws_iso_e = "aws-iso-e"
    aws_iso_f = "aws-iso-f"


class AWSOutputOptions(ProviderOutputOptions):
    security_hub_enabled: bool

    def __init__(self, arguments, bulk_checks_metadata, identity):
        # First call Provider_Output_Options init
        super().__init__(arguments, bulk_checks_metadata)

        # Check if custom output filename was input, if not, set the default
        if (
            not hasattr(arguments, "output_filename")
            or arguments.output_filename is None
        ):
            self.output_filename = (
                f"prowler-output-{identity.account}-{output_file_timestamp}"
            )
        else:
            self.output_filename = arguments.output_filename

        # Security Hub Outputs
        self.security_hub_enabled = arguments.security_hub
        self.send_sh_only_fails = arguments.send_sh_only_fails
        if arguments.security_hub:
            if not self.output_modes:
                self.output_modes = ["json-asff"]
            else:
                self.output_modes.append("json-asff")
