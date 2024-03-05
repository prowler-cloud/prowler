from dataclasses import dataclass
from datetime import datetime

from boto3.session import Session
from botocore.config import Config

from prowler.config.config import output_file_timestamp
from prowler.providers.aws.lib.arn.models import ARN
from prowler.providers.common.models import ProviderOutputOptions


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


@dataclass
class AWSCallerIdentity:
    user_id: str
    account: str
    arn: str
    region: str


@dataclass
class AWSMFAInfo:
    arn: str
    totp: str


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
