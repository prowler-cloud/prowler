import sys
from datetime import datetime
from typing import Any, Optional

from boto3 import client, session
from botocore.config import Config
from colorama import Fore, Style
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.aws.config import (
    AWS_STS_GLOBAL_ENDPOINT_REGION,
    BOTO3_USER_AGENT_EXTRA,
)
from prowler.providers.aws.lib.arn.arn import parse_iam_credentials_arn
from prowler.providers.aws.lib.credentials.credentials import (
    create_sts_session,
    validate_aws_credentials,
)
from prowler.providers.aws.lib.organizations.organizations import (
    get_organizations_metadata,
)
from prowler.providers.aws.lib.resource_api_tagging.resource_api_tagging import (
    get_tagged_resources,
)
from prowler.providers.common.provider import CloudProvider


class AWS_Organizations_Info(BaseModel):
    account_details_email: str
    account_details_name: str
    account_details_arn: str
    account_details_org: str
    account_details_tags: str


class AWS_Credentials(BaseModel):
    aws_access_key_id: str
    aws_session_token: str
    aws_secret_access_key: str
    expiration: datetime


class AWS_Assume_Role(BaseModel):
    role_arn: str = None
    session_duration: int = None
    external_id: str = None
    mfa_enabled: bool = None


class AWSAssumeRoleConfiguration(BaseModel):
    assumed_role_info: AWS_Assume_Role
    assumed_role_credentials: AWS_Credentials


class AWSIdentityInfo(BaseModel):
    account: str = (None,)
    account_arn: str = (None,)
    user_id: str = (None,)
    partition: str = (None,)
    identity_arn: str = (None,)
    profile: str = (None,)
    profile_region: str = (None,)
    audited_regions: list = ([],)


class AWSSession(BaseModel):
    session: session.Session
    session_config: Config
    original_session: None


class AWSAuditConfig(BaseModel):
    mfa_enabled: bool = False
    ignore_unused_services: bool = False


class AWSProvider(CloudProvider):
    session: AWSSession
    identity: AWSIdentityInfo
    assumed_role: AWSAssumeRoleConfiguration
    organizations_metadata: AWS_Organizations_Info
    audit_resources: Optional[Any]
    audit_metadata: Optional[Any]
    audit_config: dict
    mfa_enabled: bool = False
    ignore_unused_services: bool = False

    def __init__(self, arguments):
        logger.info("Setting AWS provider ...")
        # Parse input arguments
        # Assume Role Options
        input_role = arguments.get("role")
        input_session_duration = arguments.get("session_duration")
        input_external_id = arguments.get("external_id")

        # STS Endpoint Region
        sts_endpoint_region = arguments.get("sts_endpoint_region")

        # MFA Configuration (false by default)
        input_mfa = arguments.get("mfa")

        input_profile = arguments.get("profile")
        input_regions = arguments.get("region")
        organizations_role_arn = arguments.get("organizations_role")

        # Set the maximum retries for the standard retrier config
        aws_retries_max_attempts = arguments.get("aws_retries_max_attempts")

        # Set if unused services must be ignored
        ignore_unused_services = arguments.get("ignore_unused_services")

        # Set the maximum retries for the standard retrier config
        self.session.session_config = self.__set_session_config__(
            aws_retries_max_attempts
        )

        # Set ignore unused services
        self.ignore_unused_services = ignore_unused_services

        # Start populating AWS identity object
        self.identity.profile = input_profile
        self.identity.audited_regions = input_regions

        # We need to create an original sessions using regular auth path (creds, profile, etc)
        logger.info("Generating original session ...")
        self.session.session = self.setup_session(input_mfa)

        # After the session is created, validate it
        logger.info("Validating credentials ...")
        caller_identity = validate_aws_credentials(
            self.session, input_regions, sts_endpoint_region
        )

        logger.info("Credentials validated")
        logger.info(f"Original caller identity UserId: {caller_identity['UserId']}")
        logger.info(f"Original caller identity ARN: {caller_identity['Arn']}")
        # Set values of AWS identity object
        self.identity.account = caller_identity["Account"]
        self.identity.identity_arn = caller_identity["Arn"]
        self.identity.user_id = caller_identity["UserId"]
        self.identity.partition = parse_iam_credentials_arn(
            caller_identity["Arn"]
        ).partition
        self.identity.account_arn = (
            f"arn:{self.identity.partition}:iam::{self.identity.account}:root"
        )

        # save original session
        self.session.original_session = self.session.session
        # time for checking role assumption
        if input_role:
            # session will be the assumed one
            self.session.session = self.setup_assumed_session(
                input_role,
                input_external_id,
                input_mfa,
                input_session_duration,
                sts_endpoint_region,
            )
            logger.info("Audit session is the new session created assuming role")
        # check if organizations info is gonna be retrieved
        if organizations_role_arn:
            logger.info(
                f"Getting organizations metadata for account {organizations_role_arn}"
            )
            # session will be the assumed one with organizations permissions
            self.session.session = self.setup_assumed_session(
                organizations_role_arn,
                input_external_id,
                input_mfa,
                input_session_duration,
                sts_endpoint_region,
            )
            self.organizations_metadata = get_organizations_metadata(
                self.identity.account, self.assumed_role.assumed_role_credentials
            )
            logger.info("Organizations metadata retrieved")
        if self.session.session.region_name:
            self.identity.profile_region = self.session.session.region_name
        else:
            self.identity.profile_region = "us-east-1"

        if not arguments.get("only_logs"):
            self.print_credentials()

        # Parse Scan Tags
        if arguments.get("resource_tags"):
            input_resource_tags = arguments.get("resource_tags")
            self.audit_resources = get_tagged_resources(
                input_resource_tags, current_audit_info
            )

        # Parse Input Resource ARNs
        if arguments.get("resource_arn"):
            current_audit_info.audit_resources = arguments.get("resource_arn")

    def setup_session(self, input_mfa: bool) -> session.Session:
        logger.info("Creating regular session ...")
        # Input MFA only if a role is not going to be assumed
        if input_mfa and not self.assumed_role.assumed_role_info.role_arn:
            mfa_ARN, mfa_TOTP = self.__input_role_mfa_token_and_code__()
            get_session_token_arguments = {
                "SerialNumber": mfa_ARN,
                "TokenCode": mfa_TOTP,
            }
            sts_client = client("sts")
            session_credentials = sts_client.get_session_token(
                **get_session_token_arguments
            )
            return session.Session(
                aws_access_key_id=session_credentials["Credentials"]["AccessKeyId"],
                aws_secret_access_key=session_credentials["Credentials"][
                    "SecretAccessKey"
                ],
                aws_session_token=session_credentials["Credentials"]["SessionToken"],
                profile_name=self.identity.profile,
            )
        else:
            return session.Session(
                profile_name=self.identity.profile,
            )

    def setup_assumed_session(
        self,
        input_role: str,
        input_external_id: str,
        input_mfa: str,
        session_duration: int,
        sts_endpoint_region: str,
    ) -> session.Session:
        logger.info("Creating assumed session ...")
        # store information about the role is gonna be assumed
        self.assumed_role.assumed_role_info.role_arn = input_role
        self.assumed_role.assumed_role_info.session_duration = session_duration
        self.assumed_role.assumed_role_info.external_id = input_external_id
        self.assumed_role.assumed_role_info.mfa_enabled = input_mfa
        # Check if role arn is valid
        try:
            # this returns the arn already parsed into a dict to be used when it is needed to access its fields
            role_arn_parsed = parse_iam_credentials_arn(
                self.assumed_role.assumed_role_info.role_arn
            )

        except Exception as error:
            logger.critical(f"{error.__class__.__name__} -- {error}")
            sys.exit(1)

        else:
            logger.info(f"Assuming role {self.assumed_role.assumed_role_info.role_arn}")
            # Assume the role
            assumed_role_response = self.__assume_role__(
                self.session.session,
                sts_endpoint_region,
            )
            logger.info("Role assumed")
            # Set the info needed to create a session with an assumed role
            self.assumed_role.assumed_role_credentials = AWS_Credentials(
                aws_access_key_id=assumed_role_response["Credentials"]["AccessKeyId"],
                aws_session_token=assumed_role_response["Credentials"]["SessionToken"],
                aws_secret_access_key=assumed_role_response["Credentials"][
                    "SecretAccessKey"
                ],
                expiration=assumed_role_response["Credentials"]["Expiration"],
            )
            # Set identity parameters
            self.identity.account = role_arn_parsed.account_id
            self.identity.partition = role_arn_parsed.partition
            self.identity.account_arn = (
                f"arn:{self.identity.partition}:iam::{self.identity.account}:root"
            )

            return session.Session(
                aws_access_key_id=self.assumed_role.assumed_role_credentials[
                    "Credentials"
                ]["AccessKeyId"],
                aws_secret_access_key=self.assumed_role.assumed_role_credentials[
                    "Credentials"
                ]["SecretAccessKey"],
                aws_session_token=self.assumed_role.assumed_role_credentials[
                    "Credentials"
                ]["SessionToken"],
                profile_name=self.identity.profile,
            )

    def print_credentials(self):
        # Beautify audited regions, set "all" if there is no filter region
        regions = (
            ", ".join(self.identity.audited_regions)
            if self.identity.audited_regions is not None
            else "all"
        )
        # Beautify audited profile, set "default" if there is no profile set
        profile = (
            self.identity.profile if self.identity.profile is not None else "default"
        )

        report = f"""
    This report is being generated using credentials below:

    AWS-CLI Profile: {Fore.YELLOW}[{profile}]{Style.RESET_ALL} AWS Filter Region: {Fore.YELLOW}[{regions}]{Style.RESET_ALL}
    AWS Account: {Fore.YELLOW}[{self.identity.account}]{Style.RESET_ALL} UserId: {Fore.YELLOW}[{self.identity.user_id}]{Style.RESET_ALL}
    Caller Identity ARN: {Fore.YELLOW}[{ self.identity.identity_arn}]{Style.RESET_ALL}
    """
        # If -A is set, print Assumed Role ARN
        if self.assumed_role.assumed_role_info.role_arn is not None:
            report += f"""Assumed Role ARN: {Fore.YELLOW}[{self.assumed_role.assumed_role_info.role_arn}]{Style.RESET_ALL}
    """
        print(report)

    def __input_role_mfa_token_and_code__() -> tuple[str]:
        """input_role_mfa_token_and_code ask for the AWS MFA ARN and TOTP and returns it."""
        mfa_ARN = input("Enter ARN of MFA: ")
        mfa_TOTP = input("Enter MFA code: ")
        return (mfa_ARN.strip(), mfa_TOTP.strip())

    def __set_session_config__(self, aws_retries_max_attempts: bool):
        session_config = Config(
            retries={"max_attempts": 3, "mode": "standard"},
            user_agent_extra=BOTO3_USER_AGENT_EXTRA,
        )
        if aws_retries_max_attempts:
            # Create the new config
            config = Config(
                retries={
                    "max_attempts": aws_retries_max_attempts,
                    "mode": "standard",
                },
            )
            # Merge the new configuration
            session_config = self.session.session_config.merge(config)

        return session_config

    def __assume_role__(
        self,
        session: session.Session,
        sts_endpoint_region: str = None,
    ) -> dict:
        try:
            assume_role_arguments = {
                "RoleArn": self.assumed_role.assumed_role_info.role_arn,
                "RoleSessionName": "ProwlerAsessmentSession",
                "DurationSeconds": self.assumed_role.assumed_role_info.session_duration,
            }

            # Set the info to assume the role from the partition, account and role name
            if self.assumed_role.assumed_role_info.external_id:
                assume_role_arguments[
                    "ExternalId"
                ] = self.assumed_role.assumed_role_info.external_id

            if self.assumed_role.assumed_role_info.mfa_enabled:
                mfa_ARN, mfa_TOTP = self.__input_role_mfa_token_and_code__()
                assume_role_arguments["SerialNumber"] = mfa_ARN
                assume_role_arguments["TokenCode"] = mfa_TOTP

            # Set the STS Endpoint Region
            if sts_endpoint_region is None:
                sts_endpoint_region = AWS_STS_GLOBAL_ENDPOINT_REGION

            sts_client = create_sts_session(session, sts_endpoint_region)
            assumed_credentials = sts_client.assume_role(**assume_role_arguments)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            sys.exit(1)

        else:
            return assumed_credentials
