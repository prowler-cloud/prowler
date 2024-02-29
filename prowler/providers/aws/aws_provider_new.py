import os
import pathlib
import sys
from argparse import Namespace
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

from boto3 import client, session
from botocore.config import Config
from botocore.credentials import RefreshableCredentials
from botocore.session import get_session
from colorama import Fore, Style

from prowler.config.config import aws_services_json_file
from prowler.lib.check.check import list_modules, recover_checks_from_service
from prowler.lib.logger import logger
from prowler.lib.utils.utils import open_file, parse_json_file
from prowler.providers.aws.config import (
    AWS_STS_GLOBAL_ENDPOINT_REGION,
    BOTO3_USER_AGENT_EXTRA,
)
from prowler.providers.aws.lib.arn.arn import parse_iam_credentials_arn
from prowler.providers.aws.lib.credentials.credentials import (
    create_sts_session,
    validate_AWSCredentials,
)
from prowler.providers.aws.lib.organizations.organizations import (
    get_organizations_metadata,
)
from prowler.providers.common.provider import Provider


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
    session: session.Session
    session_config: Config
    original_session: None


class AwsProvider(Provider):
    session: AWSSession = AWSSession(
        session=None, session_config=None, original_session=None
    )
    identity: AWSIdentityInfo = AWSIdentityInfo(
        account=None,
        account_arn=None,
        user_id=None,
        partition=None,
        identity_arn=None,
        profile=None,
        profile_region=None,
        audited_regions=[],
    )
    assumed_role: AWSAssumeRoleConfiguration = AWSAssumeRoleConfiguration(
        assumed_role_info=AWSAssumeRole(
            role_arn=None,
            session_duration=None,
            external_id=None,
            mfa_enabled=False,
        ),
        assumed_role_credentials=AWSCredentials(
            aws_access_key_id=None,
            aws_session_token=None,
            aws_secret_access_key=None,
            expiration=None,
        ),
    )
    organizations_metadata: AWSOrganizationsInfo = AWSOrganizationsInfo(
        account_details_email=None,
        account_details_name=None,
        account_details_arn=None,
        account_details_org=None,
        account_details_tags=None,
    )
    audit_resources: Optional[Any]
    audit_metadata: Optional[Any]
    audit_config: dict = {}
    mfa_enabled: bool = False
    ignore_unused_services: bool = False

    def __init__(self, arguments: Namespace):
        logger.info("Setting AWS provider ...")
        # Parse input arguments
        # Assume Role Options
        input_role = getattr(arguments, "role", None)
        input_session_duration = getattr(arguments, "session_duration", None)
        input_external_id = getattr(arguments, "external_id", None)

        # STS Endpoint Region
        sts_endpoint_region = getattr(arguments, "sts_endpoint_region", None)

        # MFA Configuration (false by default)
        input_mfa = getattr(arguments, "mfa", None)

        input_profile = getattr(arguments, "profile", None)
        input_regions = getattr(arguments, "region", None)
        organizations_role_arn = getattr(arguments, "organizations_role", None)

        # Set the maximum retries for the standard retrier config
        aws_retries_max_attempts = getattr(arguments, "aws_retries_max_attempts", None)

        # Set if unused services must be ignored
        ignore_unused_services = getattr(arguments, "ignore_unused_services", None)

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
        caller_identity = validate_AWSCredentials(
            self.session.session, input_regions, sts_endpoint_region
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

        if not getattr(arguments, "only_logs", None):
            self.print_credentials()

        # Parse Scan Tags
        if getattr(arguments, "resource_tags", None):
            input_resource_tags = arguments.resource_tags
            self.audit_resources = self.get_tagged_resources(input_resource_tags)

        # Parse Input Resource ARNs
        self.audit_resources = getattr(arguments, "resource_arn", None)

    def setup_session(self, input_mfa: bool):
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
    ):
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
            self.assumed_role.assumed_role_credentials = AWSCredentials(
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
            # From botocore we can use RefreshableCredentials class, which has an attribute (refresh_using)
            # that needs to be a method without arguments that retrieves a new set of fresh credentials
            # asuming the role again. -> https://github.com/boto/botocore/blob/098cc255f81a25b852e1ecdeb7adebd94c7b1b73/botocore/credentials.py#L395
            assumed_refreshable_credentials = RefreshableCredentials(
                access_key=self.assumed_role.assumed_role_credentials.aws_access_key_id,
                secret_key=self.assumed_role.assumed_role_credentials.aws_secret_access_key,
                token=self.assumed_role.assumed_role_credentials.aws_session_token,
                expiry_time=self.assumed_role.assumed_role_credentials.expiration,
                refresh_using=self.refresh_credentials,
                method="sts-assume-role",
            )
            # Here we need the botocore session since it needs to use refreshable credentials
            assumed_botocore_session = get_session()
            assumed_botocore_session._credentials = assumed_refreshable_credentials
            assumed_botocore_session.set_config_variable(
                "region", self.identity.profile_region
            )
            return session.Session(
                profile_name=self.identity.profile,
                botocore_session=assumed_botocore_session,
            )

    # Refresh credentials method using assume role
    # This method is called "adding ()" to the name, so it cannot accept arguments
    # https://github.com/boto/botocore/blob/098cc255f81a25b852e1ecdeb7adebd94c7b1b73/botocore/credentials.py#L570
    def refresh_credentials(self):
        logger.info("Refreshing assumed credentials...")

        response = self.__assume_role__(self.aws_session, self.role_info)
        refreshed_credentials = dict(
            # Keys of the dict has to be the same as those that are being searched in the parent class
            # https://github.com/boto/botocore/blob/098cc255f81a25b852e1ecdeb7adebd94c7b1b73/botocore/credentials.py#L609
            access_key=response["Credentials"]["AccessKeyId"],
            secret_key=response["Credentials"]["SecretAccessKey"],
            token=response["Credentials"]["SessionToken"],
            expiry_time=response["Credentials"]["Expiration"].isoformat(),
        )
        logger.info("Refreshed Credentials:")
        logger.info(refreshed_credentials)
        return refreshed_credentials

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
Caller Identity ARN: {Fore.YELLOW}[{self.identity.identity_arn}]{Style.RESET_ALL}
"""
        # If -A is set, print Assumed Role ARN
        if self.assumed_role.assumed_role_info.role_arn is not None:
            report += f"""Assumed Role ARN: {Fore.YELLOW}[{self.assumed_role.assumed_role_info.role_arn}]{Style.RESET_ALL}
        """
        print(report)

    def generate_regional_clients(
        self, service: str, global_service: bool = False
    ) -> dict:
        try:
            regional_clients = {}
            service_regions = self.get_available_aws_service_regions(service)
            # Check if it is global service to gather only one region
            if global_service:
                if service_regions:
                    if self.identity.profile_region in service_regions:
                        service_regions = [self.identity.profile_region]
                    service_regions = service_regions[:1]
            for region in service_regions:
                regional_client = self.session.session.client(
                    service, region_name=region, config=self.session.session_config
                )
                regional_client.region = region
                regional_clients[region] = regional_client
            return regional_clients
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def get_available_aws_service_regions(self, service: str) -> list:
        # Get json locally
        actual_directory = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
        with open_file(f"{actual_directory}/{aws_services_json_file}") as f:
            data = parse_json_file(f)
        # Check if it is a subservice
        json_regions = data["services"][service]["regions"][self.identity.partition]
        if (
            self.identity.audited_regions
        ):  # Check for input aws audit_info.audited_regions
            regions = list(
                set(json_regions).intersection(self.identity.audited_regions)
            )  # Get common regions between input and json
        else:  # Get all regions from json of the service and partition
            regions = json_regions
        return regions

    def get_aws_available_regions():
        try:
            actual_directory = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
            with open_file(f"{actual_directory}/{aws_services_json_file}") as f:
                data = parse_json_file(f)

            regions = set()
            for service in data["services"].values():
                for partition in service["regions"]:
                    for item in service["regions"][partition]:
                        regions.add(item)
            return list(regions)
        except Exception as error:
            logger.error(f"{error.__class__.__name__}: {error}")
            return []

    def get_checks_from_input_arn(audit_resources: list, provider: str) -> set:
        """get_checks_from_input_arn gets the list of checks from the input arns"""
        checks_from_arn = set()
        is_subservice_in_checks = False
        # Handle if there are audit resources so only their services are executed
        if audit_resources:
            services_without_subservices = ["guardduty", "kms", "s3", "elb", "efs"]
            service_list = set()
            sub_service_list = set()
            for resource in audit_resources:
                service = resource.split(":")[2]
                sub_service = resource.split(":")[5].split("/")[0].replace("-", "_")
                # WAF Services does not have checks
                if service != "wafv2" and service != "waf":
                    # Parse services when they are different in the ARNs
                    if service == "lambda":
                        service = "awslambda"
                    elif service == "elasticloadbalancing":
                        service = "elb"
                    elif service == "elasticfilesystem":
                        service = "efs"
                    elif service == "logs":
                        service = "cloudwatch"
                    # Check if Prowler has checks in service
                    try:
                        list_modules(provider, service)
                    except ModuleNotFoundError:
                        # Service is not supported
                        pass
                    else:
                        service_list.add(service)

                    # Get subservices to execute only applicable checks
                    if service not in services_without_subservices:
                        # Parse some specific subservices
                        if service == "ec2":
                            if sub_service == "security_group":
                                sub_service = "securitygroup"
                            if sub_service == "network_acl":
                                sub_service = "networkacl"
                            if sub_service == "image":
                                sub_service = "ami"
                        if service == "rds":
                            if sub_service == "cluster_snapshot":
                                sub_service = "snapshot"
                        sub_service_list.add(sub_service)
                    else:
                        sub_service_list.add(service)
            checks = recover_checks_from_service(service_list, provider)

            # Filter only checks with audited subservices
            for check in checks:
                if any(sub_service in check for sub_service in sub_service_list):
                    if not (sub_service == "policy" and "password_policy" in check):
                        checks_from_arn.add(check)
                        is_subservice_in_checks = True

            if not is_subservice_in_checks:
                checks_from_arn = checks

        # Return final checks list
        return sorted(checks_from_arn)

    def get_regions_from_audit_resources(audit_resources: list) -> set:
        """get_regions_from_audit_resources gets the regions from the audit resources arns"""
        audited_regions = set()
        for resource in audit_resources:
            region = resource.split(":")[3]
            if region:
                audited_regions.add(region)
        return audited_regions

    def get_tagged_resources(self, input_resource_tags: list):
        """
        get_tagged_resources returns a list of the resources that are going to be scanned based on the given input tags
        """
        try:
            resource_tags = []
            tagged_resources = []
            for tag in input_resource_tags:
                key = tag.split("=")[0]
                value = tag.split("=")[1]
                resource_tags.append({"Key": key, "Values": [value]})
            # Get Resources with resource_tags for all regions
            for regional_client in self.generate_regional_clients(
                "resourcegroupstaggingapi"
            ).values():
                try:
                    get_resources_paginator = regional_client.get_paginator(
                        "get_resources"
                    )
                    for page in get_resources_paginator.paginate(
                        TagFilters=resource_tags
                    ):
                        for resource in page["ResourceTagMappingList"]:
                            tagged_resources.append(resource["ResourceARN"])
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            sys.exit(1)
        else:
            return tagged_resources

    def get_default_region(self, service: str) -> str:
        """get_default_region gets the default region based on the profile and audited service regions"""
        service_regions = self.get_available_aws_service_regions(service)
        default_region = (
            self.get_global_region()
        )  # global region of the partition when all regions are audited and there is no profile region
        if self.identity.profile_region in service_regions:
            # return profile region only if it is audited
            default_region = self.identity.profile_region
        # return first audited region if specific regions are audited
        elif self.identity.audited_regions:
            default_region = self.identity.audited_regions[0]
        return default_region

    def get_global_region(self) -> str:
        """get_global_region gets the global region based on the audited partition"""
        global_region = "us-east-1"
        if self.identity.partition == "aws-cn":
            global_region = "cn-north-1"
        elif self.identity.partition == "aws-us-gov":
            global_region = "us-gov-east-1"
        elif "aws-iso" in self.identity.partition:
            global_region = "aws-iso-global"
        return global_region

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
        session,
        sts_endpoint_region: str,
    ) -> dict:
        try:
            assume_role_arguments = {
                "RoleArn": self.assumed_role.assumed_role_info.role_arn,
                "RoleSessionName": "ProwlerAsessmentSession",
                "DurationSeconds": self.assumed_role.assumed_role_info.session_duration,
            }

            # Set the info to assume the role from the partition, account and role name
            if self.assumed_role.assumed_role_info.external_id:
                assume_role_arguments["ExternalId"] = (
                    self.assumed_role.assumed_role_info.external_id
                )

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
