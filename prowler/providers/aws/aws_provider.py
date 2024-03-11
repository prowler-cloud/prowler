import os
import pathlib
import sys
from argparse import Namespace

from boto3 import client, session
from boto3.session import Session
from botocore.config import Config
from botocore.credentials import RefreshableCredentials
from botocore.session import get_session
from colorama import Fore, Style

from prowler.config.config import aws_services_json_file, load_and_validate_config_file
from prowler.lib.check.check import list_modules, recover_checks_from_service
from prowler.lib.logger import logger
from prowler.lib.utils.utils import open_file, parse_json_file
from prowler.providers.aws.config import (
    AWS_STS_GLOBAL_ENDPOINT_REGION,
    BOTO3_USER_AGENT_EXTRA,
    ROLE_SESSION_NAME,
)
from prowler.providers.aws.lib.arn.arn import parse_iam_credentials_arn
from prowler.providers.aws.lib.mutelist.mutelist import parse_mutelist_file
from prowler.providers.aws.lib.organizations.organizations import (
    get_organizations_metadata,
    parse_organizations_metadata,
)
from prowler.providers.aws.models import (
    AWSAssumeRoleConfiguration,
    AWSAssumeRoleInfo,
    AWSCallerIdentity,
    AWSCredentials,
    AWSIdentityInfo,
    AWSMFAInfo,
    AWSOrganizationsInfo,
    AWSOutputOptions,
    AWSSession,
)
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider


class AwsProvider(Provider):
    _type: str = "aws"
    _identity: AWSIdentityInfo
    _session: AWSSession
    _organizations_metadata: AWSOrganizationsInfo
    _audit_resources: list = []
    _audit_config: dict
    _ignore_unused_services: bool = False
    _enabled_regions: set = set()
    # TODO: enforce the mutelist for the Provider class
    _mutelist: dict = {}
    _output_options: AWSOutputOptions
    # TODO: this is not optional, enforce for all providers
    audit_metadata: Audit_Metadata

    def __init__(self, arguments: Namespace):
        logger.info("Initializing AWS provider ...")
        ######## Parse Arguments
        # Session
        aws_retries_max_attempts = getattr(arguments, "aws_retries_max_attempts", None)

        # Assume Role
        input_role = getattr(arguments, "role", None)
        input_session_duration = getattr(arguments, "session_duration", None)
        input_external_id = getattr(arguments, "external_id", None)
        input_role_session_name = getattr(arguments, "role_session_name", None)

        # MFA Configuration (false by default)
        input_mfa = getattr(arguments, "mfa", None)
        input_profile = getattr(arguments, "profile", None)
        input_regions = getattr(arguments, "region", set())
        organizations_role_arn = getattr(arguments, "organizations_role", None)

        # Set if unused services must be ignored
        ignore_unused_services = getattr(arguments, "ignore_unused_services", None)
        ########

        ######## AWS Session
        logger.info("Generating original session ...")

        # Configure the initial AWS Session using the local credentials: profile or environment variables
        aws_session = self.setup_session(input_mfa, input_profile, input_role)
        session_config = self._set_session_config(aws_retries_max_attempts)
        # Current session and the original session points to the same session object until we get a new one, if needed
        self._session = AWSSession(
            current_session=aws_session,
            session_config=session_config,
            original_session=aws_session,
        )
        ########

        ######## Validate AWS credentials
        # After the session is created, validate it
        logger.info("Validating credentials ...")
        sts_region = get_aws_region_for_sts(
            self.session.current_session.region_name, input_regions
        )

        caller_identity = validate_aws_credentials(
            self.session.current_session, sts_region
        )
        logger.info("Credentials validated")
        ########

        ######## AWS Provider Identity
        # Get profile region
        profile_region = self.get_profile_region(self._session.current_session)

        # Set identity
        self._identity = self.set_identity(
            caller_identity=caller_identity,
            input_profile=input_profile,
            input_regions=input_regions,
            profile_region=profile_region,
        )
        ########

        ######## AWS Session with Assume Role (if needed)
        if input_role:
            # Validate the input role
            valid_role_arn = parse_iam_credentials_arn(input_role)
            # Set assume IAM Role information
            assumed_role_information = self.set_assumed_role_info(
                valid_role_arn,
                input_external_id,
                input_mfa,
                input_session_duration,
                input_role_session_name,
            )
            # Assume the IAM Role
            logger.info(f"Assuming role: {assumed_role_information.role_arn.arn}")
            assumed_role_credentials = self.assume_role(
                self._session.current_session,
                assumed_role_information,
            )
            logger.info(f"IAM Role assumed: {assumed_role_information.role_arn.arn}")

            assumed_role_configuration = AWSAssumeRoleConfiguration(
                info=assumed_role_information, credentials=assumed_role_credentials
            )
            # Store the assumed role configuration since it'll be needed to refresh the credentials
            self._assumed_role_configuration = assumed_role_configuration

            # Store a new current session using the assumed IAM Role
            self._session.current_session = self.setup_assumed_session(
                assumed_role_configuration.credentials
            )
            logger.info("Audit session is the new session created assuming an IAM Role")

            # Modify identity for the IAM Role assumed since this will be the identity to audit with
            logger.info("Setting new identity for the AWS IAM Role assumed")
            self._identity.account = assumed_role_configuration.info.role_arn.account_id
            self._identity.partition = (
                assumed_role_configuration.info.role_arn.partition
            )
            self._identity.account_arn = f"arn:{assumed_role_configuration.info.role_arn.partition}:iam::{assumed_role_configuration.info.role_arn.account_id}:root"
        ########

        ######## AWS Organizations Metadata
        # This is needed in the case we don't assume an AWS Organizations IAM Role
        aws_organizations_session = self._session.original_session
        # Get a new session if the organizations_role_arn is set
        if organizations_role_arn:
            # Validate the input role
            valid_role_arn = parse_iam_credentials_arn(organizations_role_arn)
            # Set assume IAM Role information
            organizations_assumed_role_information = self.set_assumed_role_info(
                valid_role_arn,
                input_external_id,
                input_mfa,
                input_session_duration,
                input_role_session_name,
            )
            # Assume the Organizations IAM Role
            logger.info(
                f"Assuming the AWS Organizations IAM Role: {organizations_assumed_role_information.role_arn.arn}"
            )
            # Since here we can have _session.current_session with an IAM Role
            # we'll use the _session.original_session
            organizations_assumed_role_credentials = self.assume_role(
                self._session.original_session,
                organizations_assumed_role_information,
            )
            logger.info(
                f"AWS Organizations IAM Role assumed: {organizations_assumed_role_information.role_arn.arn}"
            )
            organizations_assumed_role_configuration = AWSAssumeRoleConfiguration(
                info=organizations_assumed_role_information,
                credentials=organizations_assumed_role_credentials,
            )
            # Get a new session using the AWS Organizations IAM Role assumed
            aws_organizations_session = self.setup_assumed_session(
                organizations_assumed_role_configuration.credentials
            )
            logger.info(
                "Generated new session for to get the AWS Organizations metadata"
            )

            # TODO: Do we need to modify the identity here? I think not since it is not used
            # self._identity.account = assumed_role.info.role_arn.account_id
            # self._identity.partition = assumed_role.info.role_arn.partition
            # self._identity.account_arn = f"arn:{self._identity.partition}:iam::{assumed_role.info.role_arn.account_id}:root"

        self._organizations_metadata = self.get_organizations_info(
            aws_organizations_session, self._identity.account
        )
        ########

        # Parse Scan Tags
        if getattr(arguments, "resource_tags", None):
            self._audit_resources = self.get_tagged_resources(arguments.resource_tags)

        # Parse Input Resource ARNs
        if getattr(arguments, "resource_arn", None):
            self._audit_resources = arguments.resource_arn

        # Get Enabled Regions
        self._enabled_regions = self.get_aws_enabled_regions(
            self._session.current_session
        )

        # Set ignore unused services
        self._ignore_unused_services = ignore_unused_services

        # Audit Config
        self._audit_config = {}
        if hasattr(arguments, "config_file"):
            self._audit_config = load_and_validate_config_file(
                self._type, arguments.config_file
            )

    @property
    def identity(self):
        return self._identity

    @property
    def type(self):
        return self._type

    @property
    def session(self):
        return self._session

    @property
    def organizations_metadata(self):
        return self._organizations_metadata

    @property
    def audit_resources(self):
        return self._audit_resources

    @property
    def ignore_unused_services(self):
        return self._ignore_unused_services

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def output_options(self):
        return self._output_options

    @output_options.setter
    def output_options(self, options: tuple):
        arguments, bulk_checks_metadata = options
        self._output_options = AWSOutputOptions(
            arguments, bulk_checks_metadata, self._identity
        )

    @property
    def mutelist(self):
        return self._mutelist

    @mutelist.setter
    def mutelist(self, mutelist_path):
        if mutelist_path:
            mutelist = parse_mutelist_file(
                self._session.current_session, self._identity.account, mutelist_path
            )
        else:
            mutelist = {}
        self._mutelist = mutelist

    # TODO: This can be moved to another class since it doesn't need self
    def get_organizations_info(
        self, organizations_session: Session, aws_account_id: str
    ) -> AWSOrganizationsInfo:
        """
        get_organizations_info returns a AWSOrganizationsInfo object if the account to be audited is a delegated administrator for AWS Organizations or if the AWS Organizations Role ARN (--organizations-role) is passed.

        Arguments:
        - organizations_session: needs to be a Session object with permissions to do organizations:DescribeAccount and organizations:ListTagsForResource.
        - aws_account_id: is the AWS Account ID from which we want to get the AWS Organizations account metadata

        Returns:
        - None if it is not unable to retrieve that data, and raises a logger.warning()
        """
        try:
            logger.info(
                f"Getting AWS Organizations metadata for account {aws_account_id}"
            )

            organizations_metadata, list_tags_for_resource = get_organizations_metadata(
                aws_account_id=aws_account_id,
                session=organizations_session,
            )

            if organizations_metadata:
                organizations_metadata = parse_organizations_metadata(
                    organizations_metadata, list_tags_for_resource
                )
                logger.info(
                    f"AWS Organizations metadata retrieved for account {aws_account_id}"
                )
                return organizations_metadata

        except Exception as error:
            # If the account is not a delegated administrator for AWS Organizations a credentials error will be thrown
            # Since it is a permission issue for an optional we'll raise a warning
            logger.warning(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    # TODO: This can be moved to another class since it doesn't need self
    def get_profile_region(self, session: Session):
        # TODO: read "us-east-1" from another place
        profile_region = "us-east-1"
        if session.region_name:
            profile_region = session.region_name

        return profile_region

    def set_identity(
        self,
        caller_identity: AWSCallerIdentity,
        input_profile: str,
        input_regions: set,
        profile_region: str,
    ) -> AWSIdentityInfo:
        logger.info(f"Original AWS Caller Identity UserId: {caller_identity.user_id}")
        logger.info(f"Original AWS Caller Identity ARN: {caller_identity.arn}")

        partition = parse_iam_credentials_arn(caller_identity.arn).partition

        return AWSIdentityInfo(
            account=caller_identity.account,
            account_arn=f"arn:{partition}:iam::{caller_identity.account}:root",
            user_id=caller_identity.user_id,
            partition=partition,
            identity_arn=caller_identity.arn,
            profile=input_profile,
            profile_region=profile_region,
            audited_regions=input_regions,
        )

    def setup_session(
        self, input_mfa: bool, input_profile: str, input_role: str = None
    ) -> Session:
        try:
            logger.info("Creating original session ...")
            if input_mfa and not input_role:
                mfa_info = self.__input_role_mfa_token_and_code__()
                # TODO: validate MFA ARN here
                get_session_token_arguments = {
                    "SerialNumber": mfa_info.arn,
                    "TokenCode": mfa_info.totp,
                }
                sts_client = client("sts")
                session_credentials = sts_client.get_session_token(
                    **get_session_token_arguments
                )
                return Session(
                    aws_access_key_id=session_credentials["Credentials"]["AccessKeyId"],
                    aws_secret_access_key=session_credentials["Credentials"][
                        "SecretAccessKey"
                    ],
                    aws_session_token=session_credentials["Credentials"][
                        "SessionToken"
                    ],
                    profile_name=input_profile,
                )
            else:
                return Session(
                    profile_name=input_profile,
                )
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            sys.exit(1)

    def set_assumed_role_info(
        self,
        role_arn: str,
        input_external_id: str,
        input_mfa: str,
        session_duration: int,
        role_session_name: str,
    ) -> AWSAssumeRoleInfo:
        """
        set_assumed_role_info returns a AWSAssumeRoleInfo object
        """
        logger.info("Setting assume IAM Role information ...")
        return AWSAssumeRoleInfo(
            role_arn=role_arn,
            session_duration=session_duration,
            external_id=input_external_id,
            mfa_enabled=input_mfa,
            role_session_name=role_session_name,
        )

    def setup_assumed_session(
        self,
        assumed_role_credentials: AWSCredentials,
    ) -> Session:
        # FIXME: Boto3 returns the timestamp in UTC and the local TZ could be different so the expiration time could not work as expected
        # PRWLR-3305
        try:
            # From botocore we can use RefreshableCredentials class, which has an attribute (refresh_using)
            # that needs to be a method without arguments that retrieves a new set of fresh credentials
            # asuming the role again. -> https://github.com/boto/botocore/blob/098cc255f81a25b852e1ecdeb7adebd94c7b1b73/botocore/credentials.py#L395
            assumed_refreshable_credentials = RefreshableCredentials(
                access_key=assumed_role_credentials.aws_access_key_id,
                secret_key=assumed_role_credentials.aws_secret_access_key,
                token=assumed_role_credentials.aws_session_token,
                expiry_time=assumed_role_credentials.expiration,
                refresh_using=self.refresh_credentials,
                method="sts-assume-role",
            )

            # Here we need the botocore session since it needs to use refreshable credentials
            assumed_session = get_session()
            assumed_session._credentials = assumed_refreshable_credentials
            assumed_session.set_config_variable("region", self._identity.profile_region)
            return session.Session(
                profile_name=self._identity.profile,
                botocore_session=assumed_session,
            )
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            sys.exit(1)

    # Refresh credentials method using assume role
    # This method is called "adding ()" to the name, so it cannot accept arguments
    # https://github.com/boto/botocore/blob/098cc255f81a25b852e1ecdeb7adebd94c7b1b73/botocore/credentials.py#L570
    # TODO: maybe this can be improved with botocore.credentials.DeferredRefreshableCredentials https://stackoverflow.com/a/75576540
    def refresh_credentials(self) -> dict:
        logger.info("Refreshing assumed credentials...")
        # Since this method does not accept arguments, we need to get the original_session and the assumed role credentials
        response = self.assume_role(
            self._session.original_session, self._assumed_role_configuration.info
        )
        refreshed_credentials = dict(
            # Keys of the dict has to be the same as those that are being searched in the parent class
            # https://github.com/boto/botocore/blob/098cc255f81a25b852e1ecdeb7adebd94c7b1b73/botocore/credentials.py#L609
            access_key=response.aws_access_key_id,
            secret_key=response.aws_secret_access_key,
            token=response.aws_session_token,
            expiry_time=response.expiration.isoformat(),
        )
        logger.info(f"Refreshed Credentials: {refreshed_credentials}")
        return refreshed_credentials

    def print_credentials(self):
        # Beautify audited regions, set "all" if there is no filter region
        regions = (
            ", ".join(self._identity.audited_regions)
            if self._identity.audited_regions is not None
            else "all"
        )
        # Beautify audited profile, set "default" if there is no profile set
        profile = (
            self._identity.profile if self._identity.profile is not None else "default"
        )
        # TODO: rename AWS Filter Region to AWS Regions, and UserId to User ID
        # review new banner
        #       report = f"""
        # The current audit for AWS will use the following credentials:

        # CLI Profile: {Fore.YELLOW}[{profile}]{Style.RESET_ALL} Regions: {Fore.YELLOW}[{regions}]{Style.RESET_ALL}
        # Account: {Fore.YELLOW}[{self._identity.account}]{Style.RESET_ALL} User ID: {Fore.YELLOW}[{self._identity.user_id}]{Style.RESET_ALL}
        # Caller Identity ARN: {Fore.YELLOW}[{self._identity.identity_arn}]{Style.RESET_ALL}
        # """
        report = f"""
This report is being generated using credentials below:

AWS-CLI Profile: {Fore.YELLOW}[{profile}]{Style.RESET_ALL} AWS Filter Region: {Fore.YELLOW}[{regions}]{Style.RESET_ALL}
AWS Account: {Fore.YELLOW}[{self._identity.account}]{Style.RESET_ALL} UserId: {Fore.YELLOW}[{self._identity.user_id}]{Style.RESET_ALL}
Caller Identity ARN: {Fore.YELLOW}[{self._identity.identity_arn}]{Style.RESET_ALL}
"""
        # If -A is set, print Assumed Role ARN
        if (
            hasattr(self, "_assumed_role")
            and self._assumed_role.info.role_arn is not None
        ):
            report += f"""Assumed Role ARN: {Fore.YELLOW}[{self._assumed_role.info.role_arn.arn}]{Style.RESET_ALL}
        """
        print(report)

    def generate_regional_clients(
        self,
        service: str,
    ) -> dict:
        """generate_regional_clients returns a dict with the following format for the given service:

        Example:
            {"eu-west-1": boto3_service_client}
        """
        try:
            regional_clients = {}
            service_regions = self.get_available_aws_service_regions(service)

            # Get the regions enabled for the account and get the intersection with the service available regions
            if self._enabled_regions:
                enabled_regions = service_regions.intersection(self._enabled_regions)
            else:
                enabled_regions = service_regions

            for region in enabled_regions:
                regional_client = self._session.current_session.client(
                    service, region_name=region, config=self._session.session_config
                )
                regional_client.region = region
                regional_clients[region] = regional_client

            return regional_clients
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def get_available_aws_service_regions(self, service: str) -> set:
        data = read_aws_regions_file()
        json_regions = set(
            data["services"][service]["regions"][self._identity.partition]
        )
        # Check for input aws audit_info.audited_regions
        if self._identity.audited_regions:
            # Get common regions between input and json
            regions = json_regions.intersection(self._identity.audited_regions)
        else:  # Get all regions from json of the service and partition
            regions = json_regions
        return regions

    def get_checks_from_input_arn(self) -> set:
        """
        get_checks_from_input_arn gets the list of checks from the input arns
        """
        checks_from_arn = set()
        is_subservice_in_checks = False
        # Handle if there are audit resources so only their services are executed
        if self._audit_resources:
            # TODO: this should be retrieved automatically
            services_without_subservices = ["guardduty", "kms", "s3", "elb", "efs"]
            service_list = set()
            sub_service_list = set()
            for resource in self._audit_resources:
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
                        list_modules(self.type, service)
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
            # TODO: this should be split in several function
            checks = recover_checks_from_service(service_list, self.type)

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

    # TODO: This can be moved to another class since it doesn't need self
    def get_regions_from_audit_resources(self, audit_resources: list) -> set:
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
        """get_default_region returns the default region based on the profile and audited service regions"""
        service_regions = self.get_available_aws_service_regions(service)
        default_region = (
            self.get_global_region()
        )  # global region of the partition when all regions are audited and there is no profile region
        if self._identity.profile_region in service_regions:
            # return profile region only if it is audited
            default_region = self._identity.profile_region
        # return first audited region if specific regions are audited
        elif self._identity.audited_regions:
            default_region = self._identity.audited_regions[0]
        return default_region

    def get_global_region(self) -> str:
        """get_global_region returns the global region based on the audited partition"""
        global_region = "us-east-1"
        if self._identity.partition == "aws-cn":
            global_region = "cn-north-1"
        elif self._identity.partition == "aws-us-gov":
            global_region = "us-gov-east-1"
        elif "aws-iso" in self._identity.partition:
            global_region = "aws-iso-global"
        return global_region

    def __input_role_mfa_token_and_code__(self) -> AWSMFAInfo:
        """input_role_mfa_token_and_code ask for the AWS MFA ARN and TOTP and returns it."""
        mfa_ARN = input("Enter ARN of MFA: ")
        mfa_TOTP = input("Enter MFA code: ")
        return AWSMFAInfo(arn=mfa_ARN, totp=mfa_TOTP)

    # TODO: rename function
    def _set_session_config(self, aws_retries_max_attempts: int) -> Config:
        """
        _set_session_config returns a botocore Config object with the Prowler user agent and the default retrier configuration if nothing is passed as argument
        """
        # Set the maximum retries for the standard retrier config
        default_session_config = Config(
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
            default_session_config.merge(config)
            # TODO: I don't understand the following line
            # default_session_config = self.session.session_config.merge(config)

        return default_session_config

    def assume_role(
        self,
        session: Session,
        assumed_role_info: AWSAssumeRoleInfo,
        # TODO: remove I think
        # sts_endpoint_region: str = None,
    ) -> AWSCredentials:
        """
        assume_role assumes the IAM roles passed with the given session and returns AWSCredentials
        """
        try:
            role_session_name = (
                assumed_role_info.role_session_name
                if assumed_role_info.role_session_name
                else ROLE_SESSION_NAME
            )

            assume_role_arguments = {
                "RoleArn": assumed_role_info.role_arn.arn,
                "RoleSessionName": role_session_name,
                "DurationSeconds": assumed_role_info.session_duration,
            }

            # Set the info to assume the IAM Role from the partition, account and role name
            if assumed_role_info.external_id:
                assume_role_arguments["ExternalId"] = assumed_role_info.external_id

            if assumed_role_info.mfa_enabled:
                mfa_info = self.__input_role_mfa_token_and_code__()
                assume_role_arguments["SerialNumber"] = mfa_info.arn
                assume_role_arguments["TokenCode"] = mfa_info.totp

            # Set the STS Endpoint Region
            # TODO: review the STS endpoint region removal
            # https://github.com/prowler-cloud/prowler/pull/3046
            # if sts_endpoint_region is None:
            #     sts_endpoint_region = AWS_STS_GLOBAL_ENDPOINT_REGION

            sts_client = create_sts_session(session, AWS_STS_GLOBAL_ENDPOINT_REGION)
            assumed_credentials = sts_client.assume_role(**assume_role_arguments)
            return AWSCredentials(
                aws_access_key_id=assumed_credentials["Credentials"]["AccessKeyId"],
                aws_session_token=assumed_credentials["Credentials"]["SessionToken"],
                aws_secret_access_key=assumed_credentials["Credentials"][
                    "SecretAccessKey"
                ],
                expiration=assumed_credentials["Credentials"]["Expiration"],
            )
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            sys.exit(1)

    def get_aws_enabled_regions(self, current_session: Session) -> set:
        """get_aws_enabled_regions returns a set of enabled AWS regions"""

        # EC2 Client to check enabled regions
        service = "ec2"
        default_region = self.get_default_region(service)
        ec2_client = current_session.client(service, region_name=default_region)

        enabled_regions = set()
        # With AllRegions=False we only get the enabled regions for the account
        for region in ec2_client.describe_regions(AllRegions=False).get("Regions", []):
            enabled_regions.add(region.get("RegionName"))

        return enabled_regions

    # TODO: review this function
    # Maybe this should be done within the AwsProvider and not in __main__.py
    def get_checks_to_execute_by_audit_resources(self) -> set[str]:
        # Once the audit_info is set and we have the eventual checks from arn, it is time to exclude the others
        try:
            checks = set()
            # TODO: self._audit_resources should be a list[ARN] instead of list[str]
            if self._audit_resources:
                self._identity.audited_regions = self.get_regions_from_audit_resources(
                    self._audit_resources
                )
                checks = self.get_checks_from_input_arn()
            return checks
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            sys.exit(1)


def read_aws_regions_file() -> dict:
    # Get JSON locally
    actual_directory = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
    with open_file(f"{actual_directory}/{aws_services_json_file}") as f:
        data = parse_json_file(f)

    return data


def get_aws_available_regions():
    try:
        data = read_aws_regions_file()

        regions = set()
        for service in data["services"].values():
            for partition in service["regions"]:
                for item in service["regions"][partition]:
                    regions.add(item)
        return regions
    except Exception as error:
        logger.error(f"{error.__class__.__name__}: {error}")
        return []


# TODO: This can be moved to another class since it doesn't need self
# TODO: rename to validate_credentials
def validate_aws_credentials(
    session: Session,
    aws_region: str,
) -> AWSCallerIdentity:
    """
    validate_aws_credentials returns the get_caller_identity() answer, exits if something exception is raised.
    """
    try:
        validate_credentials_client = create_sts_session(session, aws_region)
        caller_identity = validate_credentials_client.get_caller_identity()
        # Include the region where the caller_identity has validated the credentials
        return AWSCallerIdentity(
            user_id=caller_identity.get("UserId"),
            account=caller_identity.get("Account"),
            arn=caller_identity.get("Arn"),
            region=aws_region,
        )
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
        )
        sys.exit(1)


# TODO: This can be moved to another class since it doesn't need self
def get_aws_region_for_sts(session_region: str, input_regions: set[str]) -> str:
    # If there is no region passed with -f/--region/--filter-region
    if input_regions is None or len(input_regions) == 0:
        # If you have a region configured in your AWS config or credentials file
        if session_region is not None:
            aws_region = session_region
        else:
            # If there is no region set passed with -f/--region
            # we use the Global STS Endpoint Region, us-east-1
            aws_region = AWS_STS_GLOBAL_ENDPOINT_REGION
    else:
        # Get the first region passed to the -f/--region
        aws_region = input_regions[0]

    return aws_region


# TODO: This can be moved to another class since it doesn't need self
def create_sts_session(
    session: session.Session, aws_region: str
) -> session.Session.client:
    return session.client(
        "sts", aws_region, endpoint_url=f"https://sts.{aws_region}.amazonaws.com"
    )
