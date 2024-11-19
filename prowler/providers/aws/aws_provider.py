import os
import pathlib
from datetime import datetime
from re import fullmatch
from typing import Optional

from boto3.session import Session
from botocore.config import Config
from botocore.credentials import RefreshableCredentials
from botocore.exceptions import ClientError, NoCredentialsError, ProfileNotFound
from botocore.session import Session as BotocoreSession
from colorama import Fore, Style
from pytz import utc
from tzlocal import get_localzone

from prowler.config.config import (
    aws_services_json_file,
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.check.utils import list_modules, recover_checks_from_service
from prowler.lib.logger import logger
from prowler.lib.utils.utils import open_file, parse_json_file, print_boxes
from prowler.providers.aws.config import (
    AWS_REGION_US_EAST_1,
    AWS_STS_GLOBAL_ENDPOINT_REGION,
    BOTO3_USER_AGENT_EXTRA,
    ROLE_SESSION_NAME,
)
from prowler.providers.aws.exceptions.exceptions import (
    AWSAccessKeyIDInvalidError,
    AWSArgumentTypeValidationError,
    AWSAssumeRoleError,
    AWSClientError,
    AWSIAMRoleARNEmptyResourceError,
    AWSIAMRoleARNInvalidAccountIDError,
    AWSIAMRoleARNInvalidResourceTypeError,
    AWSIAMRoleARNPartitionEmptyError,
    AWSIAMRoleARNRegionNotEmtpyError,
    AWSIAMRoleARNServiceNotIAMnorSTSError,
    AWSInvalidPartitionError,
    AWSInvalidProviderIdError,
    AWSNoCredentialsError,
    AWSProfileNotFoundError,
    AWSSecretAccessKeyInvalidError,
    AWSSessionTokenExpiredError,
    AWSSetUpSessionError,
)
from prowler.providers.aws.lib.arn.arn import parse_iam_credentials_arn
from prowler.providers.aws.lib.arn.models import ARN
from prowler.providers.aws.lib.mutelist.mutelist import AWSMutelist
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
    AWSSession,
    Partition,
)
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider


class AwsProvider(Provider):
    """
    AwsProvider class is the main class for the AWS provider.

    This class is responsible for initializing the AWS provider, setting up the AWS session, validating the AWS
    credentials, assuming an IAM role, getting the AWS Organizations metadata, and setting the AWS identity.

    Attributes:
        _type (str): The provider type.
        _identity (AWSIdentityInfo): The AWS provider identity information.
        _session (AWSSession): The AWS provider session.
        _organizations_metadata (AWSOrganizationsInfo): The AWS Organizations metadata.
        _audit_resources (list): The list of resources to audit.
        _audit_config (dict): The audit configuration.
        _scan_unused_services (bool): A boolean indicating whether to scan unused services.
        _enabled_regions (set): The set of enabled regions.
        _mutelist (AWSMutelist): The AWS provider mutelist.
        audit_metadata (Audit_Metadata): The audit metadata.
    """

    _type: str = "aws"
    _identity: AWSIdentityInfo
    _session: AWSSession
    _organizations_metadata: AWSOrganizationsInfo
    _audit_resources: list = []
    _audit_config: dict
    _scan_unused_services: bool = False
    _enabled_regions: set = set()
    _mutelist: AWSMutelist
    # TODO: this is not optional, enforce for all providers
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        retries_max_attempts: int = 3,
        role_arn: str = None,
        session_duration: int = None,
        external_id: str = None,
        role_session_name: str = None,
        mfa: bool = None,
        profile: str = None,
        regions: set = set(),
        organizations_role_arn: str = None,
        scan_unused_services: bool = False,
        resource_tags: list[str] = [],
        resource_arn: list[str] = [],
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
        aws_access_key_id: str = None,
        aws_secret_access_key: str = None,
        aws_session_token: Optional[str] = None,
    ):
        """
        Initializes the AWS provider.

        Args:
            - retries_max_attempts: The maximum number of retries for the AWS client.
            - role_arn: The ARN of the IAM role to assume.
            - session_duration: The duration of the session in seconds, between 900 and 43200.
            - external_id: The external ID to use when assuming the IAM role.
            - role_session_name: The name of the session when assuming the IAM role.
            - mfa: A boolean indicating whether MFA is enabled.
            - profile: The name of the AWS CLI profile to use.
            - regions: A set of regions to audit.
            - organizations_role_arn: The ARN of the AWS Organizations IAM role to assume.
            - scan_unused_services: A boolean indicating whether to scan unused services. False by default.
            - resource_tags: A list of tags to filter the resources to audit.
            - resource_arn: A list of ARNs of the resources to audit.
            - config_path: The path to the configuration file.
            - config_content: The content of the configuration file.
            - fixer_config: The fixer configuration.
            - mutelist_path: The path to the mutelist file.
            - mutelist_content: The content of the mutelist file.
            - aws_access_key_id: The AWS access key ID.
            - aws_secret_access_key: The AWS secret access key.
            - aws_session_token: The AWS session token, optional.

        Raises:
            - ArgumentTypeError: If the input MFA ARN is invalid.
            - ArgumentTypeError: If the input session duration is invalid.
            - ArgumentTypeError: If the input external ID is invalid.
            - ArgumentTypeError: If the input role session name is invalid.

        Usage:
            - Boto3 is used so we follow their credential setup process:
                - Authentication: Make sure you have properly configured your AWS CLI with a valid Access Key and Region or declare the AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables.
                    - aws configure
                    or
                    - export AWS_ACCESS_KEY_ID="ASXXXXXXX"
                      export AWS_SECRET_ACCESS_KEY="XXXXXXXXX"
                      export AWS_SESSION_TOKEN="XXXXXXXXX"
                    - To create a new aws object you can use:
                        - aws = AwsProvider()
                        - aws = AwsProvider(aws_access_key_id="ASXXXXXXX", aws_secret_access_key="XXXXXXXXX", aws_session_token="XXXXXXXXX")
                    - Profile: If you have multiple profiles in your AWS CLI configuration, you can specify the profile to use:
                        - aws = AwsProvider(profile="profile_name")
                    - MFA: If you have MFA enabled you can specify it:
                        - aws = AwsProvider(mfa=True)
                    * Note: If you have MFA enabled you will be prompted to enter the MFA ARN and the MFA TOTP code.
                    * Note: Take into account that you can use static credentials or a profile, with the combination of MFA.

                - Assume Role: *Requires authentication.* Prowler can be used against multiple accounts using IAM Assume Role features depending on each use case:
                    - Set up a custom profile inside your AWS CLI configuration file:
                        - [profile profile_name]
                            role_arn = arn:aws:iam::123456789012:role/role_name
                        - aws = AwsProvider(profile="profile_name")
                    - Use role_arn directly:
                        - aws = AwsProvider(role_arn="arn:aws:iam::123456789012:role/role_name")
                        - Use role_arn with session duration(in seconds, by default 3600) and external ID:
                            - aws = AwsProvider(role_arn="arn:aws:iam::123456789012:role/role_name", session_duration=3600, external_id="external_id")
                    - Use custom role session name:
                        - aws = AwsProvider(role_arn="arn:aws:iam::123456789012:role/role_name", role_session_name="custom_session_name")
                    * Note: You can use the combination of MFA with Assume Role.
                        - aws = AwsProvider(role_arn="arn:aws:iam::123456789012:role/role_name", mfa=True)
        """

        logger.info("Initializing AWS provider ...")

        ######## AWS Session
        logger.info("Generating original session ...")

        # Configure the initial AWS Session using the local credentials: profile or environment variables
        aws_session = self.setup_session(
            mfa=mfa,
            profile=profile,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
        )
        session_config = self.set_session_config(retries_max_attempts)
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
            self.session.current_session.region_name, regions
        )

        # Validate the credentials
        caller_identity = self.validate_credentials(
            session=self.session.current_session,
            aws_region=sts_region,
        )

        logger.info("Credentials validated")
        ########

        ######## AWS Provider Identity
        # Get profile region
        profile_region = self.get_profile_region(self._session.current_session)

        # Set identity
        self._identity = self.set_identity(
            caller_identity=caller_identity,
            profile=profile,
            regions=regions,
            profile_region=profile_region,
        )
        ########

        ######## AWS Session with Assume Role (if needed)
        if role_arn:
            # Validate the input role
            valid_role_arn = parse_iam_credentials_arn(role_arn)
            # Set assume IAM Role information
            assumed_role_information = AWSAssumeRoleInfo(
                role_arn=valid_role_arn,
                session_duration=session_duration,
                external_id=external_id,
                mfa_enabled=mfa,
                role_session_name=role_session_name,
                sts_region=sts_region,
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
            organizations_assumed_role_information = AWSAssumeRoleInfo(
                role_arn=valid_role_arn,
                session_duration=session_duration,
                external_id=external_id,
                mfa_enabled=mfa,
                role_session_name=role_session_name,
                sts_region=sts_region,
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

        self._organizations_metadata = self.get_organizations_info(
            aws_organizations_session, self._identity.account
        )
        ########

        # Parse Scan Tags
        if resource_tags:
            self._audit_resources = self.get_tagged_resources(resource_tags)

        # Parse Input Resource ARNs
        if resource_arn:
            self._audit_resources = resource_arn

        # Get Enabled Regions
        self._enabled_regions = self.get_aws_enabled_regions(
            self._session.current_session
        )

        # Set ignore unused services
        self._scan_unused_services = scan_unused_services

        # Audit Config
        if config_content:
            self._audit_config = config_content
        else:
            if not config_path:
                config_path = default_config_file_path
            self._audit_config = load_and_validate_config_file(self._type, config_path)

        # Fixer Config
        self._fixer_config = fixer_config

        # Mutelist
        if mutelist_content:
            self._mutelist = AWSMutelist(
                mutelist_content=mutelist_content,
                session=self._session.current_session,
                aws_account_id=self._identity.account,
            )
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = AWSMutelist(
                mutelist_path=mutelist_path,
                session=self._session.current_session,
                aws_account_id=self._identity.account,
            )

        Provider.set_global_provider(self)

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
    def scan_unused_services(self):
        return self._scan_unused_services

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def fixer_config(self):
        return self._fixer_config

    @property
    def mutelist(self) -> AWSMutelist:
        """
        mutelist method returns the provider's mutelist.
        """
        return self._mutelist

    # TODO: This can be moved to another class since it doesn't need self
    def get_organizations_info(
        self, organizations_session: Session, aws_account_id: str
    ) -> AWSOrganizationsInfo:
        """
        get_organizations_info returns a AWSOrganizationsInfo object if the account to be audited is a delegated administrator for AWS Organizations or if the AWS Organizations Role ARN (--organizations-role) is passed.

        Args:
        - organizations_session: needs to be a Session object with permissions to do organizations:DescribeAccount and organizations:ListTagsForResource.
        - aws_account_id: is the AWS Account ID from which we want to get the AWS Organizations account metadata

        Returns:
        - AWSOrganizationsInfo object with the AWS Organizations metadata for the account to be audited.
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
            else:
                return AWSOrganizationsInfo(
                    account_email="",
                    account_name="",
                    organization_account_arn="",
                    organization_arn="",
                    organization_id="",
                    account_tags=[],
                )

        except Exception as error:
            # If the account is not a delegated administrator for AWS Organizations a credentials error will be thrown
            # Since it is a permission issue for an optional we'll raise a warning
            logger.warning(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    @staticmethod
    def get_profile_region(session: Session):
        profile_region = AWS_REGION_US_EAST_1
        if session.region_name:
            profile_region = session.region_name

        return profile_region

    def set_identity(
        self,
        caller_identity: AWSCallerIdentity,
        profile: str,
        regions: set,
        profile_region: str,
    ) -> AWSIdentityInfo:
        """
        set_identity sets the AWS provider identity information.

        Args:
            - caller_identity: The AWS caller identity information.
            - profile: The AWS CLI profile name.
            - regions: A set of regions to audit.
            - profile_region: The AWS CLI profile region.

        Returns:
            - AWSIdentityInfo: The AWS provider identity information.

        Raises:
            - AWSInvalidProviderIdError: If the AWS provider ID is invalid.
        """
        logger.info(f"Original AWS Caller Identity UserId: {caller_identity.user_id}")
        logger.info(f"Original AWS Caller Identity ARN: {caller_identity.arn}")

        partition = parse_iam_credentials_arn(caller_identity.arn.arn).partition
        return AWSIdentityInfo(
            account=caller_identity.account,
            account_arn=f"arn:{partition}:iam::{caller_identity.account}:root",
            user_id=caller_identity.user_id,
            partition=partition,
            identity_arn=caller_identity.arn.arn,
            profile=profile,
            profile_region=profile_region,
            audited_regions=regions,
        )

    @staticmethod
    def setup_session(
        mfa: bool = False,
        profile: str = None,
        aws_access_key_id: str = None,
        aws_secret_access_key: str = None,
        aws_session_token: Optional[str] = None,
    ) -> Session:
        """
        setup_session sets up an AWS session using the provided credentials.

        Args:
            - mfa: A boolean indicating whether MFA is enabled.
            - profile: The name of the AWS CLI profile to use.
            - aws_access_key_id: The AWS access key ID.
            - aws_secret_access_key: The AWS secret access key.
            - aws_session_token: The AWS session token, optional.

        Returns:
            - Session: The AWS session.

        Raises:
            - AWSSetUpSessionError: If an error occurs during the setup process.
        """
        try:
            logger.debug("Creating original session ...")

            session_arguments = {}
            if profile:
                session_arguments["profile_name"] = profile
            elif aws_access_key_id and aws_secret_access_key:
                session_arguments["aws_access_key_id"] = aws_access_key_id
                session_arguments["aws_secret_access_key"] = aws_secret_access_key
                if aws_session_token:
                    session_arguments["aws_session_token"] = aws_session_token

            if mfa:
                session = Session(**session_arguments)
                sts_client = session.client("sts")

                # TODO: pass values from the input
                mfa_info = AwsProvider.input_role_mfa_token_and_code()
                # TODO: validate MFA ARN here
                get_session_token_arguments = {
                    "SerialNumber": mfa_info.arn,
                    "TokenCode": mfa_info.totp,
                }
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
                )
            else:
                return Session(**session_arguments)
        except Exception as error:
            logger.critical(
                f"AWSSetUpSessionError[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise AWSSetUpSessionError(
                original_exception=error,
                file=pathlib.Path(__file__).name,
            )

    def setup_assumed_session(
        self,
        assumed_role_credentials: AWSCredentials,
    ) -> Session:
        """
        Sets up an assumed session using the provided assumed role credentials.

        This method creates a new session with temporary credentials obtained by assuming an AWS IAM role.
        It uses the `RefreshableCredentials` class from the `botocore` library to manage the automatic
        refreshing of the assumed role credentials.

        Args:
            assumed_role_credentials (AWSCredentials): The assumed role credentials.

        Returns:
            Session: The assumed session.

        Raises:
            Exception: If an error occurs during the setup process.

        References:
            - `RefreshableCredentials` class in botocore:
              [GitHub](https://github.com/boto/botocore/blob/098cc255f81a25b852e1ecdeb7adebd94c7b1b73/botocore/credentials.py#L395)
            - AWS STS AssumeRole API:
              [AWS Documentation](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)
        """
        try:
            # From botocore we can use RefreshableCredentials class, which has an attribute (refresh_using)
            # that needs to be a method without arguments that retrieves a new set of fresh credentials
            # assuming the role again.
            assumed_refreshable_credentials = RefreshableCredentials(
                access_key=assumed_role_credentials.aws_access_key_id,
                secret_key=assumed_role_credentials.aws_secret_access_key,
                token=assumed_role_credentials.aws_session_token,
                expiry_time=assumed_role_credentials.expiration,
                refresh_using=self.refresh_credentials,
                method="sts-assume-role",
            )

            # Here we need the botocore session since it needs to use refreshable credentials
            assumed_session = BotocoreSession()
            assumed_session._credentials = assumed_refreshable_credentials
            assumed_session.set_config_variable("region", self._identity.profile_region)
            return Session(
                profile_name=self._identity.profile,
                botocore_session=assumed_session,
            )
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise error

    # TODO: maybe this can be improved with botocore.credentials.DeferredRefreshableCredentials https://stackoverflow.com/a/75576540
    def refresh_credentials(self) -> dict:
        """
        Refresh credentials method using AWS STS Assume Role.

        This method is called adding "()" to the name, so it cannot accept arguments
        https://github.com/boto/botocore/blob/098cc255f81a25b852e1ecdeb7adebd94c7b1b73/botocore/credentials.py#L570
        """
        logger.info("Refreshing assumed credentials...")

        # Since this method does not accept arguments, we need to get the original_session and the assumed role credentials
        current_credentials = self._assumed_role_configuration.credentials
        refreshed_credentials = {
            "access_key": current_credentials.aws_access_key_id,
            "secret_key": current_credentials.aws_secret_access_key,
            "token": current_credentials.aws_session_token,
            "expiry_time": (
                current_credentials.expiration.isoformat()
                if hasattr(current_credentials, "expiration")
                else current_credentials.expiry_time.isoformat()
            ),
        }

        if datetime.fromisoformat(refreshed_credentials["expiry_time"]) <= datetime.now(
            get_localzone()
        ):
            assume_role_response = self.assume_role(
                self._session.original_session, self._assumed_role_configuration.info
            )
            refreshed_credentials = dict(
                # Keys of the dict has to be the same as those that are being searched in the parent class
                # https://github.com/boto/botocore/blob/098cc255f81a25b852e1ecdeb7adebd94c7b1b73/botocore/credentials.py#L609
                access_key=assume_role_response.aws_access_key_id,
                secret_key=assume_role_response.aws_secret_access_key,
                token=assume_role_response.aws_session_token,
                expiry_time=assume_role_response.expiration.isoformat(),
            )
            logger.info("Refreshed Credentials")

        return refreshed_credentials

    def print_credentials(self):
        """
        Print the AWS credentials.

        This method prints the AWS credentials used by the provider.

        Example output:
        ```
        Using the AWS credentials below:
        AWS-CLI Profile: default
        AWS Regions: all
        AWS Account: 123456789012
        User Id: AIDAJDPLRKLG7EXAMPLE
        Caller Identity ARN: arn:aws:iam::123456789012:user/prowler
        ```
        """
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
        report_lines = [
            f"AWS-CLI Profile: {Fore.YELLOW}{profile}{Style.RESET_ALL}",
            f"AWS Regions: {Fore.YELLOW}{regions}{Style.RESET_ALL}",
            f"AWS Account: {Fore.YELLOW}{self._identity.account}{Style.RESET_ALL}",
            f"User Id: {Fore.YELLOW}{self._identity.user_id}{Style.RESET_ALL}",
            f"Caller Identity ARN: {Fore.YELLOW}{self._identity.identity_arn}{Style.RESET_ALL}",
        ]
        # If -A is set, print Assumed Role ARN
        if (
            hasattr(self, "_assumed_role_configuration")
            and self._assumed_role_configuration.info.role_arn is not None
        ):
            report_lines.append(
                f"Assumed Role ARN: {Fore.YELLOW}[{self._assumed_role_configuration.info.role_arn.arn}]{Style.RESET_ALL}"
            )
        report_title = (
            f"{Style.BRIGHT}Using the AWS credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)

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
            service_regions = AwsProvider.get_available_aws_service_regions(
                service, self._identity.partition, self._identity.audited_regions
            )

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

    @staticmethod
    def get_available_aws_service_regions(
        service: str, partition: str = "aws", audited_regions: set = None
    ) -> set:
        """
        get_available_aws_service_regions returns the available regions for the given service and partition.

        Args:
            - service: The AWS service name.
            - partition: The AWS partition name. Default is "aws".
            - audited_regions: A set of regions to audit. Default is None.

        Returns:
            - A set of strings representing the available regions for the given service and partition.
        """
        data = read_aws_regions_file()
        json_regions = set(data["services"][service]["regions"][partition])
        if audited_regions:
            # Get common regions between input and json
            regions = json_regions.intersection(audited_regions)
        else:  # Get all regions from json of the service and partition
            regions = json_regions
        return regions

    def get_checks_from_input_arn(self) -> set:
        """
        get_checks_from_input_arn gets the list of checks from the input arns

        Returns:
            - set: set of strings representing the checks from the input arns

        Example:
            checks = get_checks_from_input_arn()
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
        """get_regions_from_audit_resources gets the regions from the audit resources arns

        Args:
            - audit_resources: list of ARNs of the resources to audit

        Returns:
            - set: set of strings representing the regions from the audit resources arns

        Example:
            audit_resources = ["arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0"]
            regions = get_regions_from_audit_resources(audit_resources)
        """
        audited_regions = set()
        for resource in audit_resources:
            region = resource.split(":")[3]
            if region:
                audited_regions.add(region)
        return audited_regions

    def get_tagged_resources(self, resource_tags: list[str]) -> list[str]:
        """
        Returns a list of the resources that are going to be scanned based on the given input tags.

        Parameters:
        - resource_tags: A list of strings representing the tags to filter the resources. Each string should be in the format "key=value".

        Returns:
        - A list of strings representing the ARNs (Amazon Resource Names) of the tagged resources.

        Note:
        - This method uses the AWS Resource Groups Tagging API to retrieve the tagged resources.
        - The method generates regional clients for the Resource Groups Tagging API for each enabled region in the AWS provider.
        - The method paginates through the results of the 'get_resources' operation to retrieve all the tagged resources.

        Example usage:
            resource_tags = ["Environment=Production", "Owner=John Doe"]
            tagged_resources = get_tagged_resources(resource_tags)
        """
        try:
            resource_tags_values = []
            tagged_resources = []
            for tag in resource_tags:
                key = tag.split("=")[0]
                value = tag.split("=")[1]
                resource_tags_values.append({"Key": key, "Values": [value]})
            # Get Resources with resource_tags for all regions
            for regional_client in self.generate_regional_clients(
                "resourcegroupstaggingapi"
            ).values():
                try:
                    get_resources_paginator = regional_client.get_paginator(
                        "get_resources"
                    )
                    for page in get_resources_paginator.paginate(
                        TagFilters=resource_tags_values
                    ):
                        for resource in page["ResourceTagMappingList"]:
                            tagged_resources.append(resource["ResourceARN"])
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )

            return tagged_resources
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise error

    def get_default_region(self, service: str) -> str:
        """get_default_region returns the default region based on the profile and audited service regions

        Args:
            - service: The AWS service name

        Returns:
            - str: The default region for the given service

        Example:
            service = "ec2"
            default_region = get_default_region(service)
        """
        try:
            service_regions = AwsProvider.get_available_aws_service_regions(
                service, self._identity.partition, self._identity.audited_regions
            )
            default_region = self.get_global_region()
            # global region of the partition when all regions are audited and there is no profile region
            if self._identity.profile_region in service_regions:
                # return profile region only if it is audited
                default_region = self._identity.profile_region
            # return first audited region if specific regions are audited
            elif self._identity.audited_regions:
                default_region = list(self._identity.audited_regions)[0]
            return default_region
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise error

    def get_global_region(self) -> str:
        """get_global_region returns the global region based on the audited partition

        Returns:
            - str: The global region for the audited partition

        Example:
            global_region = get_global_region()a
        """
        global_region = "us-east-1"
        if self._identity.partition == "aws-cn":
            global_region = "cn-north-1"
        elif self._identity.partition == "aws-us-gov":
            global_region = "us-gov-east-1"
        elif "aws-iso" in self._identity.partition:
            global_region = "aws-iso-global"
        return global_region

    @staticmethod
    def input_role_mfa_token_and_code() -> AWSMFAInfo:
        """input_role_mfa_token_and_code ask for the AWS MFA ARN and TOTP and returns it.

        Returns:
            - AWSMFAInfo: An object containing the MFA ARN and TOTP code

        Example:
            mfa_info = input_role_mfa_token_and_code()
        """
        mfa_ARN = input("Enter ARN of MFA: ")
        mfa_TOTP = input("Enter MFA code: ")
        return AWSMFAInfo(arn=mfa_ARN, totp=mfa_TOTP)

    def set_session_config(self, retries_max_attempts: int) -> Config:
        """
        set_session_config returns a botocore Config object with the Prowler user agent and the default retrier configuration if nothing is passed as argument

        Args:
            - retries_max_attempts: The maximum number of retries for the standard retrier config

        Returns:
            - Config: The botocore Config object
        """
        # Set the maximum retries for the standard retrier config
        default_session_config = Config(
            retries={"max_attempts": 3, "mode": "standard"},
            user_agent_extra=BOTO3_USER_AGENT_EXTRA,
        )
        if retries_max_attempts:
            # Create the new config
            config = Config(
                retries={
                    "max_attempts": retries_max_attempts,
                    "mode": "standard",
                },
            )
            # Merge the new configuration
            default_session_config = default_session_config.merge(config)

        return default_session_config

    @staticmethod
    def assume_role(
        session: Session,
        assumed_role_info: AWSAssumeRoleInfo,
    ) -> AWSCredentials:
        """
        assume_role assumes the IAM roles passed with the given session and returns AWSCredentials

        Args:
            - session: The AWS session object
            - assumed_role_info: The AWSAssumeRoleInfo object

        Returns:
            - AWSCredentials: The AWS credentials for the assumed role
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
                mfa_info = AwsProvider.input_role_mfa_token_and_code()
                assume_role_arguments["SerialNumber"] = mfa_info.arn
                assume_role_arguments["TokenCode"] = mfa_info.totp
            sts_client = AwsProvider.create_sts_session(
                session, assumed_role_info.sts_region
            )
            assumed_credentials = sts_client.assume_role(**assume_role_arguments)
            # Convert the UTC datetime object to your local timezone
            credentials_expiration_local_time = (
                assumed_credentials["Credentials"]["Expiration"]
                .replace(tzinfo=utc)
                .astimezone(get_localzone())
            )

            return AWSCredentials(
                aws_access_key_id=assumed_credentials["Credentials"]["AccessKeyId"],
                aws_session_token=assumed_credentials["Credentials"]["SessionToken"],
                aws_secret_access_key=assumed_credentials["Credentials"][
                    "SecretAccessKey"
                ],
                expiration=credentials_expiration_local_time,
            )
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise AWSAssumeRoleError(
                original_exception=error,
                file=pathlib.Path(__file__).name,
            )

    def get_aws_enabled_regions(self, current_session: Session) -> set:
        """get_aws_enabled_regions returns a set of enabled AWS regions

        Args:
            - current_session: The AWS session object

        Returns:
            - set: set of strings representing the enabled AWS regions
        """
        try:
            # EC2 Client to check enabled regions
            service = "ec2"
            default_region = self.get_default_region(service)
            ec2_client = current_session.client(service, region_name=default_region)

            enabled_regions = set()
            # With AllRegions=False we only get the enabled regions for the account
            for region in ec2_client.describe_regions(AllRegions=False).get(
                "Regions", []
            ):
                enabled_regions.add(region.get("RegionName"))

            return enabled_regions
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return set()

    # TODO: review this function
    # Maybe this should be done within the AwsProvider and not in __main__.py
    def get_checks_to_execute_by_audit_resources(self) -> set[str]:
        """
        get_checks_to_execute_by_audit_resources gets the checks to execute based on the audit resources

        Returns:
            - set: set of strings representing the checks to execute
        """
        # Once the provider is set and we have the eventual checks from arn, it is time to exclude the others
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
            raise error

    @staticmethod
    def validate_credentials(
        session: Session,
        aws_region: str,
    ) -> AWSCallerIdentity:
        """
        Validates the AWS credentials using the provided session and AWS region.
        Args:
            session (Session): The AWS session object.
            aws_region (str): The AWS region to validate the credentials.
        Returns:
            AWSCallerIdentity: An object containing the caller identity information.
        Raises:
            Exception: If an error occurs during the validation process.
        """
        try:
            sts_client = AwsProvider.create_sts_session(session, aws_region)
            caller_identity = sts_client.get_caller_identity()
            # Include the region where the caller_identity has validated the credentials
            return AWSCallerIdentity(
                user_id=caller_identity.get("UserId"),
                account=caller_identity.get("Account"),
                arn=ARN(caller_identity.get("Arn")),
                region=aws_region,
            )
        except ClientError as client_error:
            logger.error(
                f"{client_error.__class__.__name__}[{client_error.__traceback__.tb_lineno}]: {client_error}"
            )
            if client_error.response["Error"]["Code"] == "InvalidClientTokenId":
                raise AWSAccessKeyIDInvalidError(
                    original_exception=client_error,
                    file=pathlib.Path(__file__).name,
                )
            elif client_error.response["Error"]["Code"] == "SignatureDoesNotMatch":
                raise AWSSecretAccessKeyInvalidError(
                    original_exception=client_error,
                    file=pathlib.Path(__file__).name,
                )
            elif client_error.response["Error"]["Code"] == "ExpiredToken":
                raise AWSSessionTokenExpiredError(
                    original_exception=client_error,
                    file=pathlib.Path(__file__).name,
                )
            else:
                raise AWSClientError(
                    original_exception=client_error,
                    file=pathlib.Path(__file__).name,
                )

        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise error

    @staticmethod
    def test_connection(
        profile: str = None,
        aws_region: str = AWS_STS_GLOBAL_ENDPOINT_REGION,
        role_arn: str = None,
        role_session_name: str = ROLE_SESSION_NAME,
        session_duration: int = 3600,
        external_id: str = None,
        mfa_enabled: bool = False,
        raise_on_exception: bool = True,
        aws_access_key_id: str = None,
        aws_secret_access_key: str = None,
        aws_session_token: Optional[str] = None,
        provider_id: Optional[str] = None,
    ) -> Connection:
        """
        Test the connection to AWS with one of the Boto3 credentials methods.

        Args:
            profile (str): The AWS profile to use for the session.
            aws_region (str): The AWS region to validate the credentials in.
            role_arn (str): The ARN of the IAM role to assume.
            role_session_name (str): The name of the role session.
            session_duration (int): The duration of the assumed role session in seconds.
            external_id (str): The external ID to use when assuming the role.
            mfa_enabled (bool): Whether MFA (Multi-Factor Authentication) is enabled.
            raise_on_exception (bool): Whether to raise an exception if an error occurs.
            aws_access_key_id (str): The AWS access key ID to use for the session.
            aws_secret_access_key (str): The AWS secret access key to use for the session.
            aws_session_token (str): The AWS session token to use for the session. Optional.
            provider_id (str): The AWS account ID to validate that the provided credentials belongs to it.

        Returns:
            Connection: An object tha contains the result of the test connection operation.
                - is_connected (bool): Indicates whether the validation was successful.
                - error (Exception): An exception object if an error occurs during the validation.

        Raises:
            ClientError: If there is an error with the AWS client.
            ProfileNotFound: If the specified profile is not found.
            NoCredentialsError: If there are no AWS credentials found.
            ArgumentTypeError: If there is a validation error with the arguments.
            Exception: If there is an unexpected error.

        Examples:
            >>> AwsProvider.test_connection(
                role_arn="arn:aws:iam::111122223333:role/ProwlerRole",
                external_id="67f7a641-ecb0-4f6d-921d-3587febd379c",
                raise_on_exception=False)
            )
            Connection(is_connected=True, Error=None)
            >>> AwsProvider.test_connection(profile="test", raise_on_exception=False)
            Connection(is_connected=True, Error=None)
            >>> AwsProvider.test_connection(profile="not-found", raise_on_exception=False))
            Connection(is_connected=False, Error=ProfileNotFound('The config profile (not-found) could not be found'))
            >>> AwsProvider.test_connection(raise_on_exception=False))
            Connection(is_connected=False, Error=NoCredentialsError('Unable to locate credentials'))
            >>> AwsProvider.test_connection(aws_access_key_id="XXXXXXXX", aws_secret_access_key="XXXXXXXX", raise_on_exception=False))
            Connection(is_connected=True, Error=None))
            >>> AwsProvider.test_connection(aws_access_key_id="XXXXXXXX", aws_secret_access_key="XXXXXXXX", provider_id="111122223333", raise_on_exception=False))
            Connection(is_connected=True, Error=None))
        """
        try:
            session = AwsProvider.setup_session(
                mfa=mfa_enabled,
                profile=profile,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
                aws_session_token=aws_session_token,
            )

            if role_arn:
                session_duration = validate_session_duration(session_duration)
                role_session_name = validate_role_session_name(role_session_name)
                role_arn = parse_iam_credentials_arn(role_arn)
                assumed_role_information = AWSAssumeRoleInfo(
                    role_arn=role_arn,
                    session_duration=session_duration,
                    external_id=external_id,
                    mfa_enabled=mfa_enabled,
                    role_session_name=role_session_name,
                )
                assumed_role_credentials = AwsProvider.assume_role(
                    session,
                    assumed_role_information,
                )
                session = Session(
                    aws_access_key_id=assumed_role_credentials.aws_access_key_id,
                    aws_secret_access_key=assumed_role_credentials.aws_secret_access_key,
                    aws_session_token=assumed_role_credentials.aws_session_token,
                    region_name=aws_region,
                    profile_name=profile,
                )

            caller_identity = AwsProvider.validate_credentials(session, aws_region)
            # Do an extra validation if the AWS account ID is provided
            if provider_id and caller_identity.account != provider_id:
                raise AWSInvalidProviderIdError(file=pathlib.Path(__file__).name)

            return Connection(
                is_connected=True,
            )

        except AWSSetUpSessionError as setup_session_error:
            logger.error(
                f"{setup_session_error.__class__.__name__}[{setup_session_error.__traceback__.tb_lineno}]: {setup_session_error}"
            )
            if raise_on_exception:
                raise setup_session_error
            return Connection(error=setup_session_error)

        except AWSArgumentTypeValidationError as validation_error:
            logger.error(
                f"{validation_error.__class__.__name__}[{validation_error.__traceback__.tb_lineno}]: {validation_error}"
            )
            if raise_on_exception:
                raise validation_error
            return Connection(error=validation_error)

        except AWSIAMRoleARNRegionNotEmtpyError as arn_region_not_empty_error:
            logger.error(
                f"{arn_region_not_empty_error.__class__.__name__}[{arn_region_not_empty_error.__traceback__.tb_lineno}]: {arn_region_not_empty_error}"
            )
            if raise_on_exception:
                raise arn_region_not_empty_error
            return Connection(error=arn_region_not_empty_error)

        except AWSIAMRoleARNPartitionEmptyError as arn_partition_empty_error:
            logger.error(
                f"{arn_partition_empty_error.__class__.__name__}[{arn_partition_empty_error.__traceback__.tb_lineno}]: {arn_partition_empty_error}"
            )
            if raise_on_exception:
                raise arn_partition_empty_error
            return Connection(error=arn_partition_empty_error)

        except AWSIAMRoleARNServiceNotIAMnorSTSError as arn_service_not_iam_sts_error:
            logger.error(
                f"{arn_service_not_iam_sts_error.__class__.__name__}[{arn_service_not_iam_sts_error.__traceback__.tb_lineno}]: {arn_service_not_iam_sts_error}"
            )
            if raise_on_exception:
                raise arn_service_not_iam_sts_error
            return Connection(error=arn_service_not_iam_sts_error)

        except AWSIAMRoleARNInvalidAccountIDError as arn_invalid_account_id_error:
            logger.error(
                f"{arn_invalid_account_id_error.__class__.__name__}[{arn_invalid_account_id_error.__traceback__.tb_lineno}]: {arn_invalid_account_id_error}"
            )
            if raise_on_exception:
                raise arn_invalid_account_id_error
            return Connection(error=arn_invalid_account_id_error)

        except AWSIAMRoleARNInvalidResourceTypeError as arn_invalid_resource_type_error:
            logger.error(
                f"{arn_invalid_resource_type_error.__class__.__name__}[{arn_invalid_resource_type_error.__traceback__.tb_lineno}]: {arn_invalid_resource_type_error}"
            )
            if raise_on_exception:
                raise arn_invalid_resource_type_error
            return Connection(error=arn_invalid_resource_type_error)

        except AWSIAMRoleARNEmptyResourceError as arn_empty_resource_error:
            logger.error(
                f"{arn_empty_resource_error.__class__.__name__}[{arn_empty_resource_error.__traceback__.tb_lineno}]: {arn_empty_resource_error}"
            )
            if raise_on_exception:
                raise arn_empty_resource_error
            return Connection(error=arn_empty_resource_error)

        except AWSAssumeRoleError as assume_role_error:
            logger.error(
                f"{assume_role_error.__class__.__name__}[{assume_role_error.__traceback__.tb_lineno}]: {assume_role_error}"
            )
            if raise_on_exception:
                raise assume_role_error
            return Connection(error=assume_role_error)

        except ClientError as client_error:
            logger.error(
                f"AWSClientError[{client_error.__traceback__.tb_lineno}]: {client_error}"
            )
            if raise_on_exception:
                raise AWSClientError(
                    file=os.path.basename(__file__), original_exception=client_error
                ) from client_error
            return Connection(error=client_error)

        except ProfileNotFound as profile_not_found_error:
            logger.error(
                f"AWSProfileNotFoundError[{profile_not_found_error.__traceback__.tb_lineno}]: {profile_not_found_error}"
            )
            if raise_on_exception:
                raise AWSProfileNotFoundError(
                    file=os.path.basename(__file__),
                    original_exception=profile_not_found_error,
                ) from profile_not_found_error
            return Connection(error=profile_not_found_error)

        except NoCredentialsError as no_credentials_error:
            logger.error(
                f"AWSNoCredentialsError[{no_credentials_error.__traceback__.tb_lineno}]: {no_credentials_error}"
            )
            if raise_on_exception:
                raise AWSNoCredentialsError(
                    file=os.path.basename(__file__),
                    original_exception=no_credentials_error,
                ) from no_credentials_error
            return Connection(error=no_credentials_error)

        except AWSAccessKeyIDInvalidError as access_key_id_invalid_error:
            logger.error(
                f"{access_key_id_invalid_error.__class__.__name__}[{access_key_id_invalid_error.__traceback__.tb_lineno}]: {access_key_id_invalid_error}"
            )
            if raise_on_exception:
                raise access_key_id_invalid_error
            return Connection(error=access_key_id_invalid_error)

        except AWSSecretAccessKeyInvalidError as secret_access_key_invalid_error:
            logger.error(
                f"{secret_access_key_invalid_error.__class__.__name__}[{secret_access_key_invalid_error.__traceback__.tb_lineno}]: {secret_access_key_invalid_error}"
            )
            if raise_on_exception:
                raise secret_access_key_invalid_error
            return Connection(error=secret_access_key_invalid_error)

        except AWSInvalidProviderIdError as invalid_account_credentials_error:
            logger.error(
                f"{invalid_account_credentials_error.__class__.__name__}[{invalid_account_credentials_error.__traceback__.tb_lineno}]: {invalid_account_credentials_error}"
            )
            if raise_on_exception:
                raise invalid_account_credentials_error
            return Connection(error=invalid_account_credentials_error)

        except AWSSessionTokenExpiredError as session_token_expired:
            logger.error(
                f"{session_token_expired.__class__.__name__}[{session_token_expired.__traceback__.tb_lineno}]: {session_token_expired}"
            )
            if raise_on_exception:
                raise session_token_expired
            return Connection(error=session_token_expired)

        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise error
            return Connection(error=error)

    @staticmethod
    def create_sts_session(
        session: Session, aws_region: str = AWS_STS_GLOBAL_ENDPOINT_REGION
    ) -> Session.client:
        """
        Create an STS session client.

        Args:
        - session (session.Session): The AWS session object.
        - aws_region (str): The AWS region to use for the session.

        Returns:
        - session.Session.client: The STS session client.

        Example:
            session = boto3.session.Session()
            sts_client = create_sts_session(session, 'us-west-2')
        """
        try:
            sts_endpoint_url = (
                f"https://sts.{aws_region}.amazonaws.com"
                if not aws_region.startswith("cn-")
                else f"https://sts.{aws_region}.amazonaws.com.cn"
            )
            return session.client("sts", aws_region, endpoint_url=sts_endpoint_url)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise error

    @staticmethod
    def get_regions(partition: Partition = Partition.aws) -> set:
        """
        Get the available AWS regions from the AWS services JSON file with the ability of filtering by partition.

        Args:
            partition (str): The AWS partition to retrieve regions for. Defaults to "aws".

        Returns:
            set: A set of region names.

        Raises:
            AWSInvalidPartitionError: If the provided partition name is invalid.

        Example:
            >>> AwsProvider.get_regions("aws")
            {"af-south-1"}
        """

        try:
            regions = set()
            data = read_aws_regions_file()

            if partition is None:
                for service in data["services"].values():
                    for partition in service["regions"]:
                        regions.update(service["regions"][partition])
            else:
                partition = Partition(partition)
                for service in data["services"].values():
                    regions.update(service["regions"][partition.value])

            return regions
        except ValueError as value_error:
            logger.error(
                f"{value_error.__class__.__name__}[{value_error.__traceback__.tb_lineno}]: {value_error}"
            )
            raise AWSInvalidPartitionError(
                message=f"Invalid partition: {partition}",
                file=os.path.basename(__file__),
            )
        except KeyError as key_error:
            logger.error(
                f"{key_error.__class__.__name__}[{key_error.__traceback__.tb_lineno}]: {key_error}"
            )
            raise AWSInvalidPartitionError(
                message=f"Invalid partition: {partition}",
                file=os.path.basename(__file__),
            )
        except Exception as error:
            logger.error(f"{error.__class__.__name__}: {error}")
            raise error


def read_aws_regions_file() -> dict:
    """
    Reads the AWS services JSON file and returns the parsed data as a dictionary.

    Returns:
        dict: The parsed data from the AWS services JSON file.
    """
    # Get JSON locally
    actual_directory = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
    with open_file(f"{actual_directory}/{aws_services_json_file}") as f:
        data = parse_json_file(f)

    return data


# TODO: This can be moved to another class since it doesn't need self
def get_aws_region_for_sts(session_region: str, regions: set[str]) -> str:
    """
    Get the AWS region for the STS Assume Role operation.

    Args:
        - session_region (str): The region configured in the AWS session.
        - regions (set[str]): The regions passed with the -f/--region/--filter-region option.

    Returns:
        str: The AWS region for the STS Assume Role operation

    Example:
        aws_region = get_aws_region_for_sts(session_region, regions)
    """
    # If there is no region passed with -f/--region/--filter-region
    if regions is None or len(regions) == 0:
        # If you have a region configured in your AWS config or credentials file
        if session_region is not None:
            aws_region = session_region
        else:
            # If there is no region set passed with -f/--region
            # we use the Global STS Endpoint Region, us-east-1
            aws_region = AWS_STS_GLOBAL_ENDPOINT_REGION
    else:
        # Get the first region passed to the -f/--region
        aws_region = list(regions)[0]

    return aws_region


# TODO: this duplicates the provider arguments validation library
def validate_session_duration(duration: int) -> int:
    """
    validate_session_duration validates that the AWS STS Assume Role Session Duration is between 900 and 43200 seconds.

    Args:
        duration (int): The session duration in seconds.

    Returns:
        int: The validated session duration.

    Raises:
        ArgumentTypeError: If the session duration is not within the valid range.
    """
    duration = int(duration)
    # Since the range(i,j) goes from i to j-1 we have to j+1
    if duration not in range(900, 43201):
        raise AWSArgumentTypeValidationError(
            message="Session Duration must be between 900 and 43200 seconds.",
            file=os.path.basename(__file__),
        )
    else:
        return duration


# TODO: this duplicates the provider arguments validation library
def validate_role_session_name(session_name) -> str:
    """
    Validates that the role session name is valid.

    Args:
        session_name (str): The role session name to be validated.

    Returns:
        str: The validated role session name.

    Raises:
        ArgumentTypeError: If the role session name is invalid.

    Documentation:
        - AWS STS AssumeRole API: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
    """
    if fullmatch(r"[\w+=,.@-]{2,64}", session_name):
        return session_name
    else:
        raise AWSArgumentTypeValidationError(
            file=os.path.basename(__file__),
            message="Role Session Name must be between 2 and 64 characters and may contain alphanumeric characters, periods, hyphens, and underscores.",
        )
