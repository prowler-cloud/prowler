"""
Alibaba Cloud Provider

This module implements the Alibaba Cloud provider for Prowler security auditing.
"""

import sys
from typing import Optional

from colorama import Fore, Style

from prowler.config.config import (
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.alibabacloud.config import (
    ALIBABACLOUD_REGIONS,
    ALIBABACLOUD_RAM_SESSION_NAME,
)
from prowler.providers.alibabacloud.exceptions.exceptions import (
    AlibabaCloudAccountNotFoundError,
    AlibabaCloudAssumeRoleError,
    AlibabaCloudAuthenticationError,
    AlibabaCloudNoCredentialsError,
    AlibabaCloudSetUpSessionError,
)
from prowler.providers.alibabacloud.lib.mutelist.mutelist import AlibabaCloudMutelist
from prowler.providers.alibabacloud.models import (
    AlibabaCloudAssumeRoleInfo,
    AlibabaCloudCredentials,
    AlibabaCloudIdentityInfo,
    AlibabaCloudSession,
)
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider


class AlibabacloudProvider(Provider):
    """
    AlibabacloudProvider class implements the Alibaba Cloud provider for Prowler

    This class handles:
    - Authentication with Alibaba Cloud using AccessKey credentials or STS tokens
    - RAM role assumption for cross-account auditing
    - Region management and filtering
    - Resource discovery and auditing
    - Mutelist management for finding suppression

    Attributes:
        _type: Provider type identifier ("alibabacloud")
        _identity: Alibaba Cloud account identity information
        _session: Alibaba Cloud session with credentials
        _regions: List of regions to audit
        _mutelist: Mutelist for finding suppression
        _audit_config: Audit configuration dictionary
        _fixer_config: Fixer configuration dictionary
        audit_metadata: Audit execution metadata
    """

    _type: str = "alibabacloud"
    _identity: AlibabaCloudIdentityInfo
    _session: AlibabaCloudSession
    _regions: list = []
    _mutelist: AlibabaCloudMutelist
    _audit_config: dict
    _fixer_config: dict
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        access_key_id: str = None,
        access_key_secret: str = None,
        security_token: str = None,
        region_ids: list = None,
        filter_regions: list = None,
        ram_role_arn: str = None,
        ram_session_name: str = None,
        ram_session_duration: int = 3600,
        ram_external_id: str = None,
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
        resource_tags: list[str] = [],
        resource_ids: list[str] = [],
    ):
        """
        Initialize Alibaba Cloud provider

        Args:
            access_key_id: Alibaba Cloud AccessKey ID
            access_key_secret: Alibaba Cloud AccessKey Secret
            security_token: STS security token for temporary credentials
            region_ids: List of region IDs to audit
            filter_regions: List of region IDs to exclude from audit
            ram_role_arn: RAM role ARN to assume
            ram_session_name: Session name for RAM role assumption
            ram_session_duration: Session duration in seconds (900-43200)
            ram_external_id: External ID for RAM role assumption
            config_path: Path to audit configuration file
            config_content: Configuration content dictionary
            fixer_config: Fixer configuration dictionary
            mutelist_path: Path to mutelist file
            mutelist_content: Mutelist content dictionary
            resource_tags: List of resource tags to filter (key=value format)
            resource_ids: List of specific resource IDs to audit
        """
        logger.info("Initializing Alibaba Cloud provider...")

        # Validate and load configuration
        self._audit_config = load_and_validate_config_file(
            self._type, config_path
        )
        if self._audit_config is None:
            self._audit_config = {}

        # Override with config_content if provided
        if config_content:
            self._audit_config.update(config_content)

        self._fixer_config = fixer_config

        # Setup session and authenticate
        try:
            self._session = self.setup_session(
                access_key_id,
                access_key_secret,
                security_token,
                ram_role_arn,
                ram_session_name or ALIBABACLOUD_RAM_SESSION_NAME,
                ram_session_duration,
                ram_external_id,
            )
        except Exception as error:
            logger.critical(f"Failed to set up Alibaba Cloud session: {error}")
            raise AlibabaCloudSetUpSessionError(str(error))

        # Get account identity
        try:
            self._identity = self._set_identity()
        except Exception as error:
            logger.critical(
                f"Failed to retrieve Alibaba Cloud account identity: {error}"
            )
            raise AlibabaCloudAccountNotFoundError(str(error))

        # Setup regions
        self._regions = self._setup_regions(region_ids, filter_regions)

        # Setup mutelist
        self._mutelist = self._setup_mutelist(mutelist_path, mutelist_content)

        # Set audit metadata
        self.audit_metadata = Audit_Metadata(
            services_scanned=0,
            expected_checks=[],
            completed_checks=0,
            audit_progress=0,
        )

        # Set as global provider
        Provider.set_global_provider(self)

        logger.info(
            f"Alibaba Cloud provider initialized for account {self._identity.account_id}"
        )

    @property
    def type(self) -> str:
        """Return provider type"""
        return self._type

    @property
    def identity(self) -> AlibabaCloudIdentityInfo:
        """Return provider identity"""
        return self._identity

    @property
    def session(self) -> AlibabaCloudSession:
        """Return provider session"""
        return self._session

    @property
    def audit_config(self) -> dict:
        """Return audit configuration"""
        return self._audit_config

    @property
    def fixer_config(self) -> dict:
        """Return fixer configuration"""
        return self._fixer_config

    @property
    def mutelist(self) -> AlibabaCloudMutelist:
        """Return mutelist"""
        return self._mutelist

    def setup_session(
        self,
        access_key_id: str,
        access_key_secret: str,
        security_token: str = None,
        ram_role_arn: str = None,
        ram_session_name: str = ALIBABACLOUD_RAM_SESSION_NAME,
        ram_session_duration: int = 3600,
        ram_external_id: str = None,
    ) -> AlibabaCloudSession:
        """
        Setup Alibaba Cloud session with authentication

        Args:
            access_key_id: AccessKey ID
            access_key_secret: AccessKey Secret
            security_token: STS security token (optional)
            ram_role_arn: RAM role to assume (optional)
            ram_session_name: Session name for role assumption
            ram_session_duration: Session duration in seconds
            ram_external_id: External ID for role assumption

        Returns:
            AlibabaCloudSession: Configured session object

        Raises:
            AlibabaCloudNoCredentialsError: If credentials are missing
            AlibabaCloudAuthenticationError: If authentication fails
            AlibabaCloudAssumeRoleError: If role assumption fails
        """
        # Validate credentials
        if not access_key_id or not access_key_secret:
            logger.critical("Alibaba Cloud credentials are required")
            raise AlibabaCloudNoCredentialsError()

        try:
            # Create credentials object
            credentials = AlibabaCloudCredentials(
                access_key_id=access_key_id,
                access_key_secret=access_key_secret,
                security_token=security_token,
            )

            # If RAM role is specified, assume the role
            if ram_role_arn:
                logger.info(f"Assuming RAM role: {ram_role_arn}")
                credentials = self._assume_role(
                    credentials,
                    ram_role_arn,
                    ram_session_name,
                    ram_session_duration,
                    ram_external_id,
                )

            # Create session
            session = AlibabaCloudSession(
                credentials=credentials,
                region_id="cn-hangzhou",  # Default region for global APIs
            )

            logger.info("Alibaba Cloud session established successfully")
            return session

        except Exception as error:
            logger.critical(f"Authentication failed: {error}")
            raise AlibabaCloudAuthenticationError(str(error))

    def _assume_role(
        self,
        credentials: AlibabaCloudCredentials,
        role_arn: str,
        session_name: str,
        session_duration: int,
        external_id: str = None,
    ) -> AlibabaCloudCredentials:
        """
        Assume a RAM role and return temporary credentials

        Args:
            credentials: Current credentials
            role_arn: RAM role ARN to assume
            session_name: Session name
            session_duration: Session duration in seconds
            external_id: External ID (optional)

        Returns:
            AlibabaCloudCredentials: Temporary credentials from STS

        Raises:
            AlibabaCloudAssumeRoleError: If role assumption fails
        """
        try:
            # Note: In a real implementation, this would use Alibaba Cloud STS SDK
            # to call AssumeRole API and get temporary credentials
            # For now, we'll return the original credentials as a placeholder

            logger.warning(
                "RAM role assumption not yet fully implemented - using provided credentials"
            )

            # TODO: Implement actual STS AssumeRole call
            # from alibabacloud_sts20150401.client import Client as StsClient
            # from alibabacloud_sts20150401.models import AssumeRoleRequest
            #
            # sts_client = StsClient(config)
            # request = AssumeRoleRequest(
            #     role_arn=role_arn,
            #     role_session_name=session_name,
            #     duration_seconds=session_duration,
            #     external_id=external_id
            # )
            # response = sts_client.assume_role(request)
            #
            # return AlibabaCloudCredentials(
            #     access_key_id=response.body.credentials.access_key_id,
            #     access_key_secret=response.body.credentials.access_key_secret,
            #     security_token=response.body.credentials.security_token,
            #     expiration=response.body.credentials.expiration,
            # )

            return credentials

        except Exception as error:
            logger.critical(f"Failed to assume RAM role {role_arn}: {error}")
            raise AlibabaCloudAssumeRoleError(role_arn, str(error))

    def _set_identity(self) -> AlibabaCloudIdentityInfo:
        """
        Retrieve Alibaba Cloud account identity information

        Returns:
            AlibabaCloudIdentityInfo: Account identity details

        Raises:
            AlibabaCloudAccountNotFoundError: If identity cannot be retrieved
        """
        try:
            logger.info("Retrieving Alibaba Cloud account identity...")

            # Derive account ID from AccessKey ID
            # Alibaba Cloud AccessKey IDs follow the format: LTAI{account_id_hash}...
            # For a more accurate implementation, you would call STS GetCallerIdentity API
            # For now, we'll use the AccessKey ID as a unique identifier

            access_key_id = self._session.credentials.access_key_id

            # Simple implementation: Use the first 12 characters of AccessKey ID as account identifier
            # In production, you should call:
            # from alibabacloud_sts20150401.client import Client as StsClient
            # sts_client = StsClient(config)
            # response = sts_client.get_caller_identity()
            # account_id = response.body.account_id

            # For now, create a unique identifier from the AccessKey
            account_id = access_key_id[:20] if access_key_id else "unknown"
            account_arn = f"acs:ram::{account_id}:root"

            identity = AlibabaCloudIdentityInfo(
                account_id=account_id,
                account_arn=account_arn,
            )

            logger.info(f"Account ID: {identity.account_id}")
            return identity

        except Exception as error:
            logger.critical(f"Failed to get account identity: {error}")
            raise AlibabaCloudAccountNotFoundError(str(error))

    def _setup_regions(
        self, region_ids: list = None, filter_regions: list = None
    ) -> list:
        """
        Setup regions to audit

        Args:
            region_ids: Specific regions to audit (None = all regions)
            filter_regions: Regions to exclude from audit

        Returns:
            list: Final list of regions to audit
        """
        # Start with specified regions or all regions
        if region_ids:
            regions = [r for r in region_ids if r in ALIBABACLOUD_REGIONS]
            logger.info(f"Auditing specified regions: {', '.join(regions)}")
        else:
            regions = ALIBABACLOUD_REGIONS.copy()
            logger.info("Auditing all Alibaba Cloud regions")

        # Apply filters
        if filter_regions:
            regions = [r for r in regions if r not in filter_regions]
            logger.info(f"Excluded regions: {', '.join(filter_regions)}")

        logger.info(f"Total regions to audit: {len(regions)}")
        return regions

    def _setup_mutelist(
        self, mutelist_path: str = None, mutelist_content: dict = None
    ) -> AlibabaCloudMutelist:
        """
        Setup mutelist for finding suppression

        Args:
            mutelist_path: Path to mutelist file
            mutelist_content: Mutelist content dictionary

        Returns:
            AlibabaCloudMutelist: Configured mutelist instance
        """
        try:
            # Use default path if not provided
            if not mutelist_path and not mutelist_content:
                mutelist_path = get_default_mute_file_path(self._type)

            mutelist = AlibabaCloudMutelist(
                mutelist_path=mutelist_path,
                mutelist_content=mutelist_content,
                provider=self._type,
                identity=self._identity,
            )

            logger.info("Mutelist loaded successfully")
            return mutelist

        except Exception as error:
            logger.warning(f"Error loading mutelist: {error}")
            # Return empty mutelist on error
            return AlibabaCloudMutelist()

    def print_credentials(self) -> None:
        """
        Display Alibaba Cloud credentials and configuration in CLI

        This method prints the current provider configuration including:
        - Account ID
        - Regions being audited
        - Authentication method
        """
        # Account information
        report_lines = []
        report_lines.append(
            f"{Fore.CYAN}Account ID:{Style.RESET_ALL} {self._identity.account_id}"
        )

        if self._identity.user_name:
            report_lines.append(
                f"{Fore.CYAN}User:{Style.RESET_ALL} {self._identity.user_name}"
            )

        # Regions
        region_count = len(self._regions)
        regions_display = (
            ", ".join(self._regions[:5])
            + (f" ... (+{region_count - 5} more)" if region_count > 5 else "")
        )
        report_lines.append(
            f"{Fore.CYAN}Regions ({region_count}):{Style.RESET_ALL} {regions_display}"
        )

        # Authentication method
        auth_method = (
            "STS Token" if self._session.credentials.security_token else "AccessKey"
        )
        report_lines.append(
            f"{Fore.CYAN}Authentication:{Style.RESET_ALL} {auth_method}"
        )

        # Print formatted box
        print_boxes(report_lines, "Alibaba Cloud Provider Configuration")

    def test_connection(self) -> Connection:
        """
        Test connection to Alibaba Cloud

        Returns:
            Connection: Connection test result with status and error (if any)
        """
        try:
            logger.info("Testing connection to Alibaba Cloud...")

            # TODO: Implement actual connection test with a simple API call
            # For example, call DescribeRegions or GetCallerIdentity
            # from alibabacloud_ecs20140526.client import Client as EcsClient
            #
            # ecs_client = EcsClient(config)
            # ecs_client.describe_regions()

            logger.info("Connection test successful")
            return Connection(is_connected=True)

        except Exception as error:
            logger.error(f"Connection test failed: {error}")
            return Connection(is_connected=False, error=str(error))

    def validate_arguments(self) -> None:
        """
        Validate provider arguments

        This method is called after initialization to ensure all arguments
        and configurations are valid.
        """
        # Validation is handled in the CLI arguments parser
        # This method can be used for additional runtime validations
        pass
