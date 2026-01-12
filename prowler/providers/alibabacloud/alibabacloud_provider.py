import os
import pathlib

from alibabacloud_credentials.client import Client as CredClient
from alibabacloud_credentials.models import Config as CredConfig
from alibabacloud_sts20150401.client import Client as StsClient
from alibabacloud_tea_openapi import models as open_api_models
from colorama import Fore, Style

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.alibabacloud.config import (
    ALIBABACLOUD_DEFAULT_REGION,
    ALIBABACLOUD_REGIONS,
    ROLE_SESSION_NAME,
)
from prowler.providers.alibabacloud.exceptions.exceptions import (
    AlibabaCloudInvalidCredentialsError,
    AlibabaCloudNoCredentialsError,
    AlibabaCloudSetUpSessionError,
)
from prowler.providers.alibabacloud.lib.mutelist.mutelist import AlibabaCloudMutelist
from prowler.providers.alibabacloud.models import (
    AlibabaCloudCallerIdentity,
    AlibabaCloudIdentityInfo,
    AlibabaCloudSession,
)
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider


class AlibabacloudProvider(Provider):
    """
    AlibabacloudProvider class is the main class for the Alibaba Cloud provider.

    This class is responsible for initializing the Alibaba Cloud provider, setting up the session,
    validating the credentials, and setting the identity.

    Attributes:
        _type (str): The provider type.
        _identity (AlibabaCloudIdentityInfo): The Alibaba Cloud provider identity information.
        _session (AlibabaCloudSession): The Alibaba Cloud provider session.
        _audit_resources (list): The list of resources to audit.
        _audit_config (dict): The audit configuration.
        _enabled_regions (set): The set of enabled regions.
        _mutelist (AlibabaCloudMutelist): The Alibaba Cloud provider mutelist.
        audit_metadata (Audit_Metadata): The audit metadata.
    """

    _type: str = "alibabacloud"
    _identity: AlibabaCloudIdentityInfo
    _session: AlibabaCloudSession
    _audit_resources: list = []
    _audit_config: dict
    _fixer_config: dict
    _regions: list = []
    _mutelist: AlibabaCloudMutelist
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        role_arn: str = None,
        role_session_name: str = None,
        ecs_ram_role: str = None,
        oidc_role_arn: str = None,
        credentials_uri: str = None,
        regions: list = None,
        config_path: str = None,
        config_content: dict = None,
        mutelist_path: str = None,
        mutelist_content: dict = None,
        fixer_config: dict = {},
        access_key_id: str = None,
        access_key_secret: str = None,
        security_token: str = None,
    ):
        """
        Initialize the AlibabaCloudProvider.

        Args:
            role_arn: ARN of the RAM role to assume
            role_session_name: Session name when assuming the RAM role
            ecs_ram_role: Name of the RAM role attached to an ECS instance
            oidc_role_arn: ARN of the RAM role for OIDC authentication
            credentials_uri: URI to retrieve credentials from an external service
            regions: List of Alibaba Cloud region IDs to audit (if None, audits all available regions)
            config_path: Path to the configuration file
            config_content: Content of the configuration file
            mutelist_path: Path to the mutelist file
            mutelist_content: Content of the mutelist file
            fixer_config: Fixer configuration dictionary
            access_key_id: Alibaba Cloud Access Key ID
            access_key_secret: Alibaba Cloud Access Key Secret
            security_token: STS Security Token (for temporary credentials)

        Raises:
            AlibabaCloudSetUpSessionError: If an error occurs during the setup process.
            AlibabaCloudInvalidCredentialsError: If authentication fails.

        Usage:
            - Alibaba Cloud Credentials SDK is used, so we follow their credential setup process:
                - Authentication: Make sure you have properly configured your credentials with environment variables.
                    - export ALIBABA_CLOUD_ACCESS_KEY_ID=<access_key>
                    - export ALIBABA_CLOUD_ACCESS_KEY_SECRET=<secret_key>
                    or use other authentication methods (ECS RAM role, OIDC, etc.)
                - To create a new Alibaba Cloud provider object:
                    - alibabacloud = AlibabacloudProvider()  # Audits all regions
                    - alibabacloud = AlibabacloudProvider(regions=["cn-hangzhou", "cn-shanghai"])  # Specific regions
                    - alibabacloud = AlibabacloudProvider(role_arn="acs:ram::...:role/ProwlerRole")
                    - alibabacloud = AlibabacloudProvider(ecs_ram_role="ECS-Prowler-Role")
                    - alibabacloud = AlibabacloudProvider(access_key_id="LTAI...", access_key_secret="...")
        """
        logger.info("Initializing Alibaba Cloud Provider ...")

        # Setup Alibaba Cloud Session
        logger.info("Setting up Alibaba Cloud session ...")
        self._session = self.setup_session(
            role_arn=role_arn,
            role_session_name=role_session_name,
            ecs_ram_role=ecs_ram_role,
            oidc_role_arn=oidc_role_arn,
            credentials_uri=credentials_uri,
            access_key_id=access_key_id,
            access_key_secret=access_key_secret,
            security_token=security_token,
        )
        logger.info("Alibaba Cloud session configured successfully")

        # Validate credentials
        logger.info("Validating credentials ...")
        caller_identity = self.validate_credentials(
            session=self._session,
            region=ALIBABACLOUD_DEFAULT_REGION,
        )
        logger.info("Credentials validated")

        # Get profile region
        profile_region = self.get_profile_region()

        # Set identity
        self._identity = self.set_identity(
            caller_identity=caller_identity,
            profile="default",
            regions=set(),
            profile_region=profile_region,
        )

        # Populate account alias if available
        account_alias = self.get_account_alias()
        if account_alias:
            self._identity.account_name = account_alias

        # Get regions
        self._regions = self.get_regions_to_audit(regions)

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
            self._mutelist = AlibabaCloudMutelist(
                mutelist_content=mutelist_content,
                account_id=self._identity.account_id,
            )
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = AlibabaCloudMutelist(
                mutelist_path=mutelist_path,
                account_id=self._identity.account_id,
            )

        # Set up audit resources (for filtering)
        # Note: resource_tags not yet supported in AlibabaCloud provider CLI args
        self._audit_resources = []

        # Create audit metadata
        self.audit_metadata = Audit_Metadata(
            services_scanned=0,
            expected_checks=[],
            completed_checks=0,
            audit_progress=0,
        )

        Provider.set_global_provider(self)

    @property
    def type(self) -> str:
        return self._type

    @property
    def identity(self) -> AlibabaCloudIdentityInfo:
        return self._identity

    @property
    def session(self):
        return self._session

    @property
    def audit_config(self) -> dict:
        return self._audit_config

    @property
    def fixer_config(self) -> dict:
        return self._fixer_config

    @property
    def audit_resources(self) -> list:
        return self._audit_resources

    @property
    def mutelist(self) -> AlibabaCloudMutelist:
        return self._mutelist

    @property
    def regions(self) -> list:
        return self._regions

    @property
    def enabled_regions(self) -> set:
        """
        Backward compatibility property for existing checks.
        Returns a set of region IDs.
        """
        return set([r.region_id for r in self._regions])

    @staticmethod
    def setup_session(
        role_arn: str = None,
        role_session_name: str = None,
        ecs_ram_role: str = None,
        oidc_role_arn: str = None,
        credentials_uri: str = None,
        access_key_id: str = None,
        access_key_secret: str = None,
        security_token: str = None,
    ) -> AlibabaCloudSession:
        """
        Set up the Alibaba Cloud session.

        Args:
            role_arn: ARN of the RAM role to assume
            role_session_name: Session name when assuming the RAM role
            ecs_ram_role: Name of the RAM role attached to an ECS instance
            oidc_role_arn: ARN of the RAM role for OIDC authentication
            credentials_uri: URI to retrieve credentials from an external service
            access_key_id: Alibaba Cloud Access Key ID
            access_key_secret: Alibaba Cloud Access Key Secret
            security_token: STS Security Token (for temporary credentials)

        Returns:
            AlibabaCloudSession object

        Raises:
            AlibabaCloudSetUpSessionError: If session setup fails
        """
        try:
            logger.debug("Creating Alibaba Cloud session ...")

            # Create credentials configuration
            config = CredConfig()

            # Check for OIDC authentication parameters
            oidc_provider_arn = None
            oidc_token_file = None

            if oidc_role_arn and "ALIBABA_CLOUD_OIDC_PROVIDER_ARN" in os.environ:
                oidc_provider_arn = os.environ["ALIBABA_CLOUD_OIDC_PROVIDER_ARN"]

            if "ALIBABA_CLOUD_OIDC_TOKEN_FILE" in os.environ:
                oidc_token_file = os.environ["ALIBABA_CLOUD_OIDC_TOKEN_FILE"]

            # Check for credentials URI
            if not credentials_uri and "ALIBABA_CLOUD_CREDENTIALS_URI" in os.environ:
                credentials_uri = os.environ["ALIBABA_CLOUD_CREDENTIALS_URI"]

            # Check for ECS RAM role name (for ECS instance metadata credentials)
            if not ecs_ram_role and "ALIBABA_CLOUD_ECS_METADATA" in os.environ:
                ecs_ram_role = os.environ["ALIBABA_CLOUD_ECS_METADATA"]

            # Check for access key credentials from parameters first, then fall back to environment variables
            # Support both ALIBABA_CLOUD_* and ALIYUN_* prefixes for compatibility
            if not access_key_id:
                if "ALIBABA_CLOUD_ACCESS_KEY_ID" in os.environ:
                    access_key_id = os.environ["ALIBABA_CLOUD_ACCESS_KEY_ID"]
                elif "ALIYUN_ACCESS_KEY_ID" in os.environ:
                    access_key_id = os.environ["ALIYUN_ACCESS_KEY_ID"]

            if not access_key_secret:
                if "ALIBABA_CLOUD_ACCESS_KEY_SECRET" in os.environ:
                    access_key_secret = os.environ["ALIBABA_CLOUD_ACCESS_KEY_SECRET"]
                elif "ALIYUN_ACCESS_KEY_SECRET" in os.environ:
                    access_key_secret = os.environ["ALIYUN_ACCESS_KEY_SECRET"]

            # Check for STS security token (for temporary credentials)
            if not security_token and "ALIBABA_CLOUD_SECURITY_TOKEN" in os.environ:
                security_token = os.environ["ALIBABA_CLOUD_SECURITY_TOKEN"]

            # Check for RAM role assumption from CLI arguments or environment
            if (
                not role_arn
                and "ALIBABA_CLOUD_ROLE_ARN" in os.environ
                and not oidc_provider_arn
            ):
                # Only use ALIBABA_CLOUD_ROLE_ARN for RAM role assumption if OIDC is not configured
                role_arn = os.environ["ALIBABA_CLOUD_ROLE_ARN"]

            if not role_session_name:
                if "ALIBABA_CLOUD_ROLE_SESSION_NAME" in os.environ:
                    role_session_name = os.environ["ALIBABA_CLOUD_ROLE_SESSION_NAME"]
            else:
                role_session_name = ROLE_SESSION_NAME  # Default from config.py

            # Priority order for credential types:
            # 1. Credentials URI (for external credential services)
            # 2. OIDC role ARN (for OIDC authentication in ACK/Kubernetes)
            # 3. ECS RAM role (if running on ECS instance)
            # 4. RAM role assumption (with access keys)
            # 5. STS temporary credentials (with access keys and token)
            # 6. Permanent access keys
            # 7. Default credential chain (includes config file ~/.aliyun/config.json)

            if credentials_uri:
                # Use URI to retrieve credentials from external service
                config.type = "credentials_uri"
                config.credentials_uri = credentials_uri
                logger.info(f"Using credentials URI: {credentials_uri}")
            elif oidc_role_arn and oidc_provider_arn and oidc_token_file:
                # Use OIDC authentication
                config.type = "oidc_role_arn"
                config.role_arn = oidc_role_arn
                config.oidc_provider_arn = oidc_provider_arn
                config.oidc_token_file_path = oidc_token_file
                config.role_session_name = role_session_name
                logger.info(f"Using OIDC role assumption: {oidc_role_arn}")
            elif ecs_ram_role:
                # Use ECS instance metadata service to get credentials
                config.type = "ecs_ram_role"
                config.role_name = ecs_ram_role
                logger.info(f"Using ECS RAM role credentials: {ecs_ram_role}")
            elif access_key_id and access_key_secret:
                # If RAM role is provided, use role assumption (SDK will automatically manage STS tokens)
                if role_arn:
                    config.type = "ram_role_arn"
                    config.access_key_id = access_key_id
                    config.access_key_secret = access_key_secret
                    config.role_arn = role_arn
                    config.role_session_name = role_session_name
                    logger.info(
                        f"Using RAM role assumption: {role_arn} with session name: {role_session_name}"
                    )
                # If security token is provided, use STS credentials
                elif security_token:
                    config.type = "sts"
                    config.access_key_id = access_key_id
                    config.access_key_secret = access_key_secret
                    config.security_token = security_token
                    logger.info("Using STS temporary credentials")
                else:
                    config.type = "access_key"
                    config.access_key_id = access_key_id
                    config.access_key_secret = access_key_secret
                    logger.info("Using access key credentials")
            else:
                # Try to use default credential chain
                logger.info(
                    "No explicit credentials provided, using default credential chain"
                )

            # Create credential client
            try:
                cred_client = CredClient(config)
            except Exception as error:
                if "invalid type option" in str(error):
                    raise AlibabaCloudNoCredentialsError(
                        file=pathlib.Path(__file__).name,
                    )
                raise error

            # Verify credentials by getting them
            try:
                cred = cred_client.get_credential()
                if not cred.get_access_key_id() or not cred.get_access_key_secret():
                    raise AlibabaCloudNoCredentialsError(
                        file=pathlib.Path(__file__).name,
                    )
            except AlibabaCloudNoCredentialsError:
                raise
            except Exception as error:
                raise AlibabaCloudInvalidCredentialsError(
                    file=pathlib.Path(__file__).name,
                    original_exception=error,
                )

            # Create and return session object
            return AlibabaCloudSession(cred_client)

        except (AlibabaCloudNoCredentialsError, AlibabaCloudInvalidCredentialsError):
            raise
        except Exception as error:
            logger.critical(
                f"AlibabaCloudSetUpSessionError[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise AlibabaCloudSetUpSessionError(
                file=pathlib.Path(__file__).name,
                original_exception=error,
            )

    @staticmethod
    def validate_credentials(
        session: AlibabaCloudSession,
        region: str = ALIBABACLOUD_DEFAULT_REGION,
    ) -> AlibabaCloudCallerIdentity:
        """
        Validates the Alibaba Cloud credentials using STS GetCallerIdentity.

        Args:
            session: The Alibaba Cloud session object.

        Returns:
            AlibabaCloudCallerIdentity: An object containing the caller identity information.

        Raises:
            AlibabaCloudInvalidCredentialsError: If credentials are invalid.
        """
        try:
            # Get credentials
            cred = session.get_credentials()

            # Create STS client to get caller identity (similar to AWS GetCallerIdentity)
            sts_config = open_api_models.Config(
                access_key_id=cred.access_key_id,
                access_key_secret=cred.access_key_secret,
            )
            if cred.security_token:
                sts_config.security_token = cred.security_token
            sts_config.endpoint = f"sts.{region}.aliyuncs.com"

            sts_client = StsClient(sts_config)

            caller_identity = sts_client.get_caller_identity().body

            # Parse the identity information
            account_id = getattr(caller_identity, "account_id", "")
            identity_type = getattr(caller_identity, "identity_type", "")
            principal_id = getattr(caller_identity, "principal_id", "")
            arn = getattr(caller_identity, "arn", "")

            # Log the response for debugging
            logger.debug(
                f"STS GetCallerIdentity response - Account ID: {account_id}, Principal ID: {principal_id}, ARN: {arn}, Identity Type: {identity_type}"
            )

            if not account_id:
                raise ValueError("STS GetCallerIdentity did not return account_id")

            return AlibabaCloudCallerIdentity(
                account_id=account_id,
                principal_id=principal_id,
                arn=arn,
                identity_type=identity_type,
            )

        except Exception as sts_error:
            logger.error(f"Could not get caller identity from STS: {sts_error}. ")
            raise AlibabaCloudInvalidCredentialsError(
                file=pathlib.Path(__file__).name,
                original_exception=sts_error,
            )

    @staticmethod
    def get_profile_region() -> str:
        """
        Get the profile region.

        Returns:
            str: The profile region
        """
        # For now, return default region
        # This can be enhanced to read from config file if needed
        return ALIBABACLOUD_DEFAULT_REGION

    @staticmethod
    def set_identity(
        caller_identity: AlibabaCloudCallerIdentity,
        profile: str,
        regions: set,
        profile_region: str,
    ) -> AlibabaCloudIdentityInfo:
        """
        Set the Alibaba Cloud provider identity information.

        Args:
            caller_identity: The Alibaba Cloud caller identity information.
            profile: The profile name.
            regions: A set of regions to audit.
            profile_region: The profile region.

        Returns:
            AlibabaCloudIdentityInfo: The Alibaba Cloud provider identity information.
        """
        logger.info(
            f"Alibaba Cloud Caller Identity Account ID: {caller_identity.account_id}"
        )
        logger.info(f"Alibaba Cloud Caller Identity ARN: {caller_identity.arn}")

        # Determine if this is root account or RAM user
        # Root account ARN format: acs:ram::{account_id}:root
        # RAM user ARN format: acs:ram::{account_id}:user/{user_name}
        is_root = False
        user_name = ""
        user_id = caller_identity.principal_id

        if caller_identity.arn:
            if ":root" in caller_identity.arn:
                # This is the root account
                is_root = True
                user_name = "root"
            elif ":user/" in caller_identity.arn:
                # This is a RAM user
                user_name = caller_identity.arn.split(":user/")[-1]
            else:
                # Fallback: use identity_type to determine
                if (
                    caller_identity.identity_type == "RamUser"
                    or caller_identity.identity_type == "User"
                ):
                    # This is a RAM user, extract user name from principal_id if possible
                    # Principal ID format for RAM users is often: {user_id}@{account_id}
                    if "@" in caller_identity.principal_id:
                        # Try to get user name from RAM API using the user_id
                        user_name = caller_identity.principal_id.split("@")[0]
                    else:
                        user_name = caller_identity.principal_id
                    is_root = False
                elif (
                    caller_identity.identity_type == "Root"
                    or caller_identity.identity_type == ""
                ):
                    # Empty identity_type or Root indicates root account
                    user_name = "root"
                    is_root = True
                else:
                    # Unknown identity type - default to RAM user (safer assumption)
                    logger.warning(
                        f"Unknown identity type '{caller_identity.identity_type}' from ARN '{caller_identity.arn}'. "
                        "Assuming RAM user."
                    )
                    user_name = (
                        caller_identity.principal_id
                        if caller_identity.principal_id
                        else "unknown"
                    )
                    is_root = False

        # Use the ARN from caller_identity if available, otherwise construct it
        # Similar to AWS which uses caller_identity.arn.arn directly
        if caller_identity.arn:
            identity_arn = caller_identity.arn
        else:
            # Fallback: construct ARN if not provided
            identity_arn = (
                f"acs:ram::{caller_identity.account_id}:root"
                if is_root
                else f"acs:ram::{caller_identity.account_id}:user/{user_name}"
            )

        logger.info(f"Alibaba Cloud Identity ARN: {identity_arn}")

        return AlibabaCloudIdentityInfo(
            account_id=caller_identity.account_id,
            account_name="",
            user_id=user_id,
            user_name=user_name,
            identity_arn=identity_arn,
            is_root=is_root,
            profile=profile,
            profile_region=profile_region,
            audited_regions=regions,
        )

    def get_regions_to_audit(self, regions: list = None) -> list:
        """
        get_regions_to_audit returns the list of regions to audit.

        Args:
            regions: List of Alibaba Cloud region IDs to audit.

        Returns:
            list: The list of AlibabaCloudRegion objects to audit.
        """
        from prowler.providers.alibabacloud.models import AlibabaCloudRegion

        region_list = []

        if regions:
            # Audit specific regions provided by user
            for region_id in regions:
                if region_id in ALIBABACLOUD_REGIONS:
                    region_list.append(
                        AlibabaCloudRegion(
                            region_id=region_id,
                            region_name=ALIBABACLOUD_REGIONS.get(region_id, region_id),
                        )
                    )
                else:
                    logger.warning(f"Invalid region: {region_id}. Skipping.")
        else:
            # Audit ALL available regions by default
            for region_id, region_name in ALIBABACLOUD_REGIONS.items():
                region_list.append(
                    AlibabaCloudRegion(
                        region_id=region_id,
                        region_name=region_name,
                    )
                )

        logger.info(f"Found {len(region_list)} regions to audit")

        # Update identity with audited regions
        if hasattr(self, "_identity") and self._identity:
            self._identity.audited_regions = set([r.region_id for r in region_list])

        return region_list

    def get_account_alias(self) -> str:
        """
        Retrieve the Alibaba Cloud account alias from RAM.

        Returns:
            str: Account alias if available, otherwise empty string.
        """
        try:
            ram_client = self._session.client("ram")
            response = ram_client.get_account_alias()
            account_alias = getattr(response.body, "account_alias", "") or ""
            if account_alias:
                logger.info(f"Alibaba Cloud Account Alias: {account_alias}")
            return account_alias
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return ""

    def setup_audit_config(self, input_config: dict) -> dict:
        """
        Set up the audit configuration.

        Args:
            input_config: Input configuration dictionary

        Returns:
            Audit configuration dictionary
        """
        # Merge with defaults
        audit_config = {
            "shodan_api_key": None,
            **input_config,
        }
        return audit_config

    def print_credentials(self):
        """
        Print the Alibaba Cloud credentials.

        This method prints the Alibaba Cloud credentials used by the provider.

        Example output:
        ```
        Using the Alibaba Cloud credentials below:
        Alibaba Cloud Account: 1234567890
        User Name: prowler-user
        Regions: cn-hangzhou, cn-shanghai
        ```
        """
        # Beautify audited regions
        regions_str = (
            ", ".join([r.region_id for r in self._regions])
            if self._regions
            else "default regions"
        )

        report_lines = [
            f"Alibaba Cloud Account: {Fore.YELLOW}{self.identity.account_id}{Style.RESET_ALL}",
            f"User ID: {Fore.YELLOW}{self.identity.user_id}{Style.RESET_ALL}",
            f"User Name: {Fore.YELLOW}{self.identity.user_name}{Style.RESET_ALL}",
            f"Regions: {Fore.YELLOW}{regions_str}{Style.RESET_ALL}",
        ]

        report_title = (
            f"{Style.BRIGHT}Using the Alibaba Cloud credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)

    @staticmethod
    def test_connection(
        access_key_id: str = None,
        access_key_secret: str = None,
        security_token: str = None,
        role_arn: str = None,
        role_session_name: str = None,
        ecs_ram_role: str = None,
        oidc_role_arn: str = None,
        credentials_uri: str = None,
        raise_on_exception: bool = True,
        provider_id: str = None,
    ) -> Connection:
        """
        Test the connection to Alibaba Cloud with the provided credentials.

        Args:
            access_key_id: Alibaba Cloud Access Key ID (for static credentials)
            access_key_secret: Alibaba Cloud Access Key Secret (for static credentials)
            security_token: STS Security Token (for temporary credentials)
            role_arn: ARN of the RAM role to assume
            role_session_name: Session name when assuming the RAM role
            ecs_ram_role: Name of the RAM role attached to an ECS instance
            oidc_role_arn: ARN of the RAM role for OIDC authentication
            credentials_uri: URI to retrieve credentials from an external service
            raise_on_exception: Whether to raise an exception if an error occurs
            provider_id: The expected account ID to validate against

        Returns:
            Connection: An object that contains the result of the test connection operation.
                - is_connected (bool): Indicates whether the validation was successful.
                - error (Exception): An exception object if an error occurs during the validation.

        Raises:
            AlibabaCloudSetUpSessionError: If there is an error setting up the session.
            AlibabaCloudInvalidCredentialsError: If there is an authentication error.
            Exception: If there is an unexpected error.

        Examples:
            >>> AlibabacloudProvider.test_connection(raise_on_exception=False)
            Connection(is_connected=True, Error=None)
            >>> AlibabacloudProvider.test_connection(
                    role_arn="acs:ram::123456789012:role/ProwlerRole",
                    provider_id="123456789012",
                    raise_on_exception=False
                )
            Connection(is_connected=True, Error=None)
            >>> AlibabacloudProvider.test_connection(
                    access_key_id="LTAI...",
                    access_key_secret="...",
                    raise_on_exception=False
                )
            Connection(is_connected=True, Error=None)
        """
        try:
            # Setup session - pass credentials directly instead of using env vars
            session = AlibabacloudProvider.setup_session(
                role_arn=role_arn,
                role_session_name=role_session_name,
                ecs_ram_role=ecs_ram_role,
                oidc_role_arn=oidc_role_arn,
                credentials_uri=credentials_uri,
                access_key_id=access_key_id,
                access_key_secret=access_key_secret,
                security_token=security_token,
            )

            # Validate credentials
            caller_identity = AlibabacloudProvider.validate_credentials(
                session=session,
                region=ALIBABACLOUD_DEFAULT_REGION,
            )

            # Validate provider_id if provided
            if provider_id and caller_identity.account_id != provider_id:
                raise AlibabaCloudInvalidCredentialsError(
                    file=pathlib.Path(__file__).name,
                    message=f"Provider ID mismatch: expected '{provider_id}', got '{caller_identity.account_id}'",
                )

            logger.info(
                f"Successfully connected to Alibaba Cloud account: {caller_identity.account_id}"
            )

            return Connection(is_connected=True)

        except AlibabaCloudSetUpSessionError as setup_error:
            logger.error(
                f"{setup_error.__class__.__name__}[{setup_error.__traceback__.tb_lineno}]: {setup_error}"
            )
            if raise_on_exception:
                raise setup_error
            return Connection(error=setup_error)

        except AlibabaCloudInvalidCredentialsError as auth_error:
            logger.error(
                f"{auth_error.__class__.__name__}[{auth_error.__traceback__.tb_lineno}]: {auth_error}"
            )
            if raise_on_exception:
                raise auth_error
            return Connection(error=auth_error)

        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                raise error
            return Connection(error=error)

    def generate_regional_clients(self, service: str) -> dict:
        """
        generate_regional_clients returns a dict with regional clients for the given service.

        Args:
            service: The service name (e.g., 'ecs', 'vpc', 'oss').

        Returns:
            dict: A dictionary with region keys and Alibaba Cloud service client values.

        Example:
            {"cn-hangzhou": alibabacloud_service_client, "cn-shanghai": alibabacloud_service_client}
        """
        try:
            regional_clients = {}

            # For each enabled region, create a client
            for region in self._regions:
                try:
                    client = self._session.client(service, region.region_id)
                    if client:
                        # Attach region information to the client
                        client.region = region.region_id
                        regional_clients[region.region_id] = client
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )

            return regional_clients

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return {}

    def get_default_region(self, service: str) -> str:
        """
        Get the default region for a service.

        Args:
            service: The service name

        Returns:
            The default region ID
        """
        # Return the first enabled region or the default
        if self.enabled_regions:
            return sorted(list(self.enabled_regions))[0]
        return ALIBABACLOUD_DEFAULT_REGION

    def get_checks_to_execute_by_audit_resources(self):
        """
        Get the checks to execute based on audit resources.

        Returns:
            Set of check names to execute
        """
        # This would filter checks based on resources to audit
        # For now, return empty set (no filtering)
        return set()

    @staticmethod
    def get_regions() -> dict:
        """
        Get the available Alibaba Cloud regions.

        Returns:
            dict: A dictionary of region IDs and region names.

        Example:
            >>> AlibabacloudProvider.get_regions()
            {"cn-hangzhou": "China (Hangzhou)", "cn-shanghai": "China (Shanghai)", ...}
        """
        return ALIBABACLOUD_REGIONS
