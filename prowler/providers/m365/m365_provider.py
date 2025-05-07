import asyncio
import os
from argparse import ArgumentTypeError
from os import getenv
from uuid import UUID

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.identity import (
    ClientSecretCredential,
    CredentialUnavailableError,
    DefaultAzureCredential,
    InteractiveBrowserCredential,
)
from colorama import Fore, Style
from msal import ConfidentialClientApplication
from msgraph import GraphServiceClient

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider
from prowler.providers.m365.exceptions.exceptions import (
    M365ArgumentTypeValidationError,
    M365BrowserAuthNoFlagError,
    M365BrowserAuthNoTenantIDError,
    M365ClientAuthenticationError,
    M365ClientIdAndClientSecretNotBelongingToTenantIdError,
    M365ConfigCredentialsError,
    M365CredentialsUnavailableError,
    M365DefaultAzureCredentialError,
    M365EnvironmentVariableError,
    M365GetTokenIdentityError,
    M365HTTPResponseError,
    M365InteractiveBrowserCredentialError,
    M365InvalidProviderIdError,
    M365MissingEnvironmentCredentialsError,
    M365NoAuthenticationMethodError,
    M365NotTenantIdButClientIdAndClientSecretError,
    M365NotValidClientIdError,
    M365NotValidClientSecretError,
    M365NotValidEncryptedPasswordError,
    M365NotValidTenantIdError,
    M365NotValidUserError,
    M365SetUpRegionConfigError,
    M365SetUpSessionError,
    M365TenantIdAndClientIdNotBelongingToClientSecretError,
    M365TenantIdAndClientSecretNotBelongingToClientIdError,
    M365UserCredentialsError,
)
from prowler.providers.m365.lib.mutelist.mutelist import M365Mutelist
from prowler.providers.m365.lib.powershell.m365_powershell import (
    M365PowerShell,
    initialize_m365_powershell_modules,
)
from prowler.providers.m365.lib.regions.regions import get_regions_config
from prowler.providers.m365.models import (
    M365Credentials,
    M365IdentityInfo,
    M365RegionConfig,
)


class M365Provider(Provider):
    """
    Represents an M365 provider.

    This class provides functionality to interact with the M365 resources.
    It handles authentication, region configuration, and provides access to various properties and methods
    related to the M365 provider.

    Attributes:
        _type (str): The type of the provider, which is set to "m365".
        _session (DefaultM365Credential): The session object associated with the M365 provider.
        _identity (M365IdentityInfo): The identity information for the M365 provider.
        _audit_config (dict): The audit configuration for the M365 provider.
        _region_config (M365RegionConfig): The region configuration for the M365 provider.
        _mutelist (M365Mutelist): The mutelist object associated with the M365 provider.
        audit_metadata (Audit_Metadata): The audit metadata for the M365 provider.

    Methods:
        __init__ -> Initializes the M365 provider.
        identity(self): Returns the identity of the M365 provider.
        type(self): Returns the type of the M365 provider.
        session(self): Returns the session object associated with the M365 provider.
        region_config(self): Returns the region configuration for the M365 provider.
        audit_config(self): Returns the audit configuration for the M365 provider.
        fixer_config(self): Returns the fixer configuration.
        output_options(self, options: tuple): Sets the output options for the M365 provider.
        mutelist(self) -> M365Mutelist: Returns the mutelist object associated with the M365 provider.
        setup_region_config(cls, region): Sets up the region configuration for the M365 provider.
        print_credentials(self): Prints the M365 credentials information.
        setup_session(cls, az_cli_auth, app_env_auth, browser_auth, managed_identity_auth, tenant_id, region_config): Set up the M365 session with the specified authentication method.
    """

    _type: str = "m365"
    _session: DefaultAzureCredential  # Must be used besides being named for Azure
    _identity: M365IdentityInfo
    _audit_config: dict
    _region_config: M365RegionConfig
    _mutelist: M365Mutelist
    _credentials: M365Credentials = {}
    # TODO: this is not optional, enforce for all providers
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        sp_env_auth: bool = False,
        env_auth: bool = False,
        az_cli_auth: bool = False,
        browser_auth: bool = False,
        tenant_id: str = None,
        client_id: str = None,
        client_secret: str = None,
        user: str = None,
        encrypted_password: str = None,
        init_modules: bool = False,
        region: str = "M365Global",
        config_content: dict = None,
        config_path: str = None,
        mutelist_path: str = None,
        mutelist_content: dict = None,
        fixer_config: dict = {},
    ):
        """
        Initializes the M365 provider.

        Args:
            tenant_id (str): The M365 Active Directory tenant ID.
            region (str): The M365 region.
            client_id (str): The M365 client ID.
            client_secret (str): The M365 client secret.
            config_path (str): The path to the configuration file.
            config_content (dict): The configuration content.
            fixer_config (dict): The fixer configuration.
            mutelist_path (str): The path to the mutelist file.
            mutelist_content (dict): The mutelist content.

        Returns:
            None

        Raises:
            M365ArgumentTypeValidationError: If there is an error in the argument type validation.
            M365SetUpRegionConfigError: If there is an error in setting up the region configuration.
            M365ConfigCredentialsError: If there is an error in configuring the M365 credentials from a dictionary.
            M365GetTokenIdentityError: If there is an error in getting the token from the M365 identity.
            M365HTTPResponseError: If there is an HTTP response error.
        """
        logger.info("Setting M365 provider ...")

        logger.info("Checking if any credentials mode is set ...")

        # Validate the authentication arguments
        self.validate_arguments(
            az_cli_auth,
            sp_env_auth,
            env_auth,
            browser_auth,
            tenant_id,
            client_id,
            client_secret,
            user,
            encrypted_password,
        )

        logger.info("Checking if region is different than default one")
        self._region_config = self.setup_region_config(region)

        # Get the dict from the static credentials
        m365_credentials = None
        if tenant_id and client_id and client_secret and user and encrypted_password:
            m365_credentials = self.validate_static_credentials(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
                user=user,
                encrypted_password=encrypted_password,
            )

        # Set up the M365 session
        self._session = self.setup_session(
            az_cli_auth,
            sp_env_auth,
            env_auth,
            browser_auth,
            tenant_id,
            m365_credentials,
            self._region_config,
        )

        # Set up the identity
        self._identity = self.setup_identity(
            az_cli_auth,
            sp_env_auth,
            env_auth,
            browser_auth,
            client_id,
        )

        # Set up PowerShell session credentials
        self._credentials = self.setup_powershell(
            env_auth=env_auth,
            m365_credentials=m365_credentials,
            provider_id=self.identity.tenant_domain,
            init_modules=init_modules,
        )

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
            self._mutelist = M365Mutelist(
                mutelist_content=mutelist_content,
            )
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = M365Mutelist(
                mutelist_path=mutelist_path,
            )

        Provider.set_global_provider(self)

    @property
    def identity(self):
        """Returns the identity of the M365 provider."""
        return self._identity

    @property
    def type(self):
        """Returns the type of the M365 provider."""
        return self._type

    @property
    def session(self):
        """Returns the session object associated with the M365 provider."""
        return self._session

    @property
    def region_config(self):
        """Returns the region configuration for the M365 provider."""
        return self._region_config

    @property
    def audit_config(self):
        """Returns the audit configuration for the M365 provider."""
        return self._audit_config

    @property
    def fixer_config(self):
        """Returns the fixer configuration."""
        return self._fixer_config

    @property
    def mutelist(self) -> M365Mutelist:
        """Mutelist object associated with this M365 provider."""
        return self._mutelist

    @property
    def credentials(self) -> M365Credentials:
        """Return powershell credentials"""
        return self._credentials

    @staticmethod
    def validate_arguments(
        az_cli_auth: bool,
        sp_env_auth: bool,
        env_auth: bool,
        browser_auth: bool,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        user: str,
        encrypted_password: str,
    ):
        """
        Validates the authentication arguments for the M365 provider.

        Args:
            az_cli_auth (bool): Flag indicating whether Azure CLI authentication is enabled.
            sp_env_auth (bool): Flag indicating whether application authentication with environment variables is enabled.
            env_auth: (bool): Flag indicating whether to use application and PowerShell authentication with environment variables.
            browser_auth (bool): Flag indicating whether browser authentication is enabled.
            tenant_id (str): The M365 Tenant ID.
            client_id (str): The M365 Client ID.
            client_secret (str): The M365 Client Secret.
            user (str): The M365 User Account.
            encrpted_password (str): The M365 Encrypted Password.

        Raises:
            M365BrowserAuthNoTenantIDError: If browser authentication is enabled but the tenant ID is not found.
        """

        if not client_id and not client_secret:
            if not browser_auth and tenant_id and not env_auth:
                raise M365BrowserAuthNoFlagError(
                    file=os.path.basename(__file__),
                    message="M365 tenant ID error: browser authentication flag (--browser-auth) not found",
                )
            elif (
                not az_cli_auth
                and not sp_env_auth
                and not browser_auth
                and not env_auth
            ):
                raise M365NoAuthenticationMethodError(
                    file=os.path.basename(__file__),
                    message="M365 provider requires at least one authentication method set: [--env-auth | --az-cli-auth | --sp-env-auth | --browser-auth]",
                )
            elif browser_auth and not tenant_id:
                raise M365BrowserAuthNoTenantIDError(
                    file=os.path.basename(__file__),
                    message="M365 Tenant ID (--tenant-id) is required for browser authentication mode",
                )
        elif env_auth:
            if not user or not encrypted_password or not tenant_id:
                raise M365MissingEnvironmentCredentialsError(
                    file=os.path.basename(__file__),
                    message="M365 provider requires AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID, M365_USER and M365_ENCRYPTED_PASSWORD environment variables to be set when using --env-auth",
                )
        else:
            if not tenant_id:
                raise M365NotTenantIdButClientIdAndClientSecretError(
                    file=os.path.basename(__file__),
                    message="Tenant Id is required for M365 static credentials. Make sure you are using the correct credentials.",
                )

    @staticmethod
    def setup_region_config(region):
        """
        Sets up the region configuration for the M365 provider.

        Args:
            region (str): The name of the region.

        Returns:
            M365RegionConfig: The region configuration object.

        """
        try:
            config = get_regions_config(region)

            return M365RegionConfig(
                name=region,
                authority=config["authority"],
                base_url=config["base_url"],
                credential_scopes=config["credential_scopes"],
            )
        except ArgumentTypeError as validation_error:
            logger.error(
                f"{validation_error.__class__.__name__}[{validation_error.__traceback__.tb_lineno}]: {validation_error}"
            )
            raise M365ArgumentTypeValidationError(
                file=os.path.basename(__file__),
                original_exception=validation_error,
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise M365SetUpRegionConfigError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    @staticmethod
    def setup_powershell(
        env_auth: bool = False,
        m365_credentials: dict = {},
        provider_id: str = None,
        init_modules: bool = False,
    ) -> M365Credentials:
        """Gets the M365 credentials.

        Args:
            env_auth: (bool): Flag indicating whether to use application and PowerShell authentication with environment variables.

        Returns:
            M365Credentials: Object containing the user credentials.
                If env_auth is True, retrieves from environment variables.
                If False, returns empty credentials.
        """
        credentials = None
        if m365_credentials:
            credentials = M365Credentials(
                user=m365_credentials.get("user", ""),
                passwd=m365_credentials.get("encrypted_password", ""),
                client_id=m365_credentials.get("client_id", ""),
                client_secret=m365_credentials.get("client_secret", ""),
                tenant_id=m365_credentials.get("tenant_id", ""),
                provider_id=provider_id,
            )
        elif env_auth:
            m365_user = getenv("M365_USER")
            m365_password = getenv("M365_ENCRYPTED_PASSWORD")
            client_id = getenv("AZURE_CLIENT_ID")
            client_secret = getenv("AZURE_CLIENT_SECRET")
            tenant_id = getenv("AZURE_TENANT_ID")

            if not m365_user or not m365_password:
                logger.critical(
                    "M365 provider: Missing M365_USER or M365_ENCRYPTED_PASSWORD environment variables needed for credentials authentication"
                )
                raise M365MissingEnvironmentCredentialsError(
                    file=os.path.basename(__file__),
                    message="Missing M365_USER or M365_ENCRYPTED_PASSWORD environment variables required for credentials authentication.",
                )
            credentials = M365Credentials(
                user=m365_user,
                passwd=m365_password,
                client_id=client_id,
                client_secret=client_secret,
                tenant_id=tenant_id,
                provider_id=provider_id,
            )

        if credentials:
            test_session = M365PowerShell(credentials)
            try:
                if test_session.test_credentials(credentials):
                    if init_modules:
                        initialize_m365_powershell_modules()
                    return credentials
                raise M365UserCredentialsError(
                    file=os.path.basename(__file__),
                    message="The provided M365 User credentials are not valid.",
                )
            finally:
                test_session.close()

    def print_credentials(self):
        """M365 credentials information.

        This method prints the M365 Tenant Domain, M365 Tenant ID, M365 Region,
        M365 Subscriptions, M365 Identity Type, and M365 Identity ID.

        Args:
            None

        Returns:
            None
        """
        report_lines = [
            f"M365 Region: {Fore.YELLOW}{self.region_config.name}{Style.RESET_ALL}",
            f"M365 Tenant Domain: {Fore.YELLOW}{self._identity.tenant_domain}{Style.RESET_ALL} M365 Tenant ID: {Fore.YELLOW}{self._identity.tenant_id}{Style.RESET_ALL}",
            f"M365 Identity Type: {Fore.YELLOW}{self._identity.identity_type}{Style.RESET_ALL} M365 Identity ID: {Fore.YELLOW}{self._identity.identity_id}{Style.RESET_ALL}",
        ]
        if self.credentials and self.credentials.user:
            report_lines.append(
                f"M365 User: {Fore.YELLOW}{self.credentials.user}{Style.RESET_ALL}"
            )
        report_title = (
            f"{Style.BRIGHT}Using the M365 credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)

    # TODO: setup_session or setup_credentials?
    # This should be setup_credentials, since it is setting up the credentials for the provider
    @staticmethod
    def setup_session(
        az_cli_auth: bool,
        sp_env_auth: bool,
        env_auth: bool,
        browser_auth: bool,
        tenant_id: str,
        m365_credentials: dict,
        region_config: M365RegionConfig,
    ):
        """Returns the M365 credentials object.

        Set up the M365 session with the specified authentication method.

        Args:
            az_cli_auth (bool): Flag indicating whether to use Azure CLI authentication.
            sp_env_auth (bool): Flag indicating whether to use application authentication with environment variables.
            browser_auth (bool): Flag indicating whether to use interactive browser authentication.
            tenant_id (str): The M365 Active Directory tenant ID.
            m365_credentials (dict): The M365 configuration object. It contains the following keys:
                - tenant_id: The M365 Active Directory tenant ID.
                - client_id: The M365 client ID.
                - client_secret: The M365 client secret
                - user: The M365 user email
                - encrypted_password: The M365 encrypted password
                - provider_id: The M365 provider ID (in this case the Tenant ID).
            region_config (M365RegionConfig): The region configuration object.

        Returns:
            credentials: The M365 credentials object.

        Raises:
            Exception: If failed to retrieve M365 credentials.

        """
        if not browser_auth:
            if sp_env_auth or env_auth:
                try:
                    M365Provider.check_service_principal_creds_env_vars()
                except M365EnvironmentVariableError as environment_credentials_error:
                    logger.critical(
                        f"{environment_credentials_error.__class__.__name__}[{environment_credentials_error.__traceback__.tb_lineno}] -- {environment_credentials_error}"
                    )
                    raise environment_credentials_error
            try:
                if m365_credentials:
                    try:
                        credentials = ClientSecretCredential(
                            tenant_id=m365_credentials["tenant_id"],
                            client_id=m365_credentials["client_id"],
                            client_secret=m365_credentials["client_secret"],
                        )
                        return credentials
                    except ClientAuthenticationError as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise M365ClientAuthenticationError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                    except CredentialUnavailableError as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise M365CredentialsUnavailableError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                    except Exception as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise M365ConfigCredentialsError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                else:
                    # Since the authentication method to be used will come as True, we have to negate it since
                    # DefaultAzureCredential sets just one authentication method, excluding the others
                    try:
                        credentials = DefaultAzureCredential(
                            exclude_environment_credential=not (
                                sp_env_auth or env_auth
                            ),
                            exclude_cli_credential=not az_cli_auth,
                            # M365 Auth using Managed Identity is not supported
                            exclude_managed_identity_credential=True,
                            # M365 Auth using Visual Studio is not supported
                            exclude_visual_studio_code_credential=True,
                            # M365 Auth using Shared Token Cache is not supported
                            exclude_shared_token_cache_credential=True,
                            # M365 Auth using PowerShell is not supported
                            exclude_powershell_credential=True,
                            # set Authority of a Microsoft Entra endpoint
                            authority=region_config.authority,
                        )
                    except ClientAuthenticationError as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise M365ClientAuthenticationError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                    except CredentialUnavailableError as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise M365CredentialsUnavailableError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                    except Exception as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise M365DefaultAzureCredentialError(
                            file=os.path.basename(__file__), original_exception=error
                        )
            except Exception as error:
                logger.critical("Failed to retrieve M365 credentials")
                logger.critical(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                )
                raise M365SetUpSessionError(
                    file=os.path.basename(__file__), original_exception=error
                )
        else:
            try:
                credentials = InteractiveBrowserCredential(tenant_id=tenant_id)
            except Exception as error:
                logger.critical(
                    "Failed to retrieve M365 credentials using browser authentication"
                )
                logger.critical(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                )
                raise M365InteractiveBrowserCredentialError(
                    file=os.path.basename(__file__), original_exception=error
                )

        return credentials

    @staticmethod
    def test_connection(
        az_cli_auth: bool = False,
        sp_env_auth: bool = False,
        env_auth: bool = False,
        browser_auth: bool = False,
        tenant_id: str = None,
        region: str = "M365Global",
        raise_on_exception: bool = True,
        client_id: str = None,
        client_secret: str = None,
        user: str = None,
        encrypted_password: str = None,
        provider_id: str = None,
    ) -> Connection:
        """Test connection to M365 tenant and PowerShell modules.

        Test the connection to an M365 tenant and PowerShell modules using the provided credentials.

        Args:

            az_cli_auth (bool): Flag indicating whether to use Azure CLI authentication.
            sp_env_auth (bool): Flag indicating whether to use application authentication with environment variables.
            env_auth: (bool): Flag indicating whether to use application and PowerShell authentication with environment variables.
            browser_auth (bool): Flag indicating whether to use interactive browser authentication.
            tenant_id (str): The M365 Active Directory tenant ID.
            region (str): The M365 region.
            raise_on_exception (bool): Flag indicating whether to raise an exception if the connection fails.
            client_id (str): The M365 client ID.
            client_secret (str): The M365 client secret.
            user (str): The M365 user email.
            encrypted_password (str): The M365 encrypted_password.
            provider_id (str): The M365 provider ID (in this case the Tenant ID).


        Returns:
            bool: True if the connection is successful, False otherwise.

        Raises:
            Exception: If failed to test the connection to M365 subscription.
            M365ArgumentTypeValidationError: If there is an error in the argument type validation.
            M365SetUpRegionConfigError: If there is an error in setting up the region configuration.
            M365InteractiveBrowserCredentialError: If there is an error in retrieving the M365 credentials using browser authentication.
            M365HTTPResponseError: If there is an HTTP response error.
            M365ConfigCredentialsError: If there is an error in configuring the M365 credentials from a dictionary.
            M365InvalidProviderIdError: If the provider ID does not match the application tenant domain.

        Examples:
            >>> M365Provider.test_connection(az_cli_auth=True)
            True
            >>> M365Provider.test_connection(sp_env_auth=False, browser_auth=True, tenant_id=None)
            False, ArgumentTypeError: M365 Tenant ID is required only for browser authentication mode
            >>> M365Provider.test_connection(tenant_id="XXXXXXXXXX", client_id="XXXXXXXXXX", client_secret="XXXXXXXXXX")
            True
        """
        try:
            M365Provider.validate_arguments(
                az_cli_auth,
                sp_env_auth,
                env_auth,
                browser_auth,
                tenant_id,
                client_id,
                client_secret,
                user,
                encrypted_password,
            )
            region_config = M365Provider.setup_region_config(region)

            # Get the dict from the static credentials
            m365_credentials = None
            if tenant_id and client_id and client_secret:
                if not user and not encrypted_password:
                    m365_credentials = M365Provider.validate_static_credentials(
                        tenant_id=tenant_id,
                        client_id=client_id,
                        client_secret=client_secret,
                        user="user",
                        encrypted_password="encrypted_password",
                    )
                else:
                    m365_credentials = M365Provider.validate_static_credentials(
                        tenant_id=tenant_id,
                        client_id=client_id,
                        client_secret=client_secret,
                        user=user,
                        encrypted_password=encrypted_password,
                    )

            # Set up the M365 session
            credentials = M365Provider.setup_session(
                az_cli_auth,
                sp_env_auth,
                env_auth,
                browser_auth,
                tenant_id,
                m365_credentials,
                region_config,
            )

            GraphServiceClient(credentials=credentials)

            logger.info("M365 provider: Connection to MSGraph successful")

            # Set up PowerShell credentials
            if user and encrypted_password:
                M365Provider.setup_powershell(
                    env_auth,
                    m365_credentials,
                    provider_id,
                )
            else:
                logger.info(
                    "M365 provider: Connection to PowerShell has not been requested"
                )

            logger.info("M365 provider: Connection to PowerShell successful")

            # Check that user domain, provider_id and Graph client tenant_domain are the same
            if user and encrypted_password:
                user_domain = user.split("@")[1]
                if provider_id and user_domain != provider_id:
                    raise M365InvalidProviderIdError(
                        file=os.path.basename(__file__),
                        message=f"Provider ID {provider_id} does not match Application tenant domain {user_domain}",
                    )

            return Connection(is_connected=True)

        # Exceptions from setup_region_config
        except M365ArgumentTypeValidationError as type_validation_error:
            logger.error(
                f"{type_validation_error.__class__.__name__}[{type_validation_error.__traceback__.tb_lineno}]: {type_validation_error}"
            )
            if raise_on_exception:
                raise type_validation_error
            return Connection(error=type_validation_error)
        except M365SetUpRegionConfigError as region_config_error:
            logger.error(
                f"{region_config_error.__class__.__name__}[{region_config_error.__traceback__.tb_lineno}]: {region_config_error}"
            )
            if raise_on_exception:
                raise region_config_error
            return Connection(error=region_config_error)
        # Exceptions from setup_session
        except M365EnvironmentVariableError as environment_credentials_error:
            logger.error(
                f"{environment_credentials_error.__class__.__name__}[{environment_credentials_error.__traceback__.tb_lineno}]: {environment_credentials_error}"
            )
            if raise_on_exception:
                raise environment_credentials_error
            return Connection(error=environment_credentials_error)
        except M365ConfigCredentialsError as config_credentials_error:
            logger.error(
                f"{config_credentials_error.__class__.__name__}[{config_credentials_error.__traceback__.tb_lineno}]: {config_credentials_error}"
            )
            if raise_on_exception:
                raise config_credentials_error
            return Connection(error=config_credentials_error)
        except M365ClientAuthenticationError as client_auth_error:
            logger.error(
                f"{client_auth_error.__class__.__name__}[{client_auth_error.__traceback__.tb_lineno}]: {client_auth_error}"
            )
            if raise_on_exception:
                raise client_auth_error
            return Connection(error=client_auth_error)
        except M365CredentialsUnavailableError as credential_unavailable_error:
            logger.error(
                f"{credential_unavailable_error.__class__.__name__}[{credential_unavailable_error.__traceback__.tb_lineno}]: {credential_unavailable_error}"
            )
            if raise_on_exception:
                raise credential_unavailable_error
            return Connection(error=credential_unavailable_error)
        except (
            M365ClientIdAndClientSecretNotBelongingToTenantIdError
        ) as tenant_id_error:
            logger.error(
                f"{tenant_id_error.__class__.__name__}[{tenant_id_error.__traceback__.tb_lineno}]: {tenant_id_error}"
            )
            if raise_on_exception:
                raise tenant_id_error
            return Connection(error=tenant_id_error)
        except (
            M365TenantIdAndClientSecretNotBelongingToClientIdError
        ) as client_id_error:
            logger.error(
                f"{client_id_error.__class__.__name__}[{client_id_error.__traceback__.tb_lineno}]: {client_id_error}"
            )
            if raise_on_exception:
                raise client_id_error
            return Connection(error=client_id_error)
        except (
            M365TenantIdAndClientIdNotBelongingToClientSecretError
        ) as client_secret_error:
            logger.error(
                f"{client_secret_error.__class__.__name__}[{client_secret_error.__traceback__.tb_lineno}]: {client_secret_error}"
            )
            if raise_on_exception:
                raise client_secret_error
            return Connection(error=client_secret_error)
        # Exceptions from provider_id validation
        except M365InvalidProviderIdError as invalid_credentials_error:
            logger.error(
                f"{invalid_credentials_error.__class__.__name__}[{invalid_credentials_error.__traceback__.tb_lineno}]: {invalid_credentials_error}"
            )
            if raise_on_exception:
                raise invalid_credentials_error
            return Connection(error=invalid_credentials_error)
        # Exceptions from SubscriptionClient
        except HttpResponseError as http_response_error:
            logger.error(
                f"{http_response_error.__class__.__name__}[{http_response_error.__traceback__.tb_lineno}]: {http_response_error}"
            )
            if raise_on_exception:
                raise M365HTTPResponseError(
                    file=os.path.basename(__file__),
                    original_exception=http_response_error,
                )
            return Connection(error=http_response_error)
        except Exception as error:
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            if raise_on_exception:
                # Raise directly the exception
                raise error
            return Connection(error=error)

    @staticmethod
    def check_service_principal_creds_env_vars():
        """
        Checks the presence of required environment variables for service principal authentication against Azure.

        This method checks for the presence of the following environment variables:
        - AZURE_CLIENT_ID: Azure client ID
        - AZURE_TENANT_ID: Azure tenant ID
        - AZURE_CLIENT_SECRET: Azure client secret

        If any of the environment variables is missing, it logs a critical error and exits the program.
        """
        logger.info(
            "M365 provider: checking service principal environment variables  ..."
        )
        for env_var in ["AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET"]:
            if not getenv(env_var):
                logger.critical(
                    f"M365 provider: Missing environment variable {env_var} needed to authenticate against M365."
                )
                raise M365EnvironmentVariableError(
                    file=os.path.basename(__file__),
                    message=f"Missing environment variable {env_var} required to authenticate.",
                )

    def setup_identity(
        self,
        az_cli_auth,
        sp_env_auth,
        env_auth,
        browser_auth,
        client_id,
    ):
        """
        Sets up the identity for the M365 provider.

        Args:
            az_cli_auth (bool): Flag indicating if Azure CLI authentication is used.
            sp_env_auth (bool): Flag indicating if application authentication with environment variables is used.
            env_auth: (bool): Flag indicating whether to use application and PowerShell authentication with environment variables.
            browser_auth (bool): Flag indicating if interactive browser authentication is used.
            client_id (str): The M365 client ID.

        Returns:
            M365IdentityInfo: An instance of M365IdentityInfo containing the identity information.
        """
        credentials = self.session
        # TODO: fill this object with real values not default and set to none
        identity = M365IdentityInfo()

        # If credentials comes from service principal or browser, if the required permissions are assigned
        # the identity can access AAD and retrieve the tenant domain name.
        # With cli also should be possible but right now it does not work, m365 python package issue is coming
        # At the time of writting this with az cli creds is not working, despite that is included
        if env_auth or az_cli_auth or sp_env_auth or browser_auth or client_id:

            async def get_m365_identity():
                # Trying to recover tenant domain info
                try:
                    logger.info(
                        "Trying to retrieve tenant domain from AAD to populate identity structure ..."
                    )
                    client = GraphServiceClient(credentials=credentials)

                    domain_result = await client.domains.get()
                    if getattr(domain_result, "value"):
                        if getattr(domain_result.value[0], "id"):
                            identity.tenant_domain = domain_result.value[0].id

                except HttpResponseError as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                    )
                    raise M365HTTPResponseError(
                        file=os.path.basename(__file__),
                        original_exception=error,
                    )
                except ClientAuthenticationError as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                    )
                    raise M365GetTokenIdentityError(
                        file=os.path.basename(__file__),
                        original_exception=error,
                    )
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                    )
                # since that exception is not considered as critical, we keep filling another identity fields
                if sp_env_auth or env_auth or client_id:
                    # The id of the sp can be retrieved from environment variables
                    identity.identity_id = getenv("AZURE_CLIENT_ID")
                    identity.identity_type = "Service Principal"
                # Same here, if user can access AAD, some fields are retrieved if not, default value, for az cli
                # should work but it doesn't, pending issue
                else:
                    identity.identity_id = "Unknown user id (Missing AAD permissions)"
                    identity.identity_type = "User"
                    try:
                        logger.info(
                            "Trying to retrieve user information from AAD to populate identity structure ..."
                        )
                        client = GraphServiceClient(credentials=credentials)

                        me = await client.me.get()
                        if me:
                            if getattr(me, "user_principal_name"):
                                identity.identity_id = me.user_principal_name

                    except Exception as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )

                # Retrieve tenant id from the client
                client = GraphServiceClient(credentials=credentials)
                organization_info = await client.organization.get()
                identity.tenant_id = organization_info.value[0].id

            asyncio.get_event_loop().run_until_complete(get_m365_identity())
            return identity

    @staticmethod
    def validate_static_credentials(
        tenant_id: str = None,
        client_id: str = None,
        client_secret: str = None,
        user: str = None,
        encrypted_password: str = None,
    ) -> dict:
        """
        Validates the static credentials for the M365 provider.

        Args:
            tenant_id (str): The M365 Active Directory tenant ID.
            client_id (str): The M365 client ID.
            client_secret (str): The M365 client secret.
            user (str): The M365 user email.
            encrypted_password (str): The M365 encrypted password.

        Raises:
            M365NotValidTenantIdError: If the provided M365 Tenant ID is not valid.
            M365NotValidClientIdError: If the provided M365 Client ID is not valid.
            M365NotValidClientSecretError: If the provided M365 Client Secret is not valid.
            M365ClientIdAndClientSecretNotBelongingToTenantIdError: If the provided M365 Client ID and Client Secret do not belong to the specified Tenant ID.
            M365TenantIdAndClientSecretNotBelongingToClientIdError: If the provided M365 Tenant ID and Client Secret do not belong to the specified Client ID.
            M365TenantIdAndClientIdNotBelongingToClientSecretError: If the provided M365 Tenant ID and Client ID do not belong to the specified Client Secret.

        Returns:
            dict: A dictionary containing the validated static credentials.
        """
        # Validate the Tenant ID
        try:
            UUID(tenant_id)
        except ValueError:
            raise M365NotValidTenantIdError(
                file=os.path.basename(__file__),
                message="The provided M365 Tenant ID is not valid.",
            )

        # Validate the Client ID
        try:
            UUID(client_id)
        except ValueError:
            raise M365NotValidClientIdError(
                file=os.path.basename(__file__),
                message="The provided M365 Client ID is not valid.",
            )

        # Validate the Client Secret
        if not client_secret:
            raise M365NotValidClientSecretError(
                file=os.path.basename(__file__),
                message="The provided M365 Client Secret is not valid.",
            )

        # Validate the User
        if not user:
            raise M365NotValidUserError(
                file=os.path.basename(__file__),
                message="The provided M365 User is not valid.",
            )

        # Validate the Encrypted Password
        if not encrypted_password:
            raise M365NotValidEncryptedPasswordError(
                file=os.path.basename(__file__),
                message="The provided M365 Encrypted Password is not valid.",
            )

        try:
            M365Provider.verify_client(tenant_id, client_id, client_secret)
            return {
                "tenant_id": tenant_id,
                "client_id": client_id,
                "client_secret": client_secret,
                "user": user,
                "encrypted_password": encrypted_password,
            }
        except M365NotValidTenantIdError as tenant_id_error:
            logger.error(
                f"{tenant_id_error.__class__.__name__}[{tenant_id_error.__traceback__.tb_lineno}]: {tenant_id_error}"
            )
            raise M365ClientIdAndClientSecretNotBelongingToTenantIdError(
                file=os.path.basename(__file__),
                message="The provided M365 Client ID and Client Secret do not belong to the specified Tenant ID.",
            )
        except M365NotValidClientIdError as client_id_error:
            logger.error(
                f"{client_id_error.__class__.__name__}[{client_id_error.__traceback__.tb_lineno}]: {client_id_error}"
            )
            raise M365TenantIdAndClientSecretNotBelongingToClientIdError(
                file=os.path.basename(__file__),
                message="The provided M365 Tenant ID and Client Secret do not belong to the specified Client ID.",
            )
        except M365NotValidClientSecretError as client_secret_error:
            logger.error(
                f"{client_secret_error.__class__.__name__}[{client_secret_error.__traceback__.tb_lineno}]: {client_secret_error}"
            )
            raise M365TenantIdAndClientIdNotBelongingToClientSecretError(
                file=os.path.basename(__file__),
                message="The provided M365 Tenant ID and Client ID do not belong to the specified Client Secret.",
            )

    @staticmethod
    def verify_client(tenant_id, client_id, client_secret) -> None:
        """
        Verifies the M365 client credentials using the specified tenant ID, client ID, and client secret.

        Args:
            tenant_id (str): The M365 Active Directory tenant ID.
            client_id (str): The M365 client ID.
            client_secret (str): The M365 client secret.

        Raises:
            M365NotValidTenantIdError: If the provided M365 Tenant ID is not valid.
            M365NotValidClientIdError: If the provided M365 Client ID is not valid.
            M365NotValidClientSecretError: If the provided M365 Client Secret is not valid.

        Returns:
            None
        """
        authority = f"https://login.microsoftonline.com/{tenant_id}"
        try:
            # Create a ConfidentialClientApplication instance
            app = ConfidentialClientApplication(
                client_id=client_id,
                client_credential=client_secret,
                authority=authority,
            )

            # Attempt to acquire a token
            result = app.acquire_token_for_client(
                scopes=["https://graph.microsoft.com/.default"]
            )

            # Check if token acquisition was successful
            if "access_token" not in result:
                # Handle specific errors based on the MSAL response
                error_description = result.get("error_description", "")
                if f"Tenant '{tenant_id}'" in error_description:
                    raise M365NotValidTenantIdError(
                        file=os.path.basename(__file__),
                        message="The provided Microsoft 365 Tenant ID is not valid for the specified Client ID and Client Secret.",
                    )
                if f"Application with identifier '{client_id}'" in error_description:
                    raise M365NotValidClientIdError(
                        file=os.path.basename(__file__),
                        message="The provided Microsoft 365 Client ID is not valid for the specified Tenant ID and Client Secret.",
                    )
                if "Invalid client secret provided" in error_description:
                    raise M365NotValidClientSecretError(
                        file=os.path.basename(__file__),
                        message="The provided Microsoft 365 Client Secret is not valid for the specified Tenant ID and Client ID.",
                    )
        except (
            M365NotValidTenantIdError,
            M365NotValidClientIdError,
            M365NotValidClientSecretError,
        ) as m365_error:
            # M365 specific errors already raised
            raise RuntimeError(f"{m365_error}")
        except Exception as error:
            # Generic exception handling for unexpected errors
            raise RuntimeError(f"An unexpected error occurred: {str(error)}")
