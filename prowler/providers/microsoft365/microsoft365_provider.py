import asyncio
import os
import re
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
from prowler.providers.microsoft365.exceptions.exceptions import (
    Microsoft365ArgumentTypeValidationError,
    Microsoft365BrowserAuthNoFlagError,
    Microsoft365BrowserAuthNoTenantIDError,
    Microsoft365ClientAuthenticationError,
    Microsoft365ClientIdAndClientSecretNotBelongingToTenantIdError,
    Microsoft365ConfigCredentialsError,
    Microsoft365CredentialsUnavailableError,
    Microsoft365DefaultAzureCredentialError,
    Microsoft365EnvironmentVariableError,
    Microsoft365GetTokenIdentityError,
    Microsoft365HTTPResponseError,
    Microsoft365InteractiveBrowserCredentialError,
    Microsoft365InvalidProviderIdError,
    Microsoft365NoAuthenticationMethodError,
    Microsoft365NotTenantIdButClientIdAndClienSecretError,
    Microsoft365NotValidClientIdError,
    Microsoft365NotValidClientSecretError,
    Microsoft365NotValidTenantIdError,
    Microsoft365SetUpRegionConfigError,
    Microsoft365SetUpSessionError,
    Microsoft365TenantIdAndClientIdNotBelongingToClientSecretError,
    Microsoft365TenantIdAndClientSecretNotBelongingToClientIdError,
)
from prowler.providers.microsoft365.lib.mutelist.mutelist import Microsoft365Mutelist
from prowler.providers.microsoft365.lib.regions.microsoft365_regions import (
    get_regions_config,
)
from prowler.providers.microsoft365.models import (
    Microsoft365IdentityInfo,
    Microsoft365RegionConfig,
)


class Microsoft365Provider(Provider):
    """
    Represents an Microsoft365 provider.

    This class provides functionality to interact with the Microsoft365 resources.
    It handles authentication, region configuration, and provides access to various properties and methods
    related to the Microsoft365 provider.

    Attributes:
        _type (str): The type of the provider, which is set to "microsoft365".
        _session (DefaultMicrosoft365Credential): The session object associated with the Microsoft365 provider.
        _identity (Microsoft365IdentityInfo): The identity information for the Microsoft365 provider.
        _audit_config (dict): The audit configuration for the Microsoft365 provider.
        _region_config (Microsoft365RegionConfig): The region configuration for the Microsoft365 provider.
        _mutelist (Microsoft365Mutelist): The mutelist object associated with the Microsoft365 provider.
        audit_metadata (Audit_Metadata): The audit metadata for the Microsoft365 provider.

    Methods:
        __init__ -> Initializes the Microsoft365 provider.
        identity(self): Returns the identity of the Microsoft365 provider.
        type(self): Returns the type of the Microsoft365 provider.
        session(self): Returns the session object associated with the Microsoft365 provider.
        region_config(self): Returns the region configuration for the Microsoft365 provider.
        audit_config(self): Returns the audit configuration for the Microsoft365 provider.
        fixer_config(self): Returns the fixer configuration.
        output_options(self, options: tuple): Sets the output options for the Microsoft365 provider.
        mutelist(self) -> Microsoft365Mutelist: Returns the mutelist object associated with the Microsoft365 provider.
        setup_region_config(cls, region): Sets up the region configuration for the Microsoft365 provider.
        print_credentials(self): Prints the Microsoft365 credentials information.
        setup_session(cls, az_cli_auth, app_env_auth, browser_auth, managed_identity_auth, tenant_id, region_config): Set up the Microsoft365 session with the specified authentication method.
    """

    _type: str = "microsoft365"
    _session: DefaultAzureCredential  # Must be used besides being named for Azure
    _identity: Microsoft365IdentityInfo
    _audit_config: dict
    _region_config: Microsoft365RegionConfig
    _mutelist: Microsoft365Mutelist
    # TODO: this is not optional, enforce for all providers
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        sp_env_auth: bool,
        az_cli_auth: bool,
        browser_auth: bool,
        tenant_id: str = None,
        client_id: str = None,
        client_secret: str = None,
        region: str = "Microsoft365Global",
        config_content: dict = None,
        config_path: str = None,
        mutelist_path: str = None,
        mutelist_content: dict = None,
        fixer_config: dict = {},
    ):
        """
        Initializes the Microsoft365 provider.

        Args:
            tenant_id (str): The Microsoft365 Active Directory tenant ID.
            region (str): The Microsoft365 region.
            client_id (str): The Microsoft365 client ID.
            client_secret (str): The Microsoft365 client secret.
            config_path (str): The path to the configuration file.
            config_content (dict): The configuration content.
            fixer_config (dict): The fixer configuration.
            mutelist_path (str): The path to the mutelist file.
            mutelist_content (dict): The mutelist content.

        Returns:
            None

        Raises:
            Microsoft365ArgumentTypeValidationError: If there is an error in the argument type validation.
            Microsoft365SetUpRegionConfigError: If there is an error in setting up the region configuration.
            Microsoft365ConfigCredentialsError: If there is an error in configuring the Microsoft365 credentials from a dictionary.
            Microsoft365GetTokenIdentityError: If there is an error in getting the token from the Microsoft365 identity.
            Microsoft365HTTPResponseError: If there is an HTTP response error.
        """
        logger.info("Setting Microsoft365 provider ...")

        logger.info("Checking if any credentials mode is set ...")

        # Validate the authentication arguments
        self.validate_arguments(
            az_cli_auth,
            sp_env_auth,
            browser_auth,
            tenant_id,
            client_id,
            client_secret,
        )

        logger.info("Checking if region is different than default one")
        self._region_config = self.setup_region_config(region)

        # Get the dict from the static credentials
        microsoft365_credentials = None
        if tenant_id and client_id and client_secret:
            microsoft365_credentials = self.validate_static_credentials(
                tenant_id=tenant_id, client_id=client_id, client_secret=client_secret
            )

        # Set up the Microsoft365 session
        self._session = self.setup_session(
            az_cli_auth,
            sp_env_auth,
            browser_auth,
            tenant_id,
            microsoft365_credentials,
            self._region_config,
        )

        # Set up the identity
        self._identity = self.setup_identity(
            az_cli_auth,
            sp_env_auth,
            browser_auth,
            client_id,
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
            self._mutelist = Microsoft365Mutelist(
                mutelist_content=mutelist_content,
            )
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = Microsoft365Mutelist(
                mutelist_path=mutelist_path,
            )

        Provider.set_global_provider(self)

    @property
    def identity(self):
        """Returns the identity of the Microsoft365 provider."""
        return self._identity

    @property
    def type(self):
        """Returns the type of the Microsoft365 provider."""
        return self._type

    @property
    def session(self):
        """Returns the session object associated with the Microsoft365 provider."""
        return self._session

    @property
    def region_config(self):
        """Returns the region configuration for the Microsoft365 provider."""
        return self._region_config

    @property
    def audit_config(self):
        """Returns the audit configuration for the Microsoft365 provider."""
        return self._audit_config

    @property
    def fixer_config(self):
        """Returns the fixer configuration."""
        return self._fixer_config

    @property
    def mutelist(self) -> Microsoft365Mutelist:
        """Mutelist object associated with this Microsoft365 provider."""
        return self._mutelist

    @staticmethod
    def validate_arguments(
        az_cli_auth: bool,
        sp_env_auth: bool,
        browser_auth: bool,
        tenant_id: str,
        client_id: str,
        client_secret: str,
    ):
        """
        Validates the authentication arguments for the Microsoft365 provider.

        Args:
            az_cli_auth (bool): Flag indicating whether Azure CLI authentication is enabled.
            sp_env_auth (bool): Flag indicating whether application authentication with environment variables is enabled.
            browser_auth (bool): Flag indicating whether browser authentication is enabled.
            tenant_id (str): The Microsoft365 Tenant ID.
            client_id (str): The Microsoft365 Client ID.
            client_secret (str): The Microsoft365 Client Secret.

        Raises:
            Microsoft365BrowserAuthNoTenantIDError: If browser authentication is enabled but the tenant ID is not found.
        """

        if not client_id and not client_secret:
            if not browser_auth and tenant_id:
                raise Microsoft365BrowserAuthNoFlagError(
                    file=os.path.basename(__file__),
                    message="Microsoft365 Tenant ID (--browser-auth) is required for browser authentication mode",
                )
            elif not az_cli_auth and not sp_env_auth and not browser_auth:
                raise Microsoft365NoAuthenticationMethodError(
                    file=os.path.basename(__file__),
                    message="Microsoft365 provider requires at least one authentication method set: [--az-cli-auth | --sp-env-auth | --browser-auth]",
                )
            elif browser_auth and not tenant_id:
                raise Microsoft365BrowserAuthNoTenantIDError(
                    file=os.path.basename(__file__),
                    message="Microsoft365 Tenant ID (--tenant-id) is required for browser authentication mode",
                )
        else:
            if not tenant_id:
                raise Microsoft365NotTenantIdButClientIdAndClienSecretError(
                    file=os.path.basename(__file__),
                    message="Tenant Id is required for Microsoft365 static credentials. Make sure you are using the correct credentials.",
                )

    @staticmethod
    def setup_region_config(region):
        """
        Sets up the region configuration for the Microsoft365 provider.

        Args:
            region (str): The name of the region.

        Returns:
            Microsoft365RegionConfig: The region configuration object.

        """
        try:
            config = get_regions_config(region)

            return Microsoft365RegionConfig(
                name=region,
                authority=config["authority"],
                base_url=config["base_url"],
                credential_scopes=config["credential_scopes"],
            )
        except ArgumentTypeError as validation_error:
            logger.error(
                f"{validation_error.__class__.__name__}[{validation_error.__traceback__.tb_lineno}]: {validation_error}"
            )
            raise Microsoft365ArgumentTypeValidationError(
                file=os.path.basename(__file__),
                original_exception=validation_error,
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise Microsoft365SetUpRegionConfigError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    def print_credentials(self):
        """Microsoft365 credentials information.

        This method prints the Microsoft365 Tenant Domain, Microsoft365 Tenant ID, Microsoft365 Region,
        Microsoft365 Subscriptions, Microsoft365 Identity Type, and Microsoft365 Identity ID.

        Args:
            None

        Returns:
            None
        """
        report_lines = [
            f"Microsoft365 Region: {Fore.YELLOW}{self.region_config.name}{Style.RESET_ALL}",
            f"Microsoft365 Tenant Domain: {Fore.YELLOW}{self._identity.tenant_domain}{Style.RESET_ALL} Microsoft365 Tenant ID: {Fore.YELLOW}{self._identity.tenant_id}{Style.RESET_ALL}",
            f"Microsoft365 Identity Type: {Fore.YELLOW}{self._identity.identity_type}{Style.RESET_ALL} Microsoft365 Identity ID: {Fore.YELLOW}{self._identity.identity_id}{Style.RESET_ALL}",
        ]
        report_title = (
            f"{Style.BRIGHT}Using the Microsoft365 credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)

    # TODO: setup_session or setup_credentials?
    # This should be setup_credentials, since it is setting up the credentials for the provider
    @staticmethod
    def setup_session(
        az_cli_auth: bool,
        sp_env_auth: bool,
        browser_auth: bool,
        tenant_id: str,
        microsoft365_credentials: dict,
        region_config: Microsoft365RegionConfig,
    ):
        """Returns the Microsoft365 credentials object.

        Set up the Microsoft365 session with the specified authentication method.

        Args:
            az_cli_auth (bool): Flag indicating whether to use Azure CLI authentication.
            sp_env_auth (bool): Flag indicating whether to use application authentication with environment variables.
            browser_auth (bool): Flag indicating whether to use interactive browser authentication.
            tenant_id (str): The Microsoft365 Active Directory tenant ID.
            microsoft365_credentials (dict): The Microsoft365 configuration object. It contains the following keys:
                - tenant_id: The Microsoft365 Active Directory tenant ID.
                - client_id: The Microsoft365 client ID.
                - client_secret: The Microsoft365 client secret
            region_config (Microsoft365RegionConfig): The region configuration object.

        Returns:
            credentials: The Microsoft365 credentials object.

        Raises:
            Exception: If failed to retrieve Microsoft365 credentials.

        """
        if not browser_auth:
            try:
                if (
                    sp_env_auth
                    and Microsoft365Provider.check_application_creds_env_vars()
                ):
                    try:
                        credentials = ClientSecretCredential(
                            tenant_id=getenv("M365_TENANT_ID"),
                            client_id=getenv("M365_CLIENT_ID"),
                            client_secret=getenv("M365_CLIENT_SECRET"),
                        )
                        return credentials
                    except ClientAuthenticationError as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise Microsoft365ClientAuthenticationError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                    except CredentialUnavailableError as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise Microsoft365CredentialsUnavailableError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                    except Exception as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise Microsoft365ConfigCredentialsError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                elif az_cli_auth:
                    try:
                        credentials = DefaultAzureCredential(
                            exclude_environment_credential=True,
                            exclude_cli_credential=not az_cli_auth,
                            # Microsoft365 Auth using Managed Identity is not supported
                            exclude_managed_identity_credential=True,
                            # Microsoft365 Auth using Visual Studio is not supported
                            exclude_visual_studio_code_credential=True,
                            # Microsoft365 Auth using Shared Token Cache is not supported
                            exclude_shared_token_cache_credential=True,
                            # Microsoft365 Auth using PowerShell is not supported
                            exclude_powershell_credential=True,
                            # set Authority of a Microsoft Entra endpoint
                            authority=region_config.authority,
                        )
                    except ClientAuthenticationError as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise Microsoft365ClientAuthenticationError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                    except CredentialUnavailableError as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise Microsoft365CredentialsUnavailableError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                    except Exception as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise Microsoft365DefaultAzureCredentialError(
                            file=os.path.basename(__file__), original_exception=error
                        )
            except Exception as error:
                logger.critical("Failed to retrieve Microsoft365 credentials")
                logger.critical(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                )
                raise Microsoft365SetUpSessionError(
                    file=os.path.basename(__file__), original_exception=error
                )
        else:
            try:
                credentials = InteractiveBrowserCredential(tenant_id=tenant_id)
            except Exception as error:
                logger.critical(
                    "Failed to retrieve Microsoft365 credentials using browser authentication"
                )
                logger.critical(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                )
                raise Microsoft365InteractiveBrowserCredentialError(
                    file=os.path.basename(__file__), original_exception=error
                )

        return credentials

    @staticmethod
    def test_connection(
        az_cli_auth: bool = False,
        sp_env_auth: bool = False,
        browser_auth: bool = False,
        tenant_id: str = None,
        region: str = "Microsoft365Global",
        raise_on_exception=True,
        client_id=None,
        client_secret=None,
    ) -> Connection:
        """Test connection to Microsoft365 subscription.

        Test the connection to an Microsoft365 subscription using the provided credentials.

        Args:

            az_cli_auth (bool): Flag indicating whether to use Azure CLI authentication.
            sp_env_auth (bool): Flag indicating whether to use application authentication with environment variables.
            browser_auth (bool): Flag indicating whether to use interactive browser authentication.
            tenant_id (str): The Microsoft365 Active Directory tenant ID.
            region (str): The Microsoft365 region.
            raise_on_exception (bool): Flag indicating whether to raise an exception if the connection fails.
            client_id (str): The Microsoft365 client ID.
            client_secret (str): The Microsoft365 client secret.

        Returns:
            bool: True if the connection is successful, False otherwise.

        Raises:
            Exception: If failed to test the connection to Microsoft365 subscription.
            Microsoft365ArgumentTypeValidationError: If there is an error in the argument type validation.
            Microsoft365SetUpRegionConfigError: If there is an error in setting up the region configuration.
            Microsoft365InteractiveBrowserCredentialError: If there is an error in retrieving the Microsoft365 credentials using browser authentication.
            Microsoft365HTTPResponseError: If there is an HTTP response error.
            Microsoft365ConfigCredentialsError: If there is an error in configuring the Microsoft365 credentials from a dictionary.


        Examples:
            >>> Microsoft365Provider.test_connection(az_cli_auth=True)
            True
            >>> Microsoft365Provider.test_connection(sp_env_auth=False, browser_auth=True, tenant_id=None)
            False, ArgumentTypeError: Microsoft365 Tenant ID is required only for browser authentication mode
            >>> Microsoft365Provider.test_connection(tenant_id="XXXXXXXXXX", client_id="XXXXXXXXXX", client_secret="XXXXXXXXXX")
            True
        """
        try:
            Microsoft365Provider.validate_arguments(
                az_cli_auth,
                sp_env_auth,
                browser_auth,
                tenant_id,
                client_id,
                client_secret,
            )
            region_config = Microsoft365Provider.setup_region_config(region)

            # Get the dict from the static credentials
            microsoft365_credentials = None
            if tenant_id and client_id and client_secret:
                microsoft365_credentials = (
                    Microsoft365Provider.validate_static_credentials(
                        tenant_id=tenant_id,
                        client_id=client_id,
                        client_secret=client_secret,
                    )
                )

            # Set up the Microsoft365 session
            credentials = Microsoft365Provider.setup_session(
                az_cli_auth,
                sp_env_auth,
                browser_auth,
                tenant_id,
                region_config,
                microsoft365_credentials,
                region_config,
            )

            GraphServiceClient(credentials=credentials)

            logger.info("Microsoft365 provider: Connection to Microsoft365 successful")

            return Connection(is_connected=True)

        # Exceptions from setup_region_config
        except Microsoft365ArgumentTypeValidationError as type_validation_error:
            logger.error(
                f"{type_validation_error.__class__.__name__}[{type_validation_error.__traceback__.tb_lineno}]: {type_validation_error}"
            )
            if raise_on_exception:
                raise type_validation_error
            return Connection(error=type_validation_error)
        except Microsoft365SetUpRegionConfigError as region_config_error:
            logger.error(
                f"{region_config_error.__class__.__name__}[{region_config_error.__traceback__.tb_lineno}]: {region_config_error}"
            )
            if raise_on_exception:
                raise region_config_error
            return Connection(error=region_config_error)
        # Exceptions from setup_session
        except Microsoft365EnvironmentVariableError as environment_credentials_error:
            logger.error(
                f"{environment_credentials_error.__class__.__name__}[{environment_credentials_error.__traceback__.tb_lineno}]: {environment_credentials_error}"
            )
            if raise_on_exception:
                raise environment_credentials_error
            return Connection(error=environment_credentials_error)
        except Microsoft365ConfigCredentialsError as config_credentials_error:
            logger.error(
                f"{config_credentials_error.__class__.__name__}[{config_credentials_error.__traceback__.tb_lineno}]: {config_credentials_error}"
            )
            if raise_on_exception:
                raise config_credentials_error
            return Connection(error=config_credentials_error)
        except Microsoft365ClientAuthenticationError as client_auth_error:
            logger.error(
                f"{client_auth_error.__class__.__name__}[{client_auth_error.__traceback__.tb_lineno}]: {client_auth_error}"
            )
            if raise_on_exception:
                raise client_auth_error
            return Connection(error=client_auth_error)
        except Microsoft365CredentialsUnavailableError as credential_unavailable_error:
            logger.error(
                f"{credential_unavailable_error.__class__.__name__}[{credential_unavailable_error.__traceback__.tb_lineno}]: {credential_unavailable_error}"
            )
            if raise_on_exception:
                raise credential_unavailable_error
            return Connection(error=credential_unavailable_error)
        except (
            Microsoft365ClientIdAndClientSecretNotBelongingToTenantIdError
        ) as tenant_id_error:
            logger.error(
                f"{tenant_id_error.__class__.__name__}[{tenant_id_error.__traceback__.tb_lineno}]: {tenant_id_error}"
            )
            if raise_on_exception:
                raise tenant_id_error
            return Connection(error=tenant_id_error)
        except (
            Microsoft365TenantIdAndClientSecretNotBelongingToClientIdError
        ) as client_id_error:
            logger.error(
                f"{client_id_error.__class__.__name__}[{client_id_error.__traceback__.tb_lineno}]: {client_id_error}"
            )
            if raise_on_exception:
                raise client_id_error
            return Connection(error=client_id_error)
        except (
            Microsoft365TenantIdAndClientIdNotBelongingToClientSecretError
        ) as client_secret_error:
            logger.error(
                f"{client_secret_error.__class__.__name__}[{client_secret_error.__traceback__.tb_lineno}]: {client_secret_error}"
            )
            if raise_on_exception:
                raise client_secret_error
            return Connection(error=client_secret_error)
        # Exceptions from provider_id validation
        except Microsoft365InvalidProviderIdError as invalid_credentials_error:
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
                raise Microsoft365HTTPResponseError(
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
    def check_application_creds_env_vars():
        """
        Checks the presence of required environment variables for application authentication against Microsoft365.

        This method checks for the presence of the following environment variables:
        - M365_CLIENT_ID: Microsoft365 client ID
        - M365_TENANT_ID: Microsoft365 tenant ID
        - M365_CLIENT_SECRET: Microsoft365 client secret

        Returns:
            bool: True if all environment variables are present, False otherwise.
        """
        logger.info(
            "Microsoft365 provider: checking service principal environment variables  ..."
        )
        missing_env_vars = []
        for env_var in ["M365_CLIENT_ID", "M365_TENANT_ID", "M365_CLIENT_SECRET"]:
            if not getenv(env_var):
                missing_env_vars.append(env_var)

        if missing_env_vars:
            raise Microsoft365CredentialsUnavailableError(
                file=os.path.basename(__file__),
                message=f"Missing environment variables needed to authenticate against Microsoft365: {', '.join(missing_env_vars)}",
            )
        else:
            return True

    def setup_identity(
        self,
        az_cli_auth,
        sp_env_auth,
        browser_auth,
        client_id,
    ):
        """
        Sets up the identity for the Microsoft365 provider.

        Args:
            az_cli_auth (bool): Flag indicating if Azure CLI authentication is used.
            sp_env_auth (bool): Flag indicating if application authentication with environment variables is used.
            browser_auth (bool): Flag indicating if interactive browser authentication is used.
            client_id (str): The Microsoft365 client ID.

        Returns:
            Microsoft365IdentityInfo: An instance of Microsoft365IdentityInfo containing the identity information.
        """
        credentials = self.session
        # TODO: fill this object with real values not default and set to none
        identity = Microsoft365IdentityInfo()

        # If credentials comes from service principal or browser, if the required permissions are assigned
        # the identity can access AAD and retrieve the tenant domain name.
        # With cli also should be possible but right now it does not work, microsoft365 python package issue is coming
        # At the time of writting this with az cli creds is not working, despite that is included
        if az_cli_auth or sp_env_auth or browser_auth or client_id:

            async def get_microsoft365_identity():
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
                    raise Microsoft365HTTPResponseError(
                        file=os.path.basename(__file__),
                        original_exception=error,
                    )
                except ClientAuthenticationError as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                    )
                    raise Microsoft365GetTokenIdentityError(
                        file=os.path.basename(__file__),
                        original_exception=error,
                    )
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                    )
                # since that exception is not considered as critical, we keep filling another identity fields
                # The id of the sp can be retrieved from environment variables
                if sp_env_auth or client_id:
                    identity.identity_id = getenv("M365_CLIENT_ID")
                    identity.identity_type = "Application"
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

            asyncio.get_event_loop().run_until_complete(get_microsoft365_identity())
            return identity

    @staticmethod
    def validate_static_credentials(
        tenant_id: str = None, client_id: str = None, client_secret: str = None
    ) -> dict:
        """
        Validates the static credentials for the Microsoft365 provider.

        Args:
            tenant_id (str): The Microsoft365 Active Directory tenant ID.
            client_id (str): The Microsoft365 client ID.
            client_secret (str): The Microsoft365 client secret.

        Raises:
            Microsoft365NotValidTenantIdError: If the provided Microsoft365 Tenant ID is not valid.
            Microsoft365NotValidClientIdError: If the provided Microsoft365 Client ID is not valid.
            Microsoft365NotValidClientSecretError: If the provided Microsoft365 Client Secret is not valid.
            Microsoft365ClientIdAndClientSecretNotBelongingToTenantIdError: If the provided Microsoft365 Client ID and Client Secret do not belong to the specified Tenant ID.
            Microsoft365TenantIdAndClientSecretNotBelongingToClientIdError: If the provided Microsoft365 Tenant ID and Client Secret do not belong to the specified Client ID.
            Microsoft365TenantIdAndClientIdNotBelongingToClientSecretError: If the provided Microsoft365 Tenant ID and Client ID do not belong to the specified Client Secret.

        Returns:
            dict: A dictionary containing the validated static credentials.
        """
        # Validate the Tenant ID
        try:
            UUID(tenant_id)
        except ValueError:
            raise Microsoft365NotValidTenantIdError(
                file=os.path.basename(__file__),
                message="The provided Microsoft365 Tenant ID is not valid.",
            )

        # Validate the Client ID
        try:
            UUID(client_id)
        except ValueError:
            raise Microsoft365NotValidClientIdError(
                file=os.path.basename(__file__),
                message="The provided Microsoft365 Client ID is not valid.",
            )
        # Validate the Client Secret
        if not re.match("^[a-zA-Z0-9._~-]+$", client_secret):
            raise Microsoft365NotValidClientSecretError(
                file=os.path.basename(__file__),
                message="The provided Microsoft365 Client Secret is not valid.",
            )

        try:
            Microsoft365Provider.verify_client(tenant_id, client_id, client_secret)
            return {
                "tenant_id": tenant_id,
                "client_id": client_id,
                "client_secret": client_secret,
            }
        except Microsoft365NotValidTenantIdError as tenant_id_error:
            logger.error(
                f"{tenant_id_error.__class__.__name__}[{tenant_id_error.__traceback__.tb_lineno}]: {tenant_id_error}"
            )
            raise Microsoft365ClientIdAndClientSecretNotBelongingToTenantIdError(
                file=os.path.basename(__file__),
                message="The provided Microsoft365 Client ID and Client Secret do not belong to the specified Tenant ID.",
            )
        except Microsoft365NotValidClientIdError as client_id_error:
            logger.error(
                f"{client_id_error.__class__.__name__}[{client_id_error.__traceback__.tb_lineno}]: {client_id_error}"
            )
            raise Microsoft365TenantIdAndClientSecretNotBelongingToClientIdError(
                file=os.path.basename(__file__),
                message="The provided Microsoft365 Tenant ID and Client Secret do not belong to the specified Client ID.",
            )
        except Microsoft365NotValidClientSecretError as client_secret_error:
            logger.error(
                f"{client_secret_error.__class__.__name__}[{client_secret_error.__traceback__.tb_lineno}]: {client_secret_error}"
            )
            raise Microsoft365TenantIdAndClientIdNotBelongingToClientSecretError(
                file=os.path.basename(__file__),
                message="The provided Microsoft365 Tenant ID and Client ID do not belong to the specified Client Secret.",
            )

    @staticmethod
    def verify_client(tenant_id, client_id, client_secret) -> None:
        """
        Verifies the Microsoft365 client credentials using the specified tenant ID, client ID, and client secret.

        Args:
            tenant_id (str): The Microsoft365 Active Directory tenant ID.
            client_id (str): The Microsoft365 client ID.
            client_secret (str): The Microsoft365 client secret.

        Raises:
            Microsoft365NotValidTenantIdError: If the provided Microsoft365 Tenant ID is not valid.
            Microsoft365NotValidClientIdError: If the provided Microsoft365 Client ID is not valid.
            Microsoft365NotValidClientSecretError: If the provided Microsoft365 Client Secret is not valid.

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
                    raise Microsoft365NotValidTenantIdError(
                        file=os.path.basename(__file__),
                        message="The provided Microsoft 365 Tenant ID is not valid for the specified Client ID and Client Secret.",
                    )
                if f"Application with identifier '{client_id}'" in error_description:
                    raise Microsoft365NotValidClientIdError(
                        file=os.path.basename(__file__),
                        message="The provided Microsoft 365 Client ID is not valid for the specified Tenant ID and Client Secret.",
                    )
                if "Invalid client secret provided" in error_description:
                    raise Microsoft365NotValidClientSecretError(
                        file=os.path.basename(__file__),
                        message="The provided Microsoft 365 Client Secret is not valid for the specified Tenant ID and Client ID.",
                    )

        except Exception as e:
            # Generic exception handling (if needed)
            raise RuntimeError(f"An unexpected error occurred: {str(e)}")
