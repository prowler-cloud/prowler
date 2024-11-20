import asyncio
import os
from argparse import ArgumentTypeError
from os import getenv

import requests
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.identity import ClientSecretCredential, DefaultAzureCredential
from colorama import Fore, Style
from msgraph import GraphServiceClient

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider
from prowler.providers.microsoft365.exceptions.exceptions import (
    Microsoft365ArgumentTypeValidationError,
    Microsoft365CredentialsUnavailableError,
    Microsoft365EnvironmentVariableError,
    Microsoft365GetTokenIdentityError,
    Microsoft365HTTPResponseError,
    Microsoft365SetUpRegionConfigError,
)
from prowler.providers.microsoft365.lib.arguments.arguments import (
    validate_microsoft365_region,
)
from prowler.providers.microsoft365.lib.mutelist.mutelist import Microsoft365Mutelist
from prowler.providers.microsoft365.lib.regions.regions import get_regions_config
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
        _locations (dict): A dictionary containing the available locations for the Microsoft365 provider.
        _mutelist (Microsoft365Mutelist): The mutelist object associated with the Microsoft365 provider.
        audit_metadata (Audit_Metadata): The audit metadata for the Microsoft365 provider.

    Methods:
        __init__ -> Initializes the Microsoft365 provider.
        identity(self): Returns the identity of the Microsoft365 provider.
        type(self): Returns the type of the Microsoft365 provider.
        session(self): Returns the session object associated with the Microsoft365 provider.
        region_config(self): Returns the region configuration for the Microsoft365 provider.
        locations(self): Returns a list of available locations for the Microsoft365 provider.
        audit_config(self): Returns the audit configuration for the Microsoft365 provider.
        fixer_config(self): Returns the fixer configuration.
        output_options(self, options: tuple): Sets the output options for the Microsoft365 provider.
        mutelist(self) -> Microsoft365Mutelist: Returns the mutelist object associated with the Microsoft365 provider.
        validate_arguments(cls, az_cli_auth, app_env_auth, browser_auth, managed_identity_auth, tenant_id): Validates the authentication arguments for the Microsoft365 provider.
        setup_region_config(cls, region): Sets up the region configuration for the Microsoft365 provider.
        print_credentials(self): Prints the Microsoft365 credentials information.
        setup_session(cls, az_cli_auth, app_env_auth, browser_auth, managed_identity_auth, tenant_id, region_config): Set up the Microsoft365 session with the specified authentication method.
    """

    _type: str = "microsoft365"
    _session: DefaultAzureCredential
    _identity: Microsoft365IdentityInfo
    _audit_config: dict
    _region_config: Microsoft365RegionConfig
    _locations: dict
    _mutelist: Microsoft365Mutelist
    # TODO: this is not optional, enforce for all providers
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        app_env_auth: bool = False,
        tenant_id: str = None,
        region: str = "AzureCloud",
        client_id: str = None,
        client_secret: str = None,
        config_content: dict = None,
        config_path: str = None,
        mutelist_path: str = None,
        mutelist_content: dict = None,
        fixer_config: dict = {},
    ):
        """
        Initializes the Microsoft365 provider.

        Args:
            app_env_auth (bool): Flag indicating whether to use application authentication with environment variables.
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
            Microsoft365DefaultMicrosoft365CredentialError: If there is an error in retrieving the Microsoft365 credentials.
            Microsoft365InteractiveBrowserCredentialError: If there is an error in retrieving the Microsoft365 credentials using browser authentication.
            Microsoft365ConfigCredentialsError: If there is an error in configuring the Microsoft365 credentials from a dictionary.
            Microsoft365GetTokenIdentityError: If there is an error in getting the token from the Microsoft365 identity.
            Microsoft365HTTPResponseError: If there is an HTTP response error.
        """
        logger.info("Setting Microsoft365 provider ...")

        logger.info("Checking if any credentials mode is set ...")

        logger.info("Checking if region is different than default one")
        self._region_config = self.setup_region_config(region)

        # Set up the Microsoft365 session
        self._session = self.setup_session(
            app_env_auth,
        )

        # Set up the identity
        self._identity = self.setup_identity(
            app_env_auth,
        )

        # TODO: should we keep this here or within the identity?
        self._locations = self.get_locations(self.session)

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
    def locations(self):
        """Returns a list of available locations for the Microsoft365 provider."""
        return self._locations

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
    def setup_region_config(region):
        """
        Sets up the region configuration for the Microsoft365 provider.

        Args:
            region (str): The name of the region.

        Returns:
            Microsoft365RegionConfig: The region configuration object.

        """
        try:
            validate_microsoft365_region(region)
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
        printed_subscriptions = []
        for key, value in self._identity.subscriptions.items():
            intermediate = key + ": " + value
            printed_subscriptions.append(intermediate)
        report_lines = [
            f"Microsoft365 Region: {Fore.YELLOW}{self.region_config.name}{Style.RESET_ALL}",
            f"Microsoft365 Identity Type: {Fore.YELLOW}{self._identity.identity_type}{Style.RESET_ALL} Microsoft365 Identity ID: {Fore.YELLOW}{self._identity.identity_id}{Style.RESET_ALL}",
        ]
        report_title = (
            f"{Style.BRIGHT}Using the Azure credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)

    # TODO: setup_session or setup_credentials?
    # This should be setup_credentials, since it is setting up the credentials for the provider
    @staticmethod
    def setup_session(
        app_env_auth: bool,
    ):
        """Returns the Microsoft365 credentials object.

        Set up the Microsoft365 session with the specified authentication method.

        Args:
            app_env_auth (bool): Flag indicating whether to use application authentication with environment variables.

        Returns:
            credentials: The Microsoft365 credentials object.

        Raises:
            Exception: If failed to retrieve Microsoft365 credentials.

        """
        # Browser auth creds cannot be set with DefaultMicrosoft365Credentials()
        if app_env_auth:
            try:
                Microsoft365Provider.check_application_creds_env_vars()
                credentials = ClientSecretCredential(
                    client_id=getenv("APP_CLIENT_ID"),
                    tenant_id=getenv("APP_TENANT_ID"),
                    client_secret=getenv("APP_CLIENT_SECRET"),
                )
            except (
                Microsoft365EnvironmentVariableError
            ) as environment_credentials_error:
                logger.critical(
                    f"{environment_credentials_error.__class__.__name__}[{environment_credentials_error.__traceback__.tb_lineno}] -- {environment_credentials_error}"
                )
                raise environment_credentials_error
        if not credentials:
            raise Microsoft365CredentialsUnavailableError(
                file=os.path.basename(__file__),
                message="Failed to retrieve Microsoft365 credentials.",
            )
        return credentials

    @staticmethod
    def check_application_creds_env_vars():
        """
        Checks the presence of required environment variables for application authentication against Azure.

        This method checks for the presence of the following environment variables:
        - APP_CLIENT_ID: Microsoft365 client ID
        - APP_TENANT_ID: Microsoft365 tenant ID
        - APP_CLIENT_SECRET: Microsoft365 client secret

        If any of the environment variables is missing, it logs a critical error and exits the program.
        """
        logger.info(
            "Microsoft365 provider: checking service principal environment variables  ..."
        )
        for env_var in ["APP_CLIENT_ID", "APP_TENANT_ID", "APP_CLIENT_SECRET"]:
            if not getenv(env_var):
                logger.critical(
                    f"Microsoft365 provider: Missing environment variable {env_var} needed to authenticate against Microsoft365"
                )
                raise Microsoft365EnvironmentVariableError(
                    file=os.path.basename(__file__),
                    message=f"Missing environment variable {env_var} required to authenticate.",
                )

    def setup_identity(
        self,
        app_env_auth,
    ):
        """
        Sets up the identity for the Microsoft365 provider.

        Args:
            app_env_auth (bool): Flag indicating if Service Principal environment authentication is used.

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
        if app_env_auth:

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
                if app_env_auth:
                    # The id of the sp can be retrieved from environment variables
                    identity.identity_id = getenv("APP_CLIENT_ID")
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

            asyncio.get_event_loop().run_until_complete(get_microsoft365_identity())

        return identity

    def get_locations(self, credentials) -> dict[str, list[str]]:
        """
        Retrieves the locations available for each subscription using the provided credentials.

        Args:
            credentials: The credentials object used to authenticate the request.

        Returns:
            A dictionary containing the locations available for each subscription. The dictionary
            has subscription display names as keys and lists of location names as values.
        """
        locations = None
        if credentials:
            locations = {}
            token = credentials.get_token("https://management.azure.com/.default").token
            for display_name, subscription_id in self._identity.subscriptions.items():
                locations.update({display_name: []})
                url = f"https://management.azure.com/subscriptions/{subscription_id}/locations?api-version=2022-12-01"
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                }
                response = requests.get(url, headers=headers)
                if response.status_code == 200:
                    data = response.json()
                    for location in data["value"]:
                        locations[display_name].append(location["name"])
        return locations
