import asyncio
import os
from argparse import ArgumentTypeError
from os import getenv

import requests
from azure.core.exceptions import HttpResponseError
from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential
from azure.mgmt.subscription import SubscriptionClient
from colorama import Fore, Style
from msgraph import GraphServiceClient

from prowler.config.config import get_default_mute_file_path
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.azure.exceptions.exceptions import (
    AzureArgumentTypeValidationError,
    AzureBrowserAuthNoTenantIDError,
    AzureDefaultAzureCredentialError,
    AzureEnvironmentVariableError,
    AzureHTTPResponseError,
    AzureInteractiveBrowserCredentialError,
    AzureNoAuthenticationMethodError,
    AzureNoSubscriptionsError,
    AzureSetUpIdentityError,
    AzureSetUpRegionConfigError,
    AzureTenantIDNoBrowserAuthError,
)
from prowler.providers.azure.lib.arguments.arguments import validate_azure_region
from prowler.providers.azure.lib.mutelist.mutelist import AzureMutelist
from prowler.providers.azure.lib.regions.regions import get_regions_config
from prowler.providers.azure.models import (
    AzureIdentityInfo,
    AzureOutputOptions,
    AzureRegionConfig,
)
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider


class AzureProvider(Provider):
    """
    Represents an Azure provider.

    This class provides functionality to interact with the Azure cloud provider.
    It handles authentication, region configuration, and provides access to various properties and methods
    related to the Azure provider.

    Attributes:
        _type (str): The type of the provider, which is set to "azure".
        _session (DefaultAzureCredential): The session object associated with the Azure provider.
        _identity (AzureIdentityInfo): The identity information for the Azure provider.
        _audit_config (dict): The audit configuration for the Azure provider.
        _region_config (AzureRegionConfig): The region configuration for the Azure provider.
        _locations (dict): A dictionary containing the available locations for the Azure provider.
        _output_options (AzureOutputOptions): The output options for the Azure provider.
        _mutelist (AzureMutelist): The mutelist object associated with the Azure provider.
        audit_metadata (Audit_Metadata): The audit metadata for the Azure provider.

    Methods:
        __init__ -> Initializes the Azure provider.
        identity(self): Returns the identity of the Azure provider.
        type(self): Returns the type of the Azure provider.
        session(self): Returns the session object associated with the Azure provider.
        region_config(self): Returns the region configuration for the Azure provider.
        locations(self): Returns a list of available locations for the Azure provider.
        audit_config(self): Returns the audit configuration for the Azure provider.
        fixer_config(self): Returns the fixer configuration.
        output_options(self, options: tuple): Sets the output options for the Azure provider.
        mutelist(self) -> AzureMutelist: Returns the mutelist object associated with the Azure provider.
        get_output_mapping(self): Returns a dictionary that maps output keys to their corresponding values.
        validate_arguments(cls, az_cli_auth, sp_env_auth, browser_auth, managed_identity_auth, tenant_id): Validates the authentication arguments for the Azure provider.
        setup_region_config(cls, region): Sets up the region configuration for the Azure provider.
        print_credentials(self): Prints the Azure credentials information.
        setup_session(cls, az_cli_auth, sp_env_auth, browser_auth, managed_identity_auth, tenant_id, region_config): Set up the Azure session with the specified authentication method.
    """

    _type: str = "azure"
    _session: DefaultAzureCredential
    _identity: AzureIdentityInfo
    _audit_config: dict
    _region_config: AzureRegionConfig
    _locations: dict
    _output_options: AzureOutputOptions
    _mutelist: AzureMutelist
    # TODO: this is not optional, enforce for all providers
    audit_metadata: Audit_Metadata

    def __init__(
        self,
        az_cli_auth: bool = False,
        sp_env_auth: bool = False,
        browser_auth: bool = False,
        managed_identity_auth: bool = False,
        tenant_id: str = None,
        region: str = "AzureCloud",
        subscription_ids: list = [],
        audit_config: dict = {},
        fixer_config: dict = {},
    ):
        """
        Initializes the Azure provider.

        Args:
            az_cli_auth (bool): Flag indicating whether to use Azure CLI authentication.
            sp_env_auth (bool): Flag indicating whether to use Service Principal environment authentication.
            browser_auth (bool): Flag indicating whether to use interactive browser authentication.
            managed_identity_auth (bool): Flag indicating whether to use managed identity authentication.
            tenant_id (str): The Azure Active Directory tenant ID.
            region (str): The Azure region.
            subscription_ids (list): List of subscription IDs.
            audit_config (dict): The audit configuration for the Azure provider.
            fixer_config (dict): The fixer configuration.

        Returns:
            None

        Raises:
            AzureArgumentTypeValidationError: If there is an error in the argument type validation.
            AzureSetUpRegionConfigError: If there is an error in setting up the region configuration.
            AzureDefaultAzureCredentialError: If there is an error in retrieving the Azure credentials.
            AzureInteractiveBrowserCredentialError: If there is an error in retrieving the Azure credentials using browser authentication.
        """
        logger.info("Setting Azure provider ...")

        logger.info("Checking if any credentials mode is set ...")

        # Validate the authentication arguments
        self.validate_arguments(
            az_cli_auth, sp_env_auth, browser_auth, managed_identity_auth, tenant_id
        )

        logger.info("Checking if region is different than default one")
        self._region_config = self.setup_region_config(region)

        # Set up the Azure session
        self._session = self.setup_session(
            az_cli_auth,
            sp_env_auth,
            browser_auth,
            managed_identity_auth,
            tenant_id,
            self._region_config,
        )

        # Set up the identity
        self._identity = self.setup_identity(
            az_cli_auth,
            sp_env_auth,
            browser_auth,
            managed_identity_auth,
            subscription_ids,
        )

        # TODO: should we keep this here or within the identity?
        self._locations = self.get_locations(self.session)

        # Audit Config
        self._audit_config = audit_config
        # Fixer Config
        self._fixer_config = fixer_config

    @property
    def identity(self):
        """Returns the identity of the Azure provider."""
        return self._identity

    @property
    def type(self):
        """Returns the type of the Azure provider."""
        return self._type

    @property
    def session(self):
        """Returns the session object associated with the Azure provider."""
        return self._session

    @property
    def region_config(self):
        """Returns the region configuration for the Azure provider."""
        return self._region_config

    @property
    def locations(self):
        """Returns a list of available locations for the Azure provider."""
        return self._locations

    @property
    def audit_config(self):
        """Returns the audit configuration for the Azure provider."""
        return self._audit_config

    @property
    def fixer_config(self):
        """Returns the fixer configuration."""
        return self._fixer_config

    @property
    def output_options(self):
        """Returns the output options for the Azure provider."""
        return self._output_options

    @output_options.setter
    def output_options(self, options: tuple):
        """Set output options for the Azure provider.

        Sets the output options for the Azure provider using the provided arguments and bulk checks metadata.

        Args:
            options (tuple): A tuple containing the arguments and bulk checks metadata.

        Returns:
            None
        """
        arguments, bulk_checks_metadata = options
        self._output_options = AzureOutputOptions(
            arguments, bulk_checks_metadata, self._identity
        )

    @property
    def mutelist(self) -> AzureMutelist:
        """Mutelist object associated with this Azure provider."""
        return self._mutelist

    @mutelist.setter
    def mutelist(self, mutelist_path):
        """
        mutelist.setter sets the provider's mutelist.
        """
        # Set default mutelist path if none is set
        if not mutelist_path:
            mutelist_path = get_default_mute_file_path(self.type)

        self._mutelist = AzureMutelist(mutelist_path)

    @property
    def get_output_mapping(self):
        """Dictionary that maps output keys to their corresponding values."""
        return {
            # identity_type: identity_id
            # "auth_method": "identity.profile",
            "provider": "type",
            # "account_uid": "identity.account",
            # TODO: store subscription_name + id pairs
            # "account_name": "organizations_metadata.account_details_name",
            # "account_email": "organizations_metadata.account_details_email",
            # TODO: check the tenant_ids
            # TODO: we have to get the account organization, the tenant is not that
            "account_organization_uid": "identity.tenant_ids",
            "account_organization_name": "identity.tenant_domain",
            # TODO: pending to get the subscription tags
            # "account_tags": "organizations_metadata.account_details_tags",
            "partition": "region_config.name",
        }

    # TODO: this should be moved to the argparse, if not we need to enforce it from the Provider
    # previously was using the AzureException
    @staticmethod
    def validate_arguments(
        az_cli_auth: bool,
        sp_env_auth: bool,
        browser_auth: bool,
        managed_identity_auth: bool,
        tenant_id: str,
    ):
        """
        Validates the authentication arguments for the Azure provider.

        Args:
            az_cli_auth (bool): Flag indicating whether AZ CLI authentication is enabled.
            sp_env_auth (bool): Flag indicating whether Service Principal environment authentication is enabled.
            browser_auth (bool): Flag indicating whether browser authentication is enabled.
            managed_identity_auth (bool): Flag indicating whether managed identity authentication is enabled.
            tenant_id (str): The Azure Tenant ID.

        Raises:
            AzureBrowserAuthNoTenantIDError: If browser authentication is enabled but the tenant ID is not found.
        """
        if not browser_auth and tenant_id:
            raise AzureTenantIDNoBrowserAuthError(
                file=os.path.basename(__file__),
                message="Azure Tenant ID (--tenant-id) is required for browser authentication mode",
            )
        elif (
            not az_cli_auth
            and not sp_env_auth
            and not browser_auth
            and not managed_identity_auth
        ):
            raise AzureNoAuthenticationMethodError(
                file=os.path.basename(__file__),
                message="Azure provider requires at least one authentication method set: [--az-cli-auth | --sp-env-auth | --browser-auth | --managed-identity-auth]",
            )
        elif browser_auth and not tenant_id:
            raise AzureBrowserAuthNoTenantIDError(
                file=os.path.basename(__file__),
                message="Azure Tenant ID (--tenant-id) is required for browser authentication mode",
            )

    @staticmethod
    def setup_region_config(region):
        """
        Sets up the region configuration for the Azure provider.

        Args:
            region (str): The name of the region.

        Returns:
            AzureRegionConfig: The region configuration object.

        """
        try:
            validate_azure_region(region)
            config = get_regions_config(region)

            return AzureRegionConfig(
                name=region,
                authority=config["authority"],
                base_url=config["base_url"],
                credential_scopes=config["credential_scopes"],
            )
        except ArgumentTypeError as validation_error:
            logger.error(
                f"{validation_error.__class__.__name__}[{validation_error.__traceback__.tb_lineno}]: {validation_error}"
            )
            raise AzureArgumentTypeValidationError(
                file=os.path.basename(__file__),
                original_exception=validation_error,
            )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise AzureSetUpRegionConfigError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

    def print_credentials(self):
        """Azure credentials information.

        This method prints the Azure Tenant Domain, Azure Tenant ID, Azure Region,
        Azure Subscriptions, Azure Identity Type, and Azure Identity ID.

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
            f"Azure Tenant Domain: {Fore.YELLOW}{self._identity.tenant_domain}{Style.RESET_ALL} Azure Tenant ID: {Fore.YELLOW}{self._identity.tenant_ids[0]}{Style.RESET_ALL}",
            f"Azure Region: {Fore.YELLOW}{self.region_config.name}{Style.RESET_ALL}",
            f"Azure Subscriptions: {Fore.YELLOW}{printed_subscriptions}{Style.RESET_ALL}",
            f"Azure Identity Type: {Fore.YELLOW}{self._identity.identity_type}{Style.RESET_ALL} Azure Identity ID: {Fore.YELLOW}{self._identity.identity_id}{Style.RESET_ALL}",
        ]
        report_title = (
            f"{Style.BRIGHT}Using the Azure credentials below:{Style.RESET_ALL}"
        )
        print_boxes(report_lines, report_title)

    # TODO: setup_session or setup_credentials?
    # This should be setup_credentials, since it is setting up the credentials for the provider
    @staticmethod
    def setup_session(
        az_cli_auth: bool,
        sp_env_auth: bool,
        browser_auth: bool,
        managed_identity_auth: bool,
        tenant_id: str,
        region_config: AzureRegionConfig,
    ):
        """Returns the Azure credentials object.

        Set up the Azure session with the specified authentication method.

        Args:
            az_cli_auth (bool): Flag indicating whether to use Azure CLI authentication.
            sp_env_auth (bool): Flag indicating whether to use Service Principal authentication with environment variables.
            browser_auth (bool): Flag indicating whether to use interactive browser authentication.
            managed_identity_auth (bool): Flag indicating whether to use managed identity authentication.
            tenant_id (str): The Azure Active Directory tenant ID.
            region_config (AzureRegionConfig): The region configuration object.

        Returns:
            credentials: The Azure credentials object.

        Raises:
            Exception: If failed to retrieve Azure credentials.

        """
        # Browser auth creds cannot be set with DefaultAzureCredentials()
        if not browser_auth:
            if sp_env_auth:
                try:
                    AzureProvider.check_service_principal_creds_env_vars()
                except AzureEnvironmentVariableError as environment_credentials_error:
                    logger.critical(
                        f"{environment_credentials_error.__class__.__name__}[{environment_credentials_error.__traceback__.tb_lineno}] -- {environment_credentials_error}"
                    )
                    raise environment_credentials_error
            try:
                # Since the input vars come as True when it is wanted to be used, we need to inverse it since
                # DefaultAzureCredential sets the auth method excluding the others
                credentials = DefaultAzureCredential(
                    exclude_environment_credential=not sp_env_auth,
                    exclude_cli_credential=not az_cli_auth,
                    exclude_managed_identity_credential=not managed_identity_auth,
                    # Azure Auth using Visual Studio is not supported
                    exclude_visual_studio_code_credential=True,
                    # Azure Auth using Shared Token Cache is not supported
                    exclude_shared_token_cache_credential=True,
                    # Azure Auth using PowerShell is not supported
                    exclude_powershell_credential=True,
                    # set Authority of a Microsoft Entra endpoint
                    authority=region_config.authority,
                )
            except Exception as error:
                logger.critical("Failed to retrieve azure credentials")
                logger.critical(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                )
                raise AzureDefaultAzureCredentialError(
                    file=os.path.basename(__file__), original_exception=error
                )
        else:
            try:
                credentials = InteractiveBrowserCredential(tenant_id=tenant_id)
            except Exception as error:
                logger.critical(
                    "Failed to retrieve azure credentials using browser authentication"
                )
                logger.critical(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                )
                raise AzureInteractiveBrowserCredentialError(
                    file=os.path.basename(__file__), original_exception=error
                )

        return credentials

    @staticmethod
    def test_connection(
        az_cli_auth=False,
        sp_env_auth=False,
        browser_auth=False,
        managed_identity_auth=False,
        tenant_id=None,
        region="AzureCloud",
        raise_on_exception=True,
    ) -> Connection:
        """Test connection to Azure subscription.

        Test the connection to an Azure subscription using the provided credentials.

        Args:
            az_cli_auth (bool): Flag indicating if Azure CLI authentication is used.
            sp_env_auth (bool): Flag indicating if Service Principal environment authentication is used.
            browser_auth (bool): Flag indicating if browser authentication is used.
            managed_identity_auth (bool): Flag indicating if managed entity authentication is used.
            tenant_id (str): The Azure Active Directory tenant ID.
            region (str): The Azure region.
            raise_on_exception (bool): Flag indicating whether to raise an exception if the connection fails.

        Returns:
            bool: True if the connection is successful, False otherwise.

        Raises:
            Exception: If failed to test the connection to Azure subscription.
            AzureArgumentTypeValidationError: If there is an error in the argument type validation.
            AzureSetUpRegionConfigError: If there is an error in setting up the region configuration.
            AzureDefaultAzureCredentialError: If there is an error in retrieving the Azure credentials.
            AzureInteractiveBrowserCredentialError: If there is an error in retrieving the Azure credentials using browser authentication.
            AzureHTTPResponseError: If there is an HTTP response error.


        Examples:
            >>> AzureProvider.test_connection(az_cli_auth=True)
            True
            >>> AzureProvider.test_connection(sp_env_auth=False, browser_auth=True, tenant_id=None)
            False, ArgumentTypeError: Azure Tenant ID is required only for browser authentication mode
        """
        try:
            AzureProvider.validate_arguments(
                az_cli_auth, sp_env_auth, browser_auth, managed_identity_auth, tenant_id
            )
            region_config = AzureProvider.setup_region_config(region)
            # Set up the Azure session
            credentials = AzureProvider.setup_session(
                az_cli_auth,
                sp_env_auth,
                browser_auth,
                managed_identity_auth,
                tenant_id,
                region_config,
            )
            # Create a SubscriptionClient
            subscription_client = SubscriptionClient(credentials)

            # Get info from the first subscription
            subscription = next(subscription_client.subscriptions.list())

            logger.info(f"Connected to Azure subscription: {subscription.display_name}")

            return Connection(is_connected=True)
        # Exceptions from validate_arguments
        except AzureNoAuthenticationMethodError as no_auth_method_error:
            logger.error(str(no_auth_method_error))
            if raise_on_exception:
                raise no_auth_method_error
            return Connection(error=no_auth_method_error)
        except AzureBrowserAuthNoTenantIDError as browser_no_tenant_error:
            logger.error(str(browser_no_tenant_error))
            if raise_on_exception:
                raise browser_no_tenant_error
            return Connection(error=browser_no_tenant_error)
        except AzureTenantIDNoBrowserAuthError as tenant_no_browser_error:
            logger.error(str(tenant_no_browser_error))
        # Exceptions from setup_region_config
        except AzureArgumentTypeValidationError as type_validation_error:
            logger.error(str(type_validation_error))
            if raise_on_exception:
                raise type_validation_error
            return Connection(error=type_validation_error)
        except AzureSetUpRegionConfigError as region_config_error:
            logger.error(str(region_config_error))
            if raise_on_exception:
                raise region_config_error
            return Connection(error=region_config_error)
        # Exceptions from setup_session
        except AzureEnvironmentVariableError as environment_credentials_error:
            logger.error(str(environment_credentials_error))
            if raise_on_exception:
                raise environment_credentials_error
            return Connection(error=environment_credentials_error)
        except AzureDefaultAzureCredentialError as default_credentials_error:
            logger.error(str(default_credentials_error))
            if raise_on_exception:
                raise default_credentials_error
            return Connection(error=default_credentials_error)
        except AzureInteractiveBrowserCredentialError as interactive_browser_error:
            logger.error(str(interactive_browser_error))
            if raise_on_exception:
                raise interactive_browser_error
            return Connection(error=interactive_browser_error)
        # Exceptions from SubscriptionClient
        except HttpResponseError as http_response_error:
            logger.error(
                f"{http_response_error.__class__.__name__}[{http_response_error.__traceback__.tb_lineno}]: {http_response_error}"
            )
            if raise_on_exception:
                raise AzureHTTPResponseError(
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
            "Azure provider: checking service principal environment variables  ..."
        )
        for env_var in ["AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET"]:
            if not getenv(env_var):
                logger.critical(
                    f"Azure provider: Missing environment variable {env_var} needed to authenticate against Azure"
                )
                raise AzureEnvironmentVariableError(
                    file=os.path.basename(__file__),
                    message=f"Missing environment variable {env_var} required to authenticate.",
                )

    def setup_identity(
        self,
        az_cli_auth,
        sp_env_auth,
        browser_auth,
        managed_identity_auth,
        subscription_ids,
    ):
        """
        Sets up the identity for the Azure provider.

        Args:
            az_cli_auth (bool): Flag indicating if Azure CLI authentication is used.
            sp_env_auth (bool): Flag indicating if Service Principal environment authentication is used.
            browser_auth (bool): Flag indicating if browser authentication is used.
            managed_identity_auth (bool): Flag indicating if managed entity authentication is used.
            subscription_ids (list): List of subscription IDs.

        Returns:
            AzureIdentityInfo: An instance of AzureIdentityInfo containing the identity information.
        """
        credentials = self.session
        # TODO: fill this object with real values not default and set to none
        identity = AzureIdentityInfo()

        # If credentials comes from service principal or browser, if the required permissions are assigned
        # the identity can access AAD and retrieve the tenant domain name.
        # With cli also should be possible but right now it does not work, azure python package issue is coming
        # At the time of writting this with az cli creds is not working, despite that is included
        if sp_env_auth or browser_auth or az_cli_auth:

            async def get_azure_identity():
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

                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                    )
                # since that exception is not considered as critical, we keep filling another identity fields
                if sp_env_auth:
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

            asyncio.get_event_loop().run_until_complete(get_azure_identity())

        # Managed identities only can be assigned resource, resource group and subscription scope permissions
        elif managed_identity_auth:
            identity.identity_id = "Default Managed Identity ID"
            identity.identity_type = "Managed Identity"
            # Pending extracting info from managed identity

        # once we have populated the id, type, and domain fields, time to retrieve the subscriptions and finally the tenants
        try:
            logger.info(
                "Trying to subscriptions and tenant ids to populate identity structure ..."
            )
            subscriptions_client = SubscriptionClient(
                credential=credentials,
                base_url=self.region_config.base_url,
                credential_scopes=self.region_config.credential_scopes,
            )
            if not subscription_ids:
                logger.info("Scanning all the Azure subscriptions...")
                for subscription in subscriptions_client.subscriptions.list():
                    # TODO: get tags or labels
                    # TODO: fill with AzureSubscription
                    identity.subscriptions.update(
                        {subscription.display_name: subscription.subscription_id}
                    )
            else:
                logger.info("Scanning the subscriptions passed as argument ...")
                for id in subscription_ids:
                    subscription = subscriptions_client.subscriptions.get(
                        subscription_id=id
                    )
                    identity.subscriptions.update({subscription.display_name: id})

            # If there are no subscriptions listed -> checks are not going to be run against any resource
            if not identity.subscriptions:
                logger.critical(
                    "It was not possible to retrieve any subscriptions, please check your permission assignments"
                )
                raise AzureNoSubscriptionsError(
                    file=os.path.basename(__file__),
                    message="No subscriptions were found, please check your permission assignments.",
                )

            tenants = subscriptions_client.tenants.list()
            for tenant in tenants:
                identity.tenant_ids.append(tenant.tenant_id)
        # This error is critical, since it implies something is wrong with the credentials provided
        except Exception as error:
            logger.critical(
                "Error with credentials provided getting subscriptions and tenants to scan"
            )
            logger.critical(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            raise AzureSetUpIdentityError(
                file=os.path.basename(__file__),
                original_exception=error,
            )

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
