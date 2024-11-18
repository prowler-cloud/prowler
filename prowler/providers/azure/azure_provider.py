import asyncio
import os
import re
from argparse import ArgumentTypeError
from itertools import chain
from os import getenv
from typing import Union
from uuid import UUID

import requests
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.identity import (
    ClientSecretCredential,
    CredentialUnavailableError,
    DefaultAzureCredential,
    InteractiveBrowserCredential,
)
from azure.mgmt.subscription import SubscriptionClient
from colorama import Fore, Style
from msgraph import GraphServiceClient

from prowler.config.config import (
    default_config_file_path,
    get_default_mute_file_path,
    load_and_validate_config_file,
)
from prowler.lib.logger import logger
from prowler.lib.utils.utils import print_boxes
from prowler.providers.azure.exceptions.exceptions import (
    AzureArgumentTypeValidationError,
    AzureBrowserAuthNoTenantIDError,
    AzureClientAuthenticationError,
    AzureClientIdAndClientSecretNotBelongingToTenantIdError,
    AzureConfigCredentialsError,
    AzureCredentialsUnavailableError,
    AzureDefaultAzureCredentialError,
    AzureEnvironmentVariableError,
    AzureGetTokenIdentityError,
    AzureHTTPResponseError,
    AzureInteractiveBrowserCredentialError,
    AzureInvalidProviderIdError,
    AzureNoAuthenticationMethodError,
    AzureNoSubscriptionsError,
    AzureNotTenantIdButClientIdAndClienSecretError,
    AzureNotValidClientIdError,
    AzureNotValidClientSecretError,
    AzureNotValidTenantIdError,
    AzureSetUpIdentityError,
    AzureSetUpRegionConfigError,
    AzureSetUpSessionError,
    AzureTenantIdAndClientIdNotBelongingToClientSecretError,
    AzureTenantIdAndClientSecretNotBelongingToClientIdError,
    AzureTenantIDNoBrowserAuthError,
)
from prowler.providers.azure.lib.arguments.arguments import validate_azure_region
from prowler.providers.azure.lib.mutelist.mutelist import AzureMutelist
from prowler.providers.azure.lib.regions.regions import get_regions_config
from prowler.providers.azure.models import AzureIdentityInfo, AzureRegionConfig
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
        config_path: str = None,
        config_content: dict = None,
        fixer_config: dict = {},
        mutelist_path: str = None,
        mutelist_content: dict = None,
        client_id: str = None,
        client_secret: str = None,
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
            config_path (str): The path to the configuration file.
            config_content (dict): The configuration content.
            fixer_config (dict): The fixer configuration.
            mutelist_path (str): The path to the mutelist file.
            mutelist_content (dict): The mutelist content.
            client_id (str): The Azure client ID.
            client_secret (str): The Azure client secret.

        Returns:
            None

        Raises:
            AzureArgumentTypeValidationError: If there is an error in the argument type validation.
            AzureSetUpRegionConfigError: If there is an error in setting up the region configuration.
            AzureDefaultAzureCredentialError: If there is an error in retrieving the Azure credentials.
            AzureInteractiveBrowserCredentialError: If there is an error in retrieving the Azure credentials using browser authentication.
            AzureConfigCredentialsError: If there is an error in configuring the Azure credentials from a dictionary.
            AzureGetTokenIdentityError: If there is an error in getting the token from the Azure identity.
            AzureHTTPResponseError: If there is an HTTP response error.

        Usage:
            - Authentication: By default Prowler uses Azure Python SDK identity package authentication methods using the classes DefaultAzureCredential and InteractiveBrowserCredential.
                - Using static credentials:
                    >>> AzureProvider(
                    ...     az_cli_auth=False,
                    ...     sp_env_auth=False,
                    ...     browser_auth=False,
                    ...     managed_identity_auth=False,
                    ...     tenant_id="XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
                    ...     client_id="XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
                    ...     client_secret="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
                    ... )
                - Using Azure CLI authentication:
                    >>> AzureProvider(
                    ...     az_cli_auth=True,
                    ...     sp_env_auth=False,
                    ...     browser_auth=False,
                    ...     managed_identity_auth=False,
                    ... )
                - Using Service Principal environment authentication:
                    >>> AzureProvider(
                    ...     az_cli_auth=False,
                    ...     sp_env_auth=True,
                    ...     browser_auth=False,
                    ...     managed_identity_auth=False,
                    ... )
                - Using interactive browser authentication:
                    >>> AzureProvider(
                    ...     az_cli_auth=False,
                    ...     sp_env_auth=False,
                    ...     browser_auth=True,
                    ...     managed_identity_auth=False,
                    ...     tenant_id="XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX",
                    ... )
                    * Note: Azure Tenant ID is required for browser authentication mode.
                - Using managed identity authentication:
                    >>> AzureProvider(
                    ...     az_cli_auth=False,
                    ...     sp_env_auth=False,
                    ...     browser_auth=False,
                    ...     managed_identity_auth=True,
                    ... )
            - Non default azure region: Microsoft provides clouds for compliance with regional laws, which are available for your use. By default, Prowler uses AzureCloud cloud which is the comercial one.
              If you want to use a different one, you can specify it using the region parameter.
                >>> AzureProvider(
                ...     az_cli_auth=False,
                ...     sp_env_auth=True,
                ...     browser_auth=False,
                ...     managed_identity_auth=False,
                ...     region="AzureUSGovernment",
                ... )
            - Subscriptions: rowler is multisubscription, which means that is going to scan all the subscriptions is able to list. If you only assign permissions to one subscription, it is going to scan a single one.
              Prowler also allows you to specify the subscriptions you want to scan by passing a list of subscription IDs.
                >>> AzureProvider(
                ...     az_cli_auth=False,
                ...     sp_env_auth=True,
                ...     browser_auth=False,
                ...     managed_identity_auth=False,
                ...     subscription_ids=["XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"],
                ... )

        """
        logger.info("Setting Azure provider ...")

        logger.info("Checking if any credentials mode is set ...")

        # Validate the authentication arguments
        self.validate_arguments(
            az_cli_auth,
            sp_env_auth,
            browser_auth,
            managed_identity_auth,
            tenant_id,
            client_id,
            client_secret,
        )

        logger.info("Checking if region is different than default one")
        self._region_config = self.setup_region_config(region)

        # Get the dict from the static credentials
        azure_credentials = None
        if tenant_id and client_id and client_secret:
            azure_credentials = self.validate_static_credentials(
                tenant_id=tenant_id, client_id=client_id, client_secret=client_secret
            )

        # Set up the Azure session
        self._session = self.setup_session(
            az_cli_auth,
            sp_env_auth,
            browser_auth,
            managed_identity_auth,
            tenant_id,
            azure_credentials,
            self._region_config,
        )

        # Set up the identity
        self._identity = self.setup_identity(
            az_cli_auth,
            sp_env_auth,
            browser_auth,
            managed_identity_auth,
            subscription_ids,
            client_id,
        )

        # TODO: should we keep this here or within the identity?
        self._locations = self.get_locations()

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
            self._mutelist = AzureMutelist(
                mutelist_content=mutelist_content,
            )
        else:
            if not mutelist_path:
                mutelist_path = get_default_mute_file_path(self.type)
            self._mutelist = AzureMutelist(
                mutelist_path=mutelist_path,
            )

        Provider.set_global_provider(self)

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
    def mutelist(self) -> AzureMutelist:
        """Mutelist object associated with this Azure provider."""
        return self._mutelist

    # TODO: this should be moved to the argparse, if not we need to enforce it from the Provider
    # previously was using the AzureException
    @staticmethod
    def validate_arguments(
        az_cli_auth: bool,
        sp_env_auth: bool,
        browser_auth: bool,
        managed_identity_auth: bool,
        tenant_id: str,
        client_id: str,
        client_secret: str,
    ):
        """
        Validates the authentication arguments for the Azure provider.

        Args:
            az_cli_auth (bool): Flag indicating whether AZ CLI authentication is enabled.
            sp_env_auth (bool): Flag indicating whether Service Principal environment authentication is enabled.
            browser_auth (bool): Flag indicating whether browser authentication is enabled.
            managed_identity_auth (bool): Flag indicating whether managed identity authentication is enabled.
            tenant_id (str): The Azure Tenant ID.
            client_id (str): The Azure Client ID.
            client_secret (str): The Azure Client Secret.

        Raises:
            AzureBrowserAuthNoTenantIDError: If browser authentication is enabled but the tenant ID is not found.
        """

        if not client_id and not client_secret:
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
        else:
            if not tenant_id:
                raise AzureNotTenantIdButClientIdAndClienSecretError(
                    file=os.path.basename(__file__),
                    message="Tenant Id is required for Azure static credentials. Make sure you are using the correct credentials.",
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
        azure_credentials: dict,
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
            azure_credentials (dict): The Azure configuration object. It contains the following keys:
                - tenant_id: The Azure Active Directory tenant ID.
                - client_id: The Azure client ID.
                - client_secret: The Azure client secret
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
                if azure_credentials:
                    try:
                        credentials = ClientSecretCredential(
                            tenant_id=azure_credentials["tenant_id"],
                            client_id=azure_credentials["client_id"],
                            client_secret=azure_credentials["client_secret"],
                        )
                        return credentials
                    except ClientAuthenticationError as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise AzureClientAuthenticationError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                    except CredentialUnavailableError as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise AzureCredentialsUnavailableError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                    except Exception as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise AzureConfigCredentialsError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                else:
                    # Since the authentication method to be used will come as True, we have to negate it since
                    # DefaultAzureCredential sets just one authentication method, excluding the others
                    try:
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
                    except ClientAuthenticationError as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise AzureClientAuthenticationError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                    except CredentialUnavailableError as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise AzureCredentialsUnavailableError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                    except Exception as error:
                        logger.critical("Failed to retrieve azure credentials")
                        logger.critical(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise AzureDefaultAzureCredentialError(
                            file=os.path.basename(__file__), original_exception=error
                        )
            except Exception as error:
                logger.critical("Failed to retrieve azure credentials")
                logger.critical(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                )
                raise AzureSetUpSessionError(
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
        client_id=None,
        client_secret=None,
        provider_id=None,
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
            client_id (str): The Azure client ID.
            client_secret (str): The Azure client secret.
            provider_id (str): The provider ID, in this case it's the Azure subscription ID.

        Returns:
            bool: True if the connection is successful, False otherwise.

        Raises:
            Exception: If failed to test the connection to Azure subscription.
            AzureArgumentTypeValidationError: If there is an error in the argument type validation.
            AzureSetUpRegionConfigError: If there is an error in setting up the region configuration.
            AzureDefaultAzureCredentialError: If there is an error in retrieving the Azure credentials.
            AzureInteractiveBrowserCredentialError: If there is an error in retrieving the Azure credentials using browser authentication.
            AzureHTTPResponseError: If there is an HTTP response error.
            AzureConfigCredentialsError: If there is an error in configuring the Azure credentials from a dictionary.


        Examples:
            >>> AzureProvider.test_connection(az_cli_auth=True)
            True
            >>> AzureProvider.test_connection(sp_env_auth=False, browser_auth=True, tenant_id=None)
            False, ArgumentTypeError: Azure Tenant ID is required only for browser authentication mode
            >>> AzureProvider.test_connection(tenant_id="XXXXXXXXXX", client_id="XXXXXXXXXX", client_secret="XXXXXXXXXX")
            True
        """
        try:
            AzureProvider.validate_arguments(
                az_cli_auth,
                sp_env_auth,
                browser_auth,
                managed_identity_auth,
                tenant_id,
                client_id,
                client_secret,
            )
            region_config = AzureProvider.setup_region_config(region)

            # Get the dict from the static credentials
            azure_credentials = None
            if tenant_id and client_id and client_secret:
                azure_credentials = AzureProvider.validate_static_credentials(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret,
                )

            # Set up the Azure session
            credentials = AzureProvider.setup_session(
                az_cli_auth,
                sp_env_auth,
                browser_auth,
                managed_identity_auth,
                tenant_id,
                azure_credentials,
                region_config,
            )
            # Create a SubscriptionClient
            subscription_client = SubscriptionClient(credentials)

            # Get info from the subscriptions
            available_subscriptions = []
            for subscription in subscription_client.subscriptions.list():
                available_subscriptions.append(subscription)

            if provider_id and provider_id not in [
                sub.subscription_id for sub in available_subscriptions
            ]:
                raise AzureInvalidProviderIdError(
                    file=os.path.basename(__file__),
                    message="The provided credentials are not valid for the specified Azure subscription.",
                )

            logger.info("Azure provider: Connection to Azure subscription successful")

            return Connection(is_connected=True)
        # Exceptions from validate_arguments
        except AzureNoAuthenticationMethodError as no_auth_method_error:
            logger.error(
                f"{no_auth_method_error.__class__.__name__}[{no_auth_method_error.__traceback__.tb_lineno}]: {no_auth_method_error}"
            )
            if raise_on_exception:
                raise no_auth_method_error
            return Connection(error=no_auth_method_error)
        except AzureBrowserAuthNoTenantIDError as browser_no_tenant_error:
            logger.error(
                f"{browser_no_tenant_error.__class__.__name__}[{browser_no_tenant_error.__traceback__.tb_lineno}]: {browser_no_tenant_error}"
            )
            if raise_on_exception:
                raise browser_no_tenant_error
            return Connection(error=browser_no_tenant_error)
        except AzureTenantIDNoBrowserAuthError as tenant_no_browser_error:
            logger.error(
                f"{tenant_no_browser_error.__class__.__name__}[{tenant_no_browser_error.__traceback__.tb_lineno}]: {tenant_no_browser_error}"
            )
        # Exceptions from setup_region_config
        except AzureArgumentTypeValidationError as type_validation_error:
            logger.error(
                f"{type_validation_error.__class__.__name__}[{type_validation_error.__traceback__.tb_lineno}]: {type_validation_error}"
            )
            if raise_on_exception:
                raise type_validation_error
            return Connection(error=type_validation_error)
        except AzureSetUpRegionConfigError as region_config_error:
            logger.error(
                f"{region_config_error.__class__.__name__}[{region_config_error.__traceback__.tb_lineno}]: {region_config_error}"
            )
            if raise_on_exception:
                raise region_config_error
            return Connection(error=region_config_error)
        # Exceptions from setup_session
        except AzureEnvironmentVariableError as environment_credentials_error:
            logger.error(
                f"{environment_credentials_error.__class__.__name__}[{environment_credentials_error.__traceback__.tb_lineno}]: {environment_credentials_error}"
            )
            if raise_on_exception:
                raise environment_credentials_error
            return Connection(error=environment_credentials_error)
        except AzureDefaultAzureCredentialError as default_credentials_error:
            logger.error(
                f"{default_credentials_error.__class__.__name__}[{default_credentials_error.__traceback__.tb_lineno}]: {default_credentials_error}"
            )
            if raise_on_exception:
                raise default_credentials_error
            return Connection(error=default_credentials_error)
        except AzureInteractiveBrowserCredentialError as interactive_browser_error:
            logger.error(
                f"{interactive_browser_error.__class__.__name__}[{interactive_browser_error.__traceback__.tb_lineno}]: {interactive_browser_error}"
            )
            if raise_on_exception:
                raise interactive_browser_error
            return Connection(error=interactive_browser_error)
        except AzureConfigCredentialsError as config_credentials_error:
            logger.error(
                f"{config_credentials_error.__class__.__name__}[{config_credentials_error.__traceback__.tb_lineno}]: {config_credentials_error}"
            )
            if raise_on_exception:
                raise config_credentials_error
            return Connection(error=config_credentials_error)
        except AzureClientAuthenticationError as client_auth_error:
            logger.error(
                f"{client_auth_error.__class__.__name__}[{client_auth_error.__traceback__.tb_lineno}]: {client_auth_error}"
            )
            if raise_on_exception:
                raise client_auth_error
            return Connection(error=client_auth_error)
        except AzureCredentialsUnavailableError as credential_unavailable_error:
            logger.error(
                f"{credential_unavailable_error.__class__.__name__}[{credential_unavailable_error.__traceback__.tb_lineno}]: {credential_unavailable_error}"
            )
            if raise_on_exception:
                raise credential_unavailable_error
            return Connection(error=credential_unavailable_error)
        except AzureDefaultAzureCredentialError as default_credentials_error:
            logger.error(
                f"{default_credentials_error.__class__.__name__}[{default_credentials_error.__traceback__.tb_lineno}]: {default_credentials_error}"
            )
            if raise_on_exception:
                raise default_credentials_error
            return Connection(error=default_credentials_error)
        except (
            AzureClientIdAndClientSecretNotBelongingToTenantIdError
        ) as tenant_id_error:
            logger.error(
                f"{tenant_id_error.__class__.__name__}[{tenant_id_error.__traceback__.tb_lineno}]: {tenant_id_error}"
            )
            if raise_on_exception:
                raise tenant_id_error
            return Connection(error=tenant_id_error)
        except (
            AzureTenantIdAndClientSecretNotBelongingToClientIdError
        ) as client_id_error:
            logger.error(
                f"{client_id_error.__class__.__name__}[{client_id_error.__traceback__.tb_lineno}]: {client_id_error}"
            )
            if raise_on_exception:
                raise client_id_error
            return Connection(error=client_id_error)
        except (
            AzureTenantIdAndClientIdNotBelongingToClientSecretError
        ) as client_secret_error:
            logger.error(
                f"{client_secret_error.__class__.__name__}[{client_secret_error.__traceback__.tb_lineno}]: {client_secret_error}"
            )
            if raise_on_exception:
                raise client_secret_error
            return Connection(error=client_secret_error)
        # Exceptions from provider_id validation
        except AzureInvalidProviderIdError as invalid_credentials_error:
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
        client_id,
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
        if sp_env_auth or browser_auth or az_cli_auth or client_id:

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

                except HttpResponseError as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                    )
                    raise AzureHTTPResponseError(
                        file=os.path.basename(__file__),
                        original_exception=error,
                    )
                except ClientAuthenticationError as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                    )
                    raise AzureGetTokenIdentityError(
                        file=os.path.basename(__file__),
                        original_exception=error,
                    )
                except Exception as error:
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                    )
                # since that exception is not considered as critical, we keep filling another identity fields
                if sp_env_auth or client_id:
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

    def get_locations(self) -> dict[str, list[str]]:
        """
        Retrieves the locations available for each subscription using the provided credentials.

        Returns:
            A dictionary containing the locations available for each subscription. The dictionary
            has subscription display names as keys and lists of location names as values.

        Examples:
            >>> provider = AzureProvider(...)
            >>> provider.get_locations()
            {
                'Subscription 1': ['eastus', 'eastus2', 'westus', 'westus2'],
                'Subscription 2': ['eastus', 'eastus2', 'westus', 'westus2']
            }
        """
        credentials = self.session
        subscription_client = SubscriptionClient(credentials)
        locations = {}

        for display_name, subscription_id in self._identity.subscriptions.items():
            locations[display_name] = []

            # List locations for each subscription
            for location in subscription_client.subscriptions.list_locations(
                subscription_id
            ):
                locations[display_name].append(location.name)

        return locations

    def get_regions(self, subscription_ids: Union[list[str], None] = None) -> set:
        """
        Retrieves a set of regions available across all subscriptions or specific subscriptions if provided.

        Args:
            subscription_ids (List[str], optional): A list of subscription display names to filter the regions.
                If None, regions from all subscriptions are returned.

        Returns:
            Set[str]: A set containing the unique regions available across the specified subscriptions.

        Examples:
            >>> provider = AzureProvider(...)
            >>> provider.get_regions()
            {'eastus', 'eastus2', 'westus', 'westus2'}

            >>> provider.get_regions(subscription_ids=['Subscription 1'])
            {'eastus', 'eastus2', 'westus', 'westus2'}
        """
        locations = self.get_locations()
        if subscription_ids is not None:
            locations = {
                sid: regions
                for sid, regions in locations.items()
                if sid in subscription_ids
            }

        return set(chain.from_iterable(locations.values()))

    @staticmethod
    def validate_static_credentials(
        tenant_id: str = None, client_id: str = None, client_secret: str = None
    ) -> dict:
        """
        Validates the static credentials for the Azure provider.

        Args:
            tenant_id (str): The Azure Active Directory tenant ID.
            client_id (str): The Azure client ID.
            client_secret (str): The Azure client secret.

        Raises:
            AzureNotValidTenantIdError: If the provided Azure Tenant ID is not valid.
            AzureNotValidClientIdError: If the provided Azure Client ID is not valid.
            AzureNotValidClientSecretError: If the provided Azure Client Secret is not valid.
            AzureClientIdAndClientSecretNotBelongingToTenantIdError: If the provided Azure Client ID and Client Secret do not belong to the specified Tenant ID.
            AzureTenantIdAndClientSecretNotBelongingToClientIdError: If the provided Azure Tenant ID and Client Secret do not belong to the specified Client ID.
            AzureTenantIdAndClientIdNotBelongingToClientSecretError: If the provided Azure Tenant ID and Client ID do not belong to the specified Client Secret.

        Returns:
            dict: A dictionary containing the validated static credentials.
        """
        # Validate the Tenant ID
        try:
            UUID(tenant_id)
        except ValueError:
            raise AzureNotValidTenantIdError(
                file=os.path.basename(__file__),
                message="The provided Azure Tenant ID is not valid.",
            )

        # Validate the Client ID
        try:
            UUID(client_id)
        except ValueError:
            raise AzureNotValidClientIdError(
                file=os.path.basename(__file__),
                message="The provided Azure Client ID is not valid.",
            )
        # Validate the Client Secret
        if not re.match("^[a-zA-Z0-9._~-]+$", client_secret):
            raise AzureNotValidClientSecretError(
                file=os.path.basename(__file__),
                message="The provided Azure Client Secret is not valid.",
            )

        try:
            AzureProvider.verify_client(tenant_id, client_id, client_secret)
            return {
                "tenant_id": tenant_id,
                "client_id": client_id,
                "client_secret": client_secret,
            }
        except AzureNotValidTenantIdError as tenant_id_error:
            logger.error(
                f"{tenant_id_error.__class__.__name__}[{tenant_id_error.__traceback__.tb_lineno}]: {tenant_id_error}"
            )
            raise AzureClientIdAndClientSecretNotBelongingToTenantIdError(
                file=os.path.basename(__file__),
                message="The provided Azure Client ID and Client Secret do not belong to the specified Tenant ID.",
            )
        except AzureNotValidClientIdError as client_id_error:
            logger.error(
                f"{client_id_error.__class__.__name__}[{client_id_error.__traceback__.tb_lineno}]: {client_id_error}"
            )
            raise AzureTenantIdAndClientSecretNotBelongingToClientIdError(
                file=os.path.basename(__file__),
                message="The provided Azure Tenant ID and Client Secret do not belong to the specified Client ID.",
            )
        except AzureNotValidClientSecretError as client_secret_error:
            logger.error(
                f"{client_secret_error.__class__.__name__}[{client_secret_error.__traceback__.tb_lineno}]: {client_secret_error}"
            )
            raise AzureTenantIdAndClientIdNotBelongingToClientSecretError(
                file=os.path.basename(__file__),
                message="The provided Azure Tenant ID and Client ID do not belong to the specified Client Secret.",
            )

    @staticmethod
    def verify_client(tenant_id, client_id, client_secret) -> None:
        """
        Verifies the Azure client credentials using the specified tenant ID, client ID, and client secret.

        Args:
            tenant_id (str): The Azure Active Directory tenant ID.
            client_id (str): The Azure client ID.
            client_secret (str): The Azure client secret.

        Raises:
            AzureNotValidTenantIdError: If the provided Azure Tenant ID is not valid.
            AzureNotValidClientIdError: If the provided Azure Client ID is not valid.
            AzureNotValidClientSecretError: If the provided Azure Client Secret is not valid.

        Returns:
            None
        """
        url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        data = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": "https://graph.microsoft.com/.default",
        }
        response = requests.post(url, headers=headers, data=data).json()
        if "access_token" not in response.keys() and "error_codes" in response.keys():
            if f"Tenant '{tenant_id}'" in response["error_description"]:
                raise AzureNotValidTenantIdError(
                    file=os.path.basename(__file__),
                    message="The provided Azure Tenant ID is not valid for the specified Client ID and Client Secret.",
                )
            if (
                f"Application with identifier '{client_id}'"
                in response["error_description"]
            ):
                raise AzureNotValidClientIdError(
                    file=os.path.basename(__file__),
                    message="The provided Azure Client ID is not valid for the specified Tenant ID and Client Secret.",
                )
            if "Invalid client secret provided" in response["error_description"]:
                raise AzureNotValidClientSecretError(
                    file=os.path.basename(__file__),
                    message="The provided Azure Client Secret is not valid for the specified Tenant ID and Client ID.",
                )
