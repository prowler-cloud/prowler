import asyncio
import base64
import binascii
import logging
import os
import re
from argparse import ArgumentTypeError
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FuturesTimeoutError
from itertools import chain
from os import getenv
from typing import Optional, Union
from uuid import UUID

import requests
from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.identity import (
    CertificateCredential,
    ClientSecretCredential,
    CredentialUnavailableError,
    DefaultAzureCredential,
    InteractiveBrowserCredential,
)
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.subscription import SubscriptionClient
from colorama import Fore, Style
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import pkcs12
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
    AzureNotValidCertificateContentError,
    AzureNotValidCertificatePathError,
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
from prowler.providers.azure.lib.certificate import validate_certificate_bundle
from prowler.providers.azure.lib.mutelist.mutelist import AzureMutelist
from prowler.providers.azure.lib.regions.regions import get_regions_config
from prowler.providers.azure.models import AzureIdentityInfo, AzureRegionConfig
from prowler.providers.common.models import Audit_Metadata, Connection
from prowler.providers.common.provider import Provider

_PROWLER_CERT_THUMBPRINT_ATTR = "_prowler_certificate_thumbprint"

# Fallback storage used only when `setattr` is rejected (a future azure-identity
# release that locks the credential with `__slots__`); accessed via id() so no
# extra references keep the credential alive.
_CERTIFICATE_THUMBPRINT_FALLBACK: dict[int, str] = {}

# Matches the 30s HTTP timeout on the client-secret path so a hung Entra ID
# endpoint cannot stall a request thread or Celery worker on either flow.
_TOKEN_ACQUISITION_TIMEOUT_SECONDS = 30


def _build_certificate_credential(
    tenant_id: str,
    client_id: str,
    certificate_data: bytes,
    authority: Optional[str],
) -> "CertificateCredential":
    """Build a `CertificateCredential` and remember its SHA-1 thumbprint."""
    credentials = CertificateCredential(
        tenant_id=tenant_id,
        client_id=client_id,
        certificate_data=certificate_data,
        authority=authority,
    )
    _remember_certificate_thumbprint(
        credentials, _compute_certificate_thumbprint(certificate_data)
    )
    return credentials


def _remember_certificate_thumbprint(
    credential: "CertificateCredential", thumbprint: Optional[str]
) -> None:
    """Stash the thumbprint on the credential, tolerating slotted types."""
    if thumbprint is None:
        return
    try:
        setattr(credential, _PROWLER_CERT_THUMBPRINT_ATTR, thumbprint)
    except AttributeError:
        _CERTIFICATE_THUMBPRINT_FALLBACK[id(credential)] = thumbprint


def _get_certificate_thumbprint(credential: object) -> Optional[str]:
    """Return the thumbprint previously stashed for `credential`, if any."""
    thumbprint = getattr(credential, _PROWLER_CERT_THUMBPRINT_ATTR, None)
    if thumbprint is not None:
        return thumbprint
    return _CERTIFICATE_THUMBPRINT_FALLBACK.get(id(credential))


def _compute_certificate_thumbprint(cert_data: bytes) -> Optional[str]:
    """Compute the SHA-1 thumbprint of an X.509 certificate as uppercase hex.

    Accepts PEM, DER, or PKCS#12/PFX (with the private key). Returns None if
    no parser can read the bytes; logs each parser failure so the "Unknown
    certificate thumbprint" placeholder in `setup_identity` is diagnosable.
    """
    parser_errors: list[str] = []
    for loader_name, loader in (
        (
            "pkcs12",
            lambda data: pkcs12.load_key_and_certificates(
                data, None, default_backend()
            )[1],
        ),
        ("pem", lambda data: x509.load_pem_x509_certificate(data, default_backend())),
        ("der", lambda data: x509.load_der_x509_certificate(data, default_backend())),
    ):
        try:
            cert = loader(cert_data)
        except Exception as error:
            parser_errors.append(f"{loader_name}: {error.__class__.__name__}: {error}")
            continue
        if cert is None:
            continue
        return cert.fingerprint(hashes.SHA1()).hex().upper()
    if parser_errors:
        logger.warning(
            "Could not compute certificate thumbprint. Parsers tried: "
            + "; ".join(parser_errors)
        )
    return None


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
    sdk_only: bool = False
    _session: DefaultAzureCredential
    _identity: AzureIdentityInfo
    _audit_config: dict
    _region_config: AzureRegionConfig
    _locations: dict
    _mutelist: AzureMutelist
    _resource_groups: dict[str, list[str]]
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
        certificate_auth: bool = False,
        certificate_content: str = None,
        certificate_path: str = None,
        resource_groups: list = [],
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
            certificate_auth (bool): Flag indicating whether to use certificate authentication with environment variables (AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CERTIFICATE_CONTENT).
            certificate_content (str): Base64-encoded certificate and private key bundle matching the App Registration certificate.
            certificate_path (str): Path to a certificate and private key bundle matching the App Registration certificate.
            resource_groups (list): List of resource group names.

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
            - Subscriptions: Prowler is multisubscription, which means that is going to scan all the subscriptions is able to list. If you only assign permissions to one subscription, it is going to scan a single one.
              Prowler also allows you to specify the subscriptions you want to scan by passing a list of subscription IDs.
                >>> AzureProvider(
                ...     az_cli_auth=False,
                ...     sp_env_auth=True,
                ...     browser_auth=False,
                ...     managed_identity_auth=False,
                ...     subscription_ids=["XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX", "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"],
                ... )
            - Resource Groups: Prowler allows you to narrow the scan to specific resource groups.
                >>> AzureProvider(
                ...     az_cli_auth=True,
                ...     resource_groups=["rg-production", "rg-staging"],
                ... )

        """
        logger.info("Setting Azure provider ...")

        # Mute HPACK library logs to prevent token leakage in debug mode
        logging.getLogger("hpack").setLevel(logging.CRITICAL)

        logger.info("Checking if any credentials mode is set ...")

        # Validate the authentication arguments
        self.validate_arguments(
            az_cli_auth,
            sp_env_auth,
            browser_auth,
            managed_identity_auth,
            certificate_auth,
            tenant_id,
            client_id,
            client_secret,
            certificate_content,
            certificate_path,
        )

        logger.info("Checking if region is different than default one")
        self._region_config = self.setup_region_config(region)

        # Get the dict from the static credentials
        azure_credentials = None
        if (
            tenant_id
            and client_id
            and (client_secret or certificate_content or certificate_path)
        ):
            azure_credentials = self.validate_static_credentials(
                tenant_id=tenant_id,
                client_id=client_id,
                client_secret=client_secret,
                certificate_content=certificate_content,
                certificate_path=certificate_path,
                region_config=self._region_config,
            )

        # Set up the Azure session
        self._session = self.setup_session(
            az_cli_auth,
            sp_env_auth,
            browser_auth,
            managed_identity_auth,
            certificate_auth,
            certificate_path,
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
            certificate_auth,
            subscription_ids,
            client_id,
        )

        # TODO: should we keep this here or within the identity?
        self._locations = self.get_locations()

        self._resource_groups = self.validate_resource_groups(resource_groups)

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

    @property
    def resource_groups(self) -> dict[str, list[str]]:
        """Mapping of subscription ID to the list of resource groups to scan within it."""
        return self._resource_groups

    # TODO: this should be moved to the argparse, if not we need to enforce it from the Provider
    # previously was using the AzureException
    @staticmethod
    def validate_arguments(
        az_cli_auth: bool,
        sp_env_auth: bool,
        browser_auth: bool,
        managed_identity_auth: bool,
        certificate_auth: bool,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        certificate_content: str,
        certificate_path: str,
    ):
        """
        Validates the authentication arguments for the Azure provider.

        Args:
            az_cli_auth (bool): Flag indicating whether AZ CLI authentication is enabled.
            sp_env_auth (bool): Flag indicating whether Service Principal environment authentication is enabled.
            browser_auth (bool): Flag indicating whether browser authentication is enabled.
            managed_identity_auth (bool): Flag indicating whether managed identity authentication is enabled.
            certificate_auth (bool): Flag indicating whether certificate authentication is enabled.
            tenant_id (str): The Azure Tenant ID.
            client_id (str): The Azure Client ID.
            client_secret (str): The Azure Client Secret.
            certificate_content (str): The base64-encoded Azure certificate content.
            certificate_path (str): The path to the Azure certificate file.

        Raises:
            AzureBrowserAuthNoTenantIDError: If browser authentication is enabled but the tenant ID is not found.
        """

        # `--certificate-content`/`--certificate-path` are meaningful only with
        # `--certificate-auth` or a full static-credentials trio; without one
        # of those, setup_session would silently drop the certificate.
        if (certificate_content or certificate_path) and not certificate_auth:
            if not (tenant_id and client_id):
                raise AzureConfigCredentialsError(
                    file=os.path.basename(__file__),
                    message=(
                        "--certificate-content and --certificate-path require --certificate-auth, "
                        "or --tenant-id together with --client-id for the static-credentials flow."
                    ),
                )

        if (
            not client_id
            and not client_secret
            and not certificate_content
            and not certificate_path
        ):
            if not browser_auth and not certificate_auth and tenant_id:
                raise AzureTenantIDNoBrowserAuthError(
                    file=os.path.basename(__file__),
                    message="Azure Tenant ID (--tenant-id) is required for browser authentication mode",
                )
            elif (
                not az_cli_auth
                and not sp_env_auth
                and not browser_auth
                and not managed_identity_auth
                and not certificate_auth
            ):
                raise AzureNoAuthenticationMethodError(
                    file=os.path.basename(__file__),
                    message="Azure provider requires at least one authentication method set: [--az-cli-auth | --sp-env-auth | --browser-auth | --managed-identity-auth | --certificate-auth]",
                )
            elif browser_auth and not tenant_id:
                raise AzureBrowserAuthNoTenantIDError(
                    file=os.path.basename(__file__),
                    message="Azure Tenant ID (--tenant-id) is required for browser authentication mode",
                )
        else:
            # `--certificate-auth` reads tenant_id from AZURE_TENANT_ID at
            # setup_session time, so a missing --tenant-id is not a fatal
            # error for this specific mode.
            if not tenant_id and not certificate_auth:
                raise AzureNotTenantIdButClientIdAndClienSecretError(
                    file=os.path.basename(__file__),
                    message="Tenant Id is required for Azure static credentials. Make sure you are using the correct credentials.",
                )
            if not client_secret and not certificate_content and not certificate_path:
                raise AzureConfigCredentialsError(
                    file=os.path.basename(__file__),
                    message="You must provide a client secret, certificate content or certificate path for Azure static credentials.",
                )
            # Client secret and certificate are mutually exclusive: `setup_session`
            # short-circuits on the certificate branch and silently drops the
            # secret, which is confusing. Fail fast at argument-validation time.
            if client_secret and (certificate_content or certificate_path):
                raise AzureConfigCredentialsError(
                    file=os.path.basename(__file__),
                    message="Provide either a client secret or a certificate (content/path) for Azure static credentials, not both.",
                )
        # Certificate content and path are also mutually exclusive.
        if certificate_content and certificate_path:
            raise AzureConfigCredentialsError(
                file=os.path.basename(__file__),
                message="Provide either certificate content or a certificate path, not both.",
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
                graph_host=config["graph_host"],
                graph_scope=config["graph_scope"],
                logs_endpoint=config["logs_endpoint"],
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
        Azure Subscriptions, Azure Resource Groups, Azure Identity Type, and Azure Identity ID.

        Args:
            None

        Returns:
            None
        """
        printed_subscriptions = []
        for subscription_id, display_name in self._identity.subscriptions.items():
            intermediate = display_name + ": " + subscription_id
            printed_subscriptions.append(intermediate)
        report_lines = [
            f"Azure Tenant Domain: {Fore.YELLOW}{self._identity.tenant_domain}{Style.RESET_ALL} Azure Tenant ID: {Fore.YELLOW}{self._identity.tenant_ids[0]}{Style.RESET_ALL}",
            f"Azure Region: {Fore.YELLOW}{self.region_config.name}{Style.RESET_ALL}",
            f"Azure Subscriptions: {Fore.YELLOW}{printed_subscriptions}{Style.RESET_ALL}",
            f"Azure Resource Groups: {Fore.YELLOW}{sorted({rg for rgs in self._resource_groups.values() for rg in rgs}) if any(self._resource_groups.values()) else ('NONE (no matching resource groups found)' if self._resource_groups else 'ALL')}{Style.RESET_ALL}",
            f"Azure Identity Type: {Fore.YELLOW}{self._identity.identity_type}{Style.RESET_ALL} Azure Identity ID: {Fore.YELLOW}{self._identity.identity_id}{Style.RESET_ALL}",
        ]
        if self._identity.certificate_thumbprint:
            report_lines.append(
                f"Azure Certificate Thumbprint: {Fore.YELLOW}{self._identity.certificate_thumbprint}{Style.RESET_ALL}"
            )
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
        certificate_auth: bool,
        certificate_path: str,
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
            certificate_auth (bool): Flag indicating whether to use certificate authentication with environment variables.
            certificate_path (str): Path to a certificate file used when certificate_auth is enabled and certificate content is not supplied via env var.
            tenant_id (str): The Azure Active Directory tenant ID.
            azure_credentials (dict): The Azure configuration object. It contains the following keys:
                - tenant_id: The Azure Active Directory tenant ID.
                - client_id: The Azure client ID.
                - client_secret: The Azure client secret.
                - certificate_content: The base64-encoded Azure certificate content.
                - certificate_path: The path to the Azure certificate file.
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
            elif certificate_auth and not azure_credentials:
                # Env vars are only required for the pure env-var flow; skip
                # this check when azure_credentials already carries the material.
                try:
                    AzureProvider.check_certificate_creds_env_vars(
                        check_certificate_content=not certificate_path
                    )
                except AzureEnvironmentVariableError as environment_variable_error:
                    logger.critical(
                        f"{environment_variable_error.__class__.__name__}[{environment_variable_error.__traceback__.tb_lineno}] -- {environment_variable_error}"
                    )
                    raise environment_variable_error
            try:
                if azure_credentials:
                    try:
                        if azure_credentials.get("certificate_content"):
                            credentials = _build_certificate_credential(
                                tenant_id=azure_credentials["tenant_id"],
                                client_id=azure_credentials["client_id"],
                                certificate_data=base64.b64decode(
                                    azure_credentials["certificate_content"]
                                ),
                                authority=region_config.authority,
                            )
                        elif azure_credentials.get("certificate_path"):
                            with open(
                                azure_credentials["certificate_path"], "rb"
                            ) as cert_file:
                                certificate_data = cert_file.read()
                            credentials = _build_certificate_credential(
                                tenant_id=azure_credentials["tenant_id"],
                                client_id=azure_credentials["client_id"],
                                certificate_data=certificate_data,
                                authority=region_config.authority,
                            )
                        else:
                            credentials = ClientSecretCredential(
                                tenant_id=azure_credentials["tenant_id"],
                                client_id=azure_credentials["client_id"],
                                client_secret=azure_credentials["client_secret"],
                                authority=region_config.authority,
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
                elif certificate_auth:
                    try:
                        if certificate_path:
                            with open(certificate_path, "rb") as cert_file:
                                certificate_data = cert_file.read()
                        else:
                            certificate_data = base64.b64decode(
                                getenv("AZURE_CERTIFICATE_CONTENT"), validate=True
                            )
                        # Same fail-fast validation the static path runs.
                        validate_certificate_bundle(certificate_data)
                        # Prefer the explicit --tenant-id so a stale env var
                        # cannot silently authenticate against the wrong tenant.
                        credentials = _build_certificate_credential(
                            tenant_id=tenant_id or getenv("AZURE_TENANT_ID"),
                            client_id=getenv("AZURE_CLIENT_ID"),
                            certificate_data=certificate_data,
                            authority=region_config.authority,
                        )
                        return credentials
                    except ClientAuthenticationError as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        raise AzureClientAuthenticationError(
                            file=os.path.basename(__file__), original_exception=error
                        )
                    except (
                        binascii.Error,
                        FileNotFoundError,
                        PermissionError,
                        IsADirectoryError,
                        OSError,
                        ValueError,
                    ) as error:
                        # Base64 with stray whitespace, unreadable file, or bytes
                        # CertificateCredential cannot parse. Surface a
                        # certificate-specific error instead of a generic one.
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                        )
                        if certificate_path:
                            raise AzureNotValidCertificatePathError(
                                file=os.path.basename(__file__),
                                original_exception=error,
                            )
                        raise AzureNotValidCertificateContentError(
                            file=os.path.basename(__file__),
                            original_exception=error,
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
                credentials = InteractiveBrowserCredential(
                    tenant_id=tenant_id,
                    authority=region_config.authority,
                )
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
        # Certificate-based auth is keyword-only so callers cannot
        # accidentally bind `provider_id` (which used to sit right after
        # `client_secret`) to any of these when calling positionally.
        *,
        certificate_auth: bool = False,
        certificate_content: str = None,
        certificate_path: str = None,
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
                certificate_auth,
                tenant_id,
                client_id,
                client_secret,
                certificate_content,
                certificate_path,
            )
            region_config = AzureProvider.setup_region_config(region)

            # Get the dict from the static credentials
            azure_credentials = None
            if (
                tenant_id
                and client_id
                and (client_secret or certificate_content or certificate_path)
            ):
                azure_credentials = AzureProvider.validate_static_credentials(
                    tenant_id=tenant_id,
                    client_id=client_id,
                    client_secret=client_secret,
                    certificate_content=certificate_content,
                    certificate_path=certificate_path,
                    region_config=region_config,
                )

            # Set up the Azure session
            credentials = AzureProvider.setup_session(
                az_cli_auth,
                sp_env_auth,
                browser_auth,
                managed_identity_auth,
                certificate_auth,
                certificate_path,
                tenant_id,
                azure_credentials,
                region_config,
            )
            # Create a SubscriptionClient
            subscription_client = SubscriptionClient(
                credentials,
                base_url=region_config.base_url,
                credential_scopes=region_config.credential_scopes,
            )

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

    @staticmethod
    def check_certificate_creds_env_vars(check_certificate_content: bool):
        """
        Checks the presence of required environment variables for certificate-based
        service principal authentication against Azure.

        This method checks for the presence of the following environment variables:
        - AZURE_CLIENT_ID: Azure client ID
        - AZURE_TENANT_ID: Azure tenant ID
        - AZURE_CERTIFICATE_CONTENT: base64-encoded certificate content (only
          required when a certificate file path is not provided)

        Raises:
            AzureEnvironmentVariableError: If any required environment variable
                is missing.
        """
        logger.info("Azure provider: checking certificate environment variables ...")
        env_vars = ["AZURE_CLIENT_ID", "AZURE_TENANT_ID"]
        if check_certificate_content:
            env_vars.append("AZURE_CERTIFICATE_CONTENT")
        for env_var in env_vars:
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
        certificate_auth,
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
        if sp_env_auth or browser_auth or az_cli_auth or certificate_auth or client_id:

            async def get_azure_identity():
                # Trying to recover tenant domain info
                try:
                    logger.info(
                        "Trying to retrieve tenant domain from AAD to populate identity structure ..."
                    )
                    client = GraphServiceClient(credentials=credentials)

                    domain_result = await client.domains.get()
                    for domain in getattr(domain_result, "value", []):
                        if getattr(domain, "is_default"):
                            identity.tenant_domain = domain.id
                            break

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
                if isinstance(credentials, CertificateCredential):
                    # Prefer the explicit constructor param over the ambient
                    # env var: with static credentials the caller has
                    # unambiguously said "this is the client id" and using
                    # the env var could silently substitute another
                    # principal's id if the shell happens to have
                    # `AZURE_CLIENT_ID` set. Fall back to the env var only
                    # for the env-only cert-auth path where `client_id` is
                    # `None`.
                    identity.identity_id = client_id or getenv("AZURE_CLIENT_ID")
                    identity.identity_type = "Service Principal with Certificate"
                    identity.certificate_thumbprint = (
                        _get_certificate_thumbprint(credentials)
                        or "Unknown certificate thumbprint"
                    )
                elif sp_env_auth or client_id:
                    # The id of the sp can be retrieved from environment variables
                    identity.identity_id = getenv("AZURE_CLIENT_ID", default=client_id)
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

            asyncio.run(get_azure_identity())

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
                # TODO: get tags or labels
                # TODO: fill with AzureSubscription
                subscription_pairs = [
                    (subscription.display_name, subscription.subscription_id)
                    for subscription in subscriptions_client.subscriptions.list()
                ]
            else:
                logger.info("Scanning the subscriptions passed as argument ...")
                subscription_pairs = [
                    (
                        subscriptions_client.subscriptions.get(
                            subscription_id=id
                        ).display_name,
                        id,
                    )
                    for id in subscription_ids
                ]

            # Key the subscriptions dict by subscription ID (which is
            # guaranteed unique) and store the display name as the value.
            # This avoids collisions when multiple subscriptions share
            # the same display name.
            for display_name, subscription_id in subscription_pairs:
                identity.subscriptions[subscription_id] = display_name

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
            has subscription IDs as keys and lists of location names as values.

        Examples:
            >>> provider = AzureProvider(...)
            >>> provider.get_locations()
            {
                'sub-id-1': ['eastus', 'eastus2', 'westus', 'westus2'],
                'sub-id-2': ['eastus', 'eastus2', 'westus', 'westus2']
            }
        """
        credentials = self.session
        subscription_client = SubscriptionClient(
            credentials,
            base_url=self.region_config.base_url,
            credential_scopes=self.region_config.credential_scopes,
        )
        locations = {}

        for subscription_id, display_name in self._identity.subscriptions.items():
            locations[subscription_id] = []

            # List locations for each subscription
            for location in subscription_client.subscriptions.list_locations(
                subscription_id
            ):
                locations[subscription_id].append(location.name)

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

    def validate_resource_groups(self, resource_groups: list) -> dict[str, list[str]]:
        """Validate requested resource groups across Azure subscriptions.

        Args:
            resource_groups: Resource group names requested for scanning.

        Returns:
            A mapping of subscription IDs to the matching resource group names.

        The matching is case-insensitive and resolved independently for each
        subscription. If a subscription's resource groups cannot be queried, a
        warning is logged and that subscription keeps an empty resource group
        list so the remaining subscriptions can still be validated.
        """
        resource_groups = [r.strip() for r in resource_groups if r and r.strip()]
        if not resource_groups:
            return {}

        rg_map = {
            subscription_id: [] for subscription_id in self._identity.subscriptions
        }
        credentials = self.session

        for subscription_id, display_name in self._identity.subscriptions.items():
            try:
                rg_client = ResourceManagementClient(
                    credentials,
                    subscription_id,
                    base_url=self._region_config.base_url,
                    credential_scopes=self._region_config.credential_scopes,
                )
                existing_rgs = {
                    rg.name.lower(): rg.name for rg in rg_client.resource_groups.list()
                }
            except Exception as error:
                logger.warning(
                    f"Could not list resource groups for subscription '{display_name}' "
                    f"({subscription_id}): {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}. "
                    "Skipping resource group filtering for this subscription."
                )
                continue

            for rg in resource_groups:
                real_name = existing_rgs.get(rg.lower())
                if real_name:
                    rg_map[subscription_id].append(real_name)

        for rg in resource_groups:
            if not any(rg.lower() == r.lower() for rgs in rg_map.values() for r in rgs):
                logger.warning(
                    f"Resource group '{rg}' was not found in any subscription. "
                    "Please check the resource group name and try again."
                )

        if not any(rgs for rgs in rg_map.values()):
            logger.warning(
                f"None of the provided resource groups {resource_groups} were found "
                "in any subscription. Please check the resource group names and try again."
            )

        return rg_map

    @staticmethod
    def validate_static_credentials(
        tenant_id: str = None,
        client_id: str = None,
        client_secret: str = None,
        certificate_content: str = None,
        certificate_path: str = None,
        region_config: AzureRegionConfig = None,
    ) -> dict:
        """
        Validates the static credentials for the Azure provider.

        Args:
            tenant_id (str): The Azure Active Directory tenant ID.
            client_id (str): The Azure client ID.
            client_secret (str): The Azure client secret.
            certificate_content (str): The base64-encoded Azure certificate content.
            certificate_path (str): The path to the Azure certificate file.
            region_config (AzureRegionConfig): The region configuration used to
                build the per-cloud login endpoint and Graph scope. Defaults to
                the public-cloud configuration when not provided.

        Raises:
            AzureNotValidTenantIdError: If the provided Azure Tenant ID is not valid.
            AzureNotValidClientIdError: If the provided Azure Client ID is not valid.
            AzureNotValidClientSecretError: If the provided Azure Client Secret is not valid.
            AzureNotValidCertificateContentError: If the provided base64 certificate content is not valid.
            AzureNotValidCertificatePathError: If the provided certificate path cannot be read or does not contain a valid certificate/private-key bundle.
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

        if not client_secret and not certificate_content and not certificate_path:
            raise AzureNotValidClientSecretError(
                file=os.path.basename(__file__),
                message="You must provide a client secret, certificate content or certificate path. Please check your credentials and try again.",
            )

        # Validate the Client Secret only when using the client-secret path.
        # For certificate auth this check must be skipped so the None value
        # does not trip the regex.
        if client_secret and not re.match("^[a-zA-Z0-9._~-]+$", client_secret):
            raise AzureNotValidClientSecretError(
                file=os.path.basename(__file__),
                message="The provided Azure Client Secret is not valid.",
            )

        if certificate_content:
            try:
                # Confirm the payload is valid base64 before handing it off to
                # azure-identity: `CertificateCredential` raises an opaque
                # exception several call frames deeper if this fails, which
                # makes for a bad UX in the API/UI.
                certificate_data = base64.b64decode(certificate_content, validate=True)
                validate_certificate_bundle(certificate_data)
            except Exception as e:
                logger.error(
                    f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}"
                )
                raise AzureNotValidCertificateContentError(
                    file=os.path.basename(__file__),
                    message=f"The provided certificate content is not a valid base64-encoded certificate/private-key bundle: {str(e)}",
                )

        if certificate_path:
            try:
                with open(certificate_path, "rb") as cert_file:
                    validate_certificate_bundle(cert_file.read())
            except Exception as e:
                logger.error(
                    f"{e.__class__.__name__}[{e.__traceback__.tb_lineno}]: {e}"
                )
                raise AzureNotValidCertificatePathError(
                    file=os.path.basename(__file__),
                    message=f"The provided certificate path does not contain a valid certificate/private-key bundle: {str(e)}",
                )

        if region_config is None:
            region_config = AzureProvider.setup_region_config("AzureCloud")

        try:
            AzureProvider.verify_client(
                tenant_id,
                client_id,
                client_secret,
                region_config,
                certificate_content=certificate_content,
                certificate_path=certificate_path,
            )
            return {
                "tenant_id": tenant_id,
                "client_id": client_id,
                "client_secret": client_secret,
                "certificate_content": certificate_content,
                "certificate_path": certificate_path,
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
    def verify_client(
        tenant_id,
        client_id,
        client_secret,
        region_config: AzureRegionConfig = None,
        certificate_content: str = None,
        certificate_path: str = None,
    ) -> None:
        """
        Verifies the Azure client credentials using the specified tenant ID, client ID, and either
        a client secret or a certificate.

        Args:
            tenant_id (str): The Azure Active Directory tenant ID.
            client_id (str): The Azure client ID.
            client_secret (str): The Azure client secret.
            region_config (AzureRegionConfig): The region configuration used to
                build the per-cloud login endpoint and Graph scope. Defaults to
                the public-cloud configuration when not provided.
            certificate_content (str): The base64-encoded Azure certificate content.
            certificate_path (str): The path to the Azure certificate file.

        Raises:
            AzureNotValidTenantIdError: If the provided Azure Tenant ID is not valid.
            AzureNotValidClientIdError: If the provided Azure Client ID is not valid.
            AzureNotValidClientSecretError: If the provided Azure Client Secret is not valid.
            AzureNotValidCertificateContentError: If the provided certificate content cannot obtain a token.
            AzureNotValidCertificatePathError: If the provided certificate file cannot obtain a token.

        Returns:
            None
        """
        if region_config is None:
            region_config = AzureProvider.setup_region_config("AzureCloud")

        if client_secret:
            # `authority` is None for the public cloud and a bare host (e.g.
            # `login.chinacloudapi.cn`) for sovereign clouds, mirroring the
            # `AzureAuthorityHosts` constants used by azure-identity.
            login_endpoint = region_config.authority or "login.microsoftonline.com"
            url = f"https://{login_endpoint}/{tenant_id}/oauth2/v2.0/token"
            headers = {
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "application/json",
            }
            data = {
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "scope": region_config.graph_scope,
            }
            # Hard timeout so a hung Entra ID endpoint cannot stall the
            # calling worker (this runs on request threads and Celery tasks
            # in the API path). 30s covers the p99 of the token endpoint
            # comfortably.
            response = requests.post(url, headers=headers, data=data, timeout=30).json()
            if (
                "access_token" not in response.keys()
                and "error_codes" in response.keys()
            ):
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
            return

        # Certificate-based flows: instantiate a `CertificateCredential` and
        # attempt a Graph call. If the credential itself is invalid, msal
        # raises inside the constructor. If it is valid but the app has no
        # Graph permissions, `get_token` still returns a token — the point
        # here is to prove the private key matches an active `keyCredentials`
        # entry on the app registration.
        try:
            if certificate_content:
                certificate_data = base64.b64decode(certificate_content, validate=True)
            elif certificate_path:
                with open(certificate_path, "rb") as cert_file:
                    certificate_data = cert_file.read()
            else:
                return

            credential = CertificateCredential(
                client_id=client_id,
                tenant_id=tenant_id,
                certificate_data=certificate_data,
                authority=region_config.authority,
            )
            # get_token has no native timeout parameter, so run it off-thread
            # with a hard deadline (matches the 30s on the client-secret path).
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    credential.get_token, region_config.graph_scope
                )
                try:
                    future.result(timeout=_TOKEN_ACQUISITION_TIMEOUT_SECONDS)
                except FuturesTimeoutError as error:
                    raise AzureCredentialsUnavailableError(
                        file=os.path.basename(__file__),
                        message=(
                            "Timed out waiting for Entra ID to issue a token "
                            "for the provided certificate."
                        ),
                        original_exception=error,
                    )
        except ClientAuthenticationError as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            if certificate_content:
                raise AzureNotValidCertificateContentError(
                    file=os.path.basename(__file__),
                    original_exception=error,
                    message="The provided certificate content is not valid for the specified Tenant ID and Client ID.",
                )
            raise AzureNotValidCertificatePathError(
                file=os.path.basename(__file__),
                original_exception=error,
                message="The provided certificate is not valid for the specified Tenant ID and Client ID.",
            )
        except (
            binascii.Error,
            FileNotFoundError,
            PermissionError,
            IsADirectoryError,
            OSError,
            ValueError,
        ) as error:
            # Malformed base64, unreadable path, or bytes CertificateCredential
            # cannot parse. Route to the typed certificate errors.
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
            )
            if certificate_content:
                raise AzureNotValidCertificateContentError(
                    file=os.path.basename(__file__),
                    original_exception=error,
                )
            raise AzureNotValidCertificatePathError(
                file=os.path.basename(__file__),
                original_exception=error,
            )
