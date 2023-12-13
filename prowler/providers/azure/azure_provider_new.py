import sys
from os import getenv
from typing import Any, Optional

from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential
from azure.mgmt.subscription import SubscriptionClient
from colorama import Fore, Style
from msgraph.core import GraphClient
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.azure.lib.regions.regions import get_regions_config
from prowler.providers.common.provider import CloudProvider


class AzureIdentityInfo(BaseModel):
    identity_id: str = ""
    identity_type: str = ""
    tenant_ids: list[str] = []
    domain: str = "Unknown tenant domain (missing AAD permissions)"
    subscriptions: dict = {}


class AzureRegionConfig(BaseModel):
    name: str = ""
    authority: str = None
    base_url: str = ""
    credential_scopes: list = []


class AzureProvider(CloudProvider):
    session: DefaultAzureCredential
    identity: AzureIdentityInfo
    audit_resources: Optional[Any]
    audit_metadata: Optional[Any]
    audit_config: dict
    region_config: AzureRegionConfig

    def __init__(self, arguments):
        logger.info("Setting Azure session ...")
        subscription_ids = arguments.subscription_ids

        logger.info("Checking if any credentials mode is set ...")
        az_cli_auth = arguments.az_cli_auth
        sp_env_auth = arguments.sp_env_auth
        browser_auth = arguments.browser_auth
        managed_entity_auth = arguments.managed_identity_auth
        tenant_id = arguments.tenant_id

        logger.info("Checking if region is different than default one")
        region = arguments.azure_region
        self.validate_arguments(
            az_cli_auth, sp_env_auth, browser_auth, managed_entity_auth, tenant_id
        )
        self.region_config = self.setup_region_config(region)
        self.session = self.setup_session(
            az_cli_auth, sp_env_auth, browser_auth, managed_entity_auth, tenant_id
        )
        self.identity = self.setup_identity(
            az_cli_auth,
            sp_env_auth,
            browser_auth,
            managed_entity_auth,
            subscription_ids,
        )
        if not arguments.only_logs:
            self.print_credentials()

    def validate_arguments(
        self, az_cli_auth, sp_env_auth, browser_auth, managed_entity_auth, tenant_id
    ):
        if (
            not az_cli_auth
            and not sp_env_auth
            and not browser_auth
            and not managed_entity_auth
        ):
            raise Exception(
                "Azure provider requires at least one authentication method set: [--az-cli-auth | --sp-env-auth | --browser-auth | --managed-identity-auth]"
            )
        if (not browser_auth and tenant_id) or (browser_auth and not tenant_id):
            raise Exception(
                "Azure Tenant ID (--tenant-id) is required only for browser authentication mode"
            )

    def setup_region_config(self, region):
        config = get_regions_config(region)
        return AzureRegionConfig(
            name=region,
            authority=config["authority"],
            base_url=config["base_url"],
            credential_scopes=config["credential_scopes"],
        )

    def print_credentials(self):
        printed_subscriptions = []
        for key, value in self.identity.subscriptions.items():
            intermediate = key + " : " + value
            printed_subscriptions.append(intermediate)
        report = f"""
This report is being generated using the identity below:

Azure Tenant IDs: {Fore.YELLOW}[{" ".join(self.identity.tenant_ids)}]{Style.RESET_ALL} Azure Tenant Domain: {Fore.YELLOW}[{self.identity.domain}]{Style.RESET_ALL} Azure Region: {Fore.YELLOW}[{self.region_config.name}]{Style.RESET_ALL}
Azure Subscriptions: {Fore.YELLOW}{printed_subscriptions}{Style.RESET_ALL}
Azure Identity Type: {Fore.YELLOW}[{self.identity.identity_type}]{Style.RESET_ALL} Azure Identity ID: {Fore.YELLOW}[{self.identity.identity_id}]{Style.RESET_ALL}
"""
        print(report)

    def setup_session(
        self, az_cli_auth, sp_env_auth, browser_auth, managed_entity_auth, tenant_id
    ):
        # Browser auth creds cannot be set with DefaultAzureCredentials()
        if not browser_auth:
            if sp_env_auth:
                self.__check_service_principal_creds_env_vars__()
            try:
                # Since the input vars come as True when it is wanted to be used, we need to inverse it since
                # DefaultAzureCredential sets the auth method excluding the others
                credentials = DefaultAzureCredential(
                    exclude_environment_credential=not sp_env_auth,
                    exclude_cli_credential=not az_cli_auth,
                    exclude_managed_identity_credential=not managed_entity_auth,
                    # Azure Auth using Visual Studio is not supported
                    exclude_visual_studio_code_credential=True,
                    # Azure Auth using Shared Token Cache is not supported
                    exclude_shared_token_cache_credential=True,
                    # Azure Auth using PowerShell is not supported
                    exclude_powershell_credential=True,
                    # set Authority of a Microsoft Entra endpoint
                    authority=self.region_config.authority,
                )
            except Exception as error:
                logger.critical("Failed to retrieve azure credentials")
                logger.critical(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                )
                sys.exit(1)
        else:
            try:
                credentials = InteractiveBrowserCredential(tenant_id=tenant_id)
            except Exception as error:
                logger.critical("Failed to retrieve azure credentials")
                logger.critical(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                )
                sys.exit(1)

        return credentials

    def __check_service_principal_creds_env_vars__(self):
        logger.info(
            "Azure provider: checking service principal environment variables  ..."
        )
        for env_var in ["AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET"]:
            if not getenv(env_var):
                logger.critical(
                    f"Azure provider: Missing environment variable {env_var} needed to autenticate against Azure"
                )
                sys.exit(1)

    def setup_identity(
        self,
        az_cli_auth,
        sp_env_auth,
        browser_auth,
        managed_entity_auth,
        subscription_ids,
    ):
        credentials = self.session
        identity = AzureIdentityInfo()

        # If credentials comes from service principal or browser, if the required permissions are assigned
        # the identity can access AAD and retrieve the tenant domain name.
        # With cli also should be possible but right now it does not work, azure python package issue is coming
        # At the time of writting this with az cli creds is not working, despite that is included
        if sp_env_auth or browser_auth or az_cli_auth:
            # Trying to recover tenant domain info
            try:
                logger.info(
                    "Trying to retrieve tenant domain from AAD to populate identity structure ..."
                )
                client = GraphClient(credential=credentials)
                domain_result = client.get("/domains").json()
                if "value" in domain_result:
                    if "id" in domain_result["value"][0]:
                        identity.domain = domain_result["value"][0]["id"]
            except Exception as error:
                logger.error(
                    "Provided identity does not have permissions to access AAD to retrieve tenant domain"
                )
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
                    client = GraphClient(credential=credentials)
                    user_name = client.get("/me").json()
                    if "userPrincipalName" in user_name:
                        identity.identity_id = user_name

                except Exception as error:
                    logger.error(
                        "Provided identity does not have permissions to access AAD to retrieve user's metadata"
                    )
                    logger.error(
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                    )
        # Managed identities only can be assigned resource, resource group and subscription scope permissions
        elif managed_entity_auth:
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
                sys.exit(1)

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
            sys.exit(1)

        return identity
