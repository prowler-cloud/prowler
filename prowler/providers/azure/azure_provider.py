import asyncio
import sys
from os import getenv

import requests
from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential
from azure.mgmt.subscription import SubscriptionClient
from colorama import Fore, Style
from msgraph import GraphServiceClient

from prowler.config.config import load_and_validate_config_file
from prowler.lib.logger import logger
from prowler.providers.azure.lib.regions.regions import get_regions_config
from prowler.providers.azure.models import (
    AzureIdentityInfo,
    AzureOutputOptions,
    AzureRegionConfig,
)
from prowler.providers.common.models import Audit_Metadata
from prowler.providers.common.provider import Provider


class AzureProvider(Provider):
    _type: str = "azure"
    _session: DefaultAzureCredential
    _identity: AzureIdentityInfo
    _audit_config: dict
    _region_config: AzureRegionConfig
    _locations: dict
    _output_options: AzureOutputOptions
    # TODO: enforce the mutelist for the Provider class
    # _mutelist: dict = {}
    # TODO: this is not optional, enforce for all providers
    audit_metadata: Audit_Metadata

    def __init__(self, arguments):
        logger.info("Setting Azure provider ...")
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
        self._region_config = self.setup_region_config(region)
        self._session = self.setup_session(
            az_cli_auth, sp_env_auth, browser_auth, managed_entity_auth, tenant_id
        )
        self._identity = self.setup_identity(
            az_cli_auth,
            sp_env_auth,
            browser_auth,
            managed_entity_auth,
            subscription_ids,
        )

        # TODO: should we keep this here or within the identity?
        self._locations = self.get_locations(self.session, self.region_config)

        # TODO: move this to the providers, pending for AWS, GCP, AZURE and K8s
        # Audit Config
        self._audit_config = load_and_validate_config_file(
            self._type, arguments.config_file
        )

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
    def region_config(self):
        return self._region_config

    @property
    def locations(self):
        return self._locations

    @property
    def audit_config(self):
        return self._audit_config

    @property
    def output_options(self):
        return self._output_options

    @output_options.setter
    def output_options(self, options: tuple):
        arguments, bulk_checks_metadata = options
        self._output_options = AzureOutputOptions(
            arguments, bulk_checks_metadata, self._identity
        )

    @property
    def get_output_mapping(self):
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
            "account_organization": "identity.tenant_domain",
            # TODO: pending to get the subscription tags
            # "account_tags": "organizations_metadata.account_details_tags",
            "partition": "region_config.name",
        }

    # TODO: pending to implement
    # @property
    # def mutelist(self):
    #     return self._mutelist

    # @mutelist.setter
    # def mutelist(self, mutelist_path):
    #     if mutelist_path:
    #         mutelist = parse_mutelist_file(
    #             self._session.current_session, self._identity.account, mutelist_path
    #         )
    #     else:
    #         mutelist = {}
    #     self._mutelist = mutelist

    # TODO: this should be moved to the argparse, if not we need to enforce it from the Provider
    def validate_arguments(
        self, az_cli_auth, sp_env_auth, browser_auth, managed_entity_auth, tenant_id
    ):
        if (
            not az_cli_auth
            and not sp_env_auth
            and not browser_auth
            and not managed_entity_auth
        ):
            raise SystemExit(
                "Azure provider requires at least one authentication method set: [--az-cli-auth | --sp-env-auth | --browser-auth | --managed-identity-auth]"
            )
        elif browser_auth and not tenant_id:
            raise SystemExit(
                "Azure Tenant ID (--tenant-id) is required for browser authentication mode"
            )
        # There is no need to handle that since it won't get here
        elif not browser_auth and tenant_id:
            raise SystemExit(
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
        for key, value in self._identity.subscriptions.items():
            intermediate = key + ": " + value
            printed_subscriptions.append(intermediate)
        report = f"""
This report is being generated using the identity below:

Azure Tenant ID: {Fore.YELLOW}[{self._identity.tenant_ids[0]}]{Style.RESET_ALL} Azure Tenant Domain: {Fore.YELLOW}[{self._identity.tenant_domain}]{Style.RESET_ALL} Azure Region: {Fore.YELLOW}[{self.region_config.name}]{Style.RESET_ALL}
Azure Subscriptions: {Fore.YELLOW}{printed_subscriptions}{Style.RESET_ALL}
Azure Identity Type: {Fore.YELLOW}[{self._identity.identity_type}]{Style.RESET_ALL} Azure Identity ID: {Fore.YELLOW}[{self._identity.identity_id}]{Style.RESET_ALL}
"""
        print(report)

    # TODO: setup_session or setup_credentials?
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

            asyncio.run(get_azure_identity())
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

    def get_locations(self, credentials, region_config) -> dict[str, list[str]]:
        locations = None
        if credentials and region_config:
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
