import sys
from os import getenv

from azure.identity import DefaultAzureCredential, InteractiveBrowserCredential
from azure.mgmt.subscription import SubscriptionClient
from msgraph.core import GraphClient

from prowler.lib.logger import logger
from prowler.providers.azure.lib.audit_info.models import Azure_Identity_Info


class Azure_Provider:
    def __init__(
        self,
        az_cli_auth: bool,
        sp_env_auth: bool,
        browser_auth: bool,
        managed_entity_auth: bool,
        subscription_ids: list,
    ):
        logger.info("Instantiating Azure Provider ...")
        self.credentials = self.__set_credentials__(
            az_cli_auth, sp_env_auth, browser_auth, managed_entity_auth
        )
        self.identity = self.__set_identity_info__(
            self.credentials,
            az_cli_auth,
            sp_env_auth,
            browser_auth,
            managed_entity_auth,
            subscription_ids,
        )

    def __set_credentials__(
        self, az_cli_auth, sp_env_auth, browser_auth, managed_entity_auth
    ):
        # Browser auth creds cannot be set with DefaultAzureCredentials()
        if not browser_auth:
            if sp_env_auth:
                self.__check_sp_creds_env_vars__()
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
                )
            except Exception as error:
                logger.critical("Failed to retrieve azure credentials")
                logger.critical(
                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
                )
                sys.exit()
        else:
            credentials = InteractiveBrowserCredential()

        return credentials

    def __check_sp_creds_env_vars__(self):
        logger.info(
            "Azure provider: checking service principal environment variables  ..."
        )
        for env_var in ["AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET"]:
            if not getenv(env_var):
                logger.critical(
                    f"Azure provider: Missing environment variable {env_var} needed to autenticate against Azure"
                )
                sys.exit()

    def __set_identity_info__(
        self,
        credentials,
        az_cli_auth,
        sp_env_auth,
        browser_auth,
        managed_entity_auth,
        subscription_ids,
    ):
        identity = Azure_Identity_Info()

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
                identity.identity_id = "Unknown user id (NO AAD permissions)"
                identity.identity_type = "User"
                try:
                    logger.info(
                        "Trying to retrieve user information from AAD to populate identity structure ..."
                    )
                    client = GraphClient(credential=credentials)
                    user_name = client.get("/me").json()["userPrincipalName"]
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
            subscriptions_client = SubscriptionClient(credential=credentials)
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
            sys.exit()

        return identity

    def get_credentials(self):
        return self.credentials

    def get_identity(self):
        return self.identity
