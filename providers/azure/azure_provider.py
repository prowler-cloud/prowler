import sys
from os import getenv

from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient
from msgraph.core import GraphClient

from lib.logger import logger
from providers.azure.lib.audit_info.audit_info import azure_audit_info
from providers.azure.lib.audit_info.models import Azure_Audit_Info, Azure_Identity_Info


class Azure_Provider:
    def __init__(self):
        logger.info("Instantiating Azure Provider ...")
        self.credentials = DefaultAzureCredential()

    def get_credentials(self):
        return self.credentials


def check_credential_env_vars() -> Azure_Identity_Info:
    for env_var in ["AZURE_CLIENT_ID", "AZURE_TENANT_ID", "AZURE_CLIENT_SECRET"]:
        if not getenv(env_var):
            logger.critical(
                f"Azure provider: Missing environment variable {env_var} needed to autenticate against Azure"
            )
            sys.exit()

    azure_identity = Azure_Identity_Info(
        app_id=getenv("AZURE_CLIENT_ID"), tenant_id=getenv("AZURE_TENANT_ID")
    )

    return azure_identity


def validate_credentials(
    azure_identity: Azure_Identity_Info, client: GraphClient
) -> Azure_Identity_Info:

    try:
        logger.info("Azure provider: validating service principal credentials ...")
        result = client.get("/servicePrincipals/").json()
        if "value" in result:
            for sp in result["value"]:
                if sp["appId"] == azure_identity.app_id:
                    azure_identity.id = sp["id"]
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit()
    else:
        return azure_identity


def azure_provider_set_session(subscription_ids: list) -> Azure_Audit_Info:
    logger.info("Setting Azure session ...")
    azure_identity = check_credential_env_vars()
    azure_audit_info.credentials = Azure_Provider().get_credentials()
    client = GraphClient(credential=azure_audit_info.credentials)
    azure_audit_info.identity = validate_credentials(azure_identity, client)
    try:

        domain_result = client.get("/domains").json()
        if "value" in domain_result:
            if "id" in domain_result["value"][0]:
                azure_audit_info.audited_account = domain_result["value"][0]["id"]
        subscriptions_client = SubscriptionClient(
            credential=azure_audit_info.credentials
        )
        if not subscription_ids:
            logger.info("Scanning all the Azure subscriptions...")
            for subscription in subscriptions_client.subscriptions.list():

                azure_audit_info.subscriptions.update(
                    {subscription.display_name: subscription.subscription_id}
                )
        else:
            logger.info("Scanning the subscriptions passed as argument ...")
            for id in subscription_ids:
                subscription = subscriptions_client.subscriptions.get(
                    subscription_id=id
                )
                azure_audit_info.subscriptions.update({subscription.display_name: id})
    except Exception as error:
        logger.critical(
            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}] -- {error}"
        )
        sys.exit()
    else:
        return azure_audit_info
