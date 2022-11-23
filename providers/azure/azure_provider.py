import sys
from os import getenv

from azure.identity import DefaultAzureCredential
from azure.mgmt.subscription import SubscriptionClient
from msgraph.core import GraphClient

from lib.logger import logger
from providers.azure.lib.audit_info.audit_info import azure_audit_info
from providers.azure.lib.audit_info.models import (
    Azure_Identity_Info,
    Azure_Subscription,
)


class Azure_Provider:
    def __init__(self):
        logger.info("Instantiating azure provider ...")
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
        logger.critical(f"{error.__class__.__name__} -- {error}")
        sys.exit()
    else:
        return azure_identity


def azure_provider_set_session():
    logger.info("Setting azure session ...")
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
        for subscription in subscriptions_client.subscriptions.list():
            logger.info(subscription.__dict__)
            azure_audit_info.subscriptions.append(
                Azure_Subscription(
                    id=subscription.subscription_id,
                    display_name=subscription.display_name,
                )
            )
    except Exception as error:
        logger.critical(f"{error.__class__.__name__} -- {error}")
        sys.exit()
    else:
        return azure_audit_info
