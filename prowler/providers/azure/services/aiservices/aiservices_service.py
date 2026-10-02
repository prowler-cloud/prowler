from typing import Optional

from azure.mgmt.cognitiveservices import CognitiveServicesManagementClient
from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService

MICROSOFT_MANAGED_KEY_SOURCE = "Microsoft.CognitiveServices"


class AIServices(AzureService):
    """Azure AI services (Microsoft.CognitiveServices/accounts).

    Covers every account kind, including Azure OpenAI (`OpenAI`) and
    Azure AI Foundry (`AIServices`).
    """

    def __init__(self, provider: AzureProvider):
        super().__init__(CognitiveServicesManagementClient, provider)
        self.accounts = self._get_accounts()

    def _get_accounts(self) -> dict[str, dict[str, "Account"]]:
        """Get Azure AI services accounts for every audited subscription.

        Returns:
            Accounts keyed by subscription ID, then by account resource ID.
        """
        logger.info("AIServices - Getting accounts...")
        accounts = {}
        for subscription, client in self.clients.items():
            accounts[subscription] = {}
            try:
                sdk_accounts = self.list_with_rg_scope(
                    subscription,
                    client.accounts.list,
                    client.accounts.list_by_resource_group,
                )
            except Exception as error:
                logger.error(
                    f"Subscription ID: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
                continue
            for sdk_account in sdk_accounts:
                try:
                    account = self._to_account(sdk_account)
                    accounts[subscription][account.id] = account
                except Exception as error:
                    logger.error(
                        f"Subscription ID: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        return accounts

    @staticmethod
    def _to_account(sdk_account) -> "Account":
        """Map an SDK account to the Prowler model.

        Unset properties follow Azure defaults: public network access on,
        local (key) authentication on, and Microsoft-managed encryption.

        Args:
            sdk_account: `azure.mgmt.cognitiveservices.models.Account`.

        Returns:
            The mapped `Account`.
        """
        properties = sdk_account.properties
        encryption = getattr(properties, "encryption", None)
        key_vault_properties = getattr(encryption, "key_vault_properties", None)
        return Account(
            id=sdk_account.id,
            name=sdk_account.name,
            location=sdk_account.location,
            kind=sdk_account.kind or "",
            public_network_access=(
                getattr(properties, "public_network_access", None) != "Disabled"
            ),
            disable_local_auth=bool(getattr(properties, "disable_local_auth", False)),
            encryption_key_source=(
                getattr(encryption, "key_source", None) or MICROSOFT_MANAGED_KEY_SOURCE
            ),
            encryption_key_name=getattr(key_vault_properties, "key_name", None),
        )


class Account(BaseModel):
    """Azure AI services account."""

    id: str
    name: str
    location: str
    kind: str
    public_network_access: bool
    disable_local_auth: bool
    encryption_key_source: str
    encryption_key_name: Optional[str] = None
