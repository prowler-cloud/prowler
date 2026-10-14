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
                    account.monitor_diagnostic_settings = self._get_diagnostic_settings(
                        subscription, account.id
                    )
                    account.deployments = self._get_deployments(
                        subscription, client, account
                    )
                    account.rai_policies = self._get_rai_policies(
                        subscription, client, account
                    )
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
        local (key) authentication on, Microsoft-managed encryption, no
        managed identity, unrestricted outbound access, and a network ACL
        default action of `Allow`.

        Args:
            sdk_account: `azure.mgmt.cognitiveservices.models.Account`.

        Returns:
            The mapped `Account`.
        """
        properties = sdk_account.properties
        encryption = getattr(properties, "encryption", None)
        key_vault_properties = getattr(encryption, "key_vault_properties", None)
        default_action = getattr(
            getattr(properties, "network_acls", None), "default_action", None
        )
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
            private_endpoint_connection_statuses=AIServices._private_endpoint_statuses(
                properties
            ),
            identity_type=getattr(getattr(sdk_account, "identity", None), "type", None),
            restrict_outbound_network_access=bool(
                getattr(properties, "restrict_outbound_network_access", False)
            ),
            # NetworkRuleAction is a str enum; keep the plain value.
            network_acls_default_action=(
                getattr(default_action, "value", default_action) or "Allow"
            ),
        )

    @staticmethod
    def _get_deployments(
        subscription: str, client, account: "Account"
    ) -> Optional[list["Deployment"]]:
        """Get the model deployments of one account.

        Args:
            subscription: Subscription ID that holds the account.
            client: `CognitiveServicesManagementClient` for the subscription.
            account: The account whose deployments are listed.

        Returns:
            The account's deployments, or `None` when they cannot be read.
        """
        try:
            deployments = []
            for sdk_deployment in client.deployments.list(
                resource_group_name=_resource_group(account.id),
                account_name=account.name,
            ):
                properties = getattr(sdk_deployment, "properties", None)
                capabilities = getattr(properties, "capabilities", None)
                deployments.append(
                    Deployment(
                        id=sdk_deployment.id,
                        name=sdk_deployment.name,
                        location=account.location,
                        model_name=getattr(
                            getattr(properties, "model", None), "name", None
                        )
                        or "",
                        # An empty name means the deployment uses the account
                        # default policy, which ARM does not identify.
                        rai_policy_name=getattr(properties, "rai_policy_name", None)
                        or "",
                        capabilities=(
                            capabilities if isinstance(capabilities, dict) else {}
                        ),
                    )
                )
            return deployments
        except Exception as error:
            logger.error(
                f"Subscription ID: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    @staticmethod
    def _get_rai_policies(
        subscription: str, client, account: "Account"
    ) -> Optional[dict[str, "RaiPolicy"]]:
        """Get the content filter (RAI) policies of one account.

        Uses `list` because `get` returns 404 for system-managed policies such
        as `Microsoft.Default`.

        Args:
            subscription: Subscription ID that holds the account.
            client: `CognitiveServicesManagementClient` for the subscription.
            account: The account whose policies are listed.

        Returns:
            Policies keyed by name, or `None` when they cannot be read.
        """
        try:
            policies = {}
            for sdk_policy in client.rai_policies.list(
                resource_group_name=_resource_group(account.id),
                account_name=account.name,
            ):
                content_filters = []
                for sdk_filter in (
                    getattr(
                        getattr(sdk_policy, "properties", None),
                        "content_filters",
                        None,
                    )
                    or []
                ):
                    source = getattr(sdk_filter, "source", None)
                    content_filters.append(
                        ContentFilter(
                            name=getattr(sdk_filter, "name", None) or "",
                            # RaiPolicyContentSource is a str enum; keep the plain value.
                            source=getattr(source, "value", source) or "",
                            enabled=bool(getattr(sdk_filter, "enabled", False)),
                            blocking=bool(getattr(sdk_filter, "blocking", False)),
                        )
                    )
                policies[sdk_policy.name] = RaiPolicy(
                    name=sdk_policy.name, content_filters=content_filters
                )
            return policies
        except Exception as error:
            logger.error(
                f"Subscription ID: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None

    @staticmethod
    def _private_endpoint_statuses(properties) -> list[str]:
        """Get the connection status of each private endpoint on an account.

        Args:
            properties: `azure.mgmt.cognitiveservices.models.AccountProperties`,
                or `None`.

        Returns:
            One status (`Approved`, `Pending`, `Rejected`) per connection that
            reports one.
        """
        statuses = []
        for connection in (
            getattr(properties, "private_endpoint_connections", None) or []
        ):
            state = getattr(
                getattr(connection, "properties", None),
                "private_link_service_connection_state",
                None,
            )
            status = getattr(state, "status", None)
            if status:
                statuses.append(status)
        return statuses

    @staticmethod
    def _get_diagnostic_settings(subscription: str, account_id: str) -> Optional[list]:
        """Get the Azure Monitor diagnostic settings of one account.

        Args:
            subscription: Subscription ID that holds the account.
            account_id: Account resource ID.

        Returns:
            The account's `DiagnosticSetting` items, or `None` when they cannot
            be read.
        """
        try:
            # Imported here because the Monitor client is built from the global
            # provider at import time; importing this module must not need it.
            from prowler.providers.azure.services.monitor.monitor_client import (
                monitor_client,
            )

            return monitor_client.diagnostic_settings_with_uri(
                subscription,
                account_id,
                monitor_client.clients[subscription],
                raise_errors=True,
            )
        except Exception as error:
            logger.error(
                f"Subscription ID: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            return None


def _resource_group(resource_id: str) -> str:
    """Get the resource group name from an ARM resource ID."""
    return resource_id.split("/")[4]


class ContentFilter(BaseModel):
    """One content filter of a content filter (RAI) policy."""

    name: str
    source: str
    enabled: bool
    blocking: bool


class RaiPolicy(BaseModel):
    """Content filter (RAI) policy of an AI services account."""

    name: str
    content_filters: list[ContentFilter] = []


class Deployment(BaseModel):
    """Model deployment of an AI services account."""

    id: str
    name: str
    location: str
    model_name: str = ""
    rai_policy_name: str = ""
    # Model capabilities, for example {"chatCompletion": "true"}.
    capabilities: dict[str, str] = {}


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
    private_endpoint_connection_statuses: list[str] = []
    identity_type: Optional[str] = None
    restrict_outbound_network_access: bool = False
    network_acls_default_action: str = "Allow"
    # None when the list call fails, so checks can report MANUAL.
    deployments: Optional[list[Deployment]] = None
    rai_policies: Optional[dict[str, RaiPolicy]] = None
    # Monitor DiagnosticSetting dataclasses. Left untyped: Pydantic would
    # re-validate them and reject log entries whose category is None.
    monitor_diagnostic_settings: Optional[list] = None
