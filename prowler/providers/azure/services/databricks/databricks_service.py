from dataclasses import dataclass
from typing import Optional

from azure.mgmt.databricks import AzureDatabricksManagementClient

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


class Databricks(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(AzureDatabricksManagementClient, provider)
        self.workspaces = self._get_workspaces()

    def _get_workspaces(self) -> dict:
        logger.info("Databricks - Getting workspaces...")
        workspaces = {}
        for subscription, client in self.clients.items():
            try:
                workspaces[subscription] = {}

                for workspace in client.workspaces.list_by_subscription():
                    workspace_parameters = getattr(workspace, "parameters", None)

                    workspaces[subscription][workspace.id] = DatabricksWorkspace(
                        id=workspace.id,
                        name=workspace.name,
                        location=workspace.location,
                        custom_managed_vnet_id=(
                            getattr(
                                workspace_parameters, "custom_virtual_network_id", None
                            ).value
                            if getattr(
                                workspace_parameters, "custom_virtual_network_id", None
                            )
                            else None
                        ),
                    )
            except Exception as error:
                logger.error(
                    f"Subscription: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return workspaces


@dataclass
class DatabricksWorkspace:
    id: str
    name: str
    location: str
    custom_managed_vnet_id: Optional[str]
