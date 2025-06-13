from typing import Optional

from azure.mgmt.databricks import AzureDatabricksManagementClient
from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


class Databricks(AzureService):
    """
    Service class for interacting with Azure Databricks workspaces.

    This class initializes the Azure Databricks Management Client for each subscription
    and retrieves all Databricks workspaces within those subscriptions.
    """

    def __init__(self, provider: AzureProvider):
        """
        Initialize the Databricks service with the given Azure provider.

        Args:
            provider: The Azure provider instance containing credentials and configuration.
        """
        super().__init__(AzureDatabricksManagementClient, provider)
        self.workspaces = self._get_workspaces()

    def _get_workspaces(self) -> dict:
        """
        Retrieve all Databricks workspaces for each subscription.

        Returns:
            A dictionary mapping subscription IDs to their Databricks workspaces.
        """
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


class DatabricksWorkspace(BaseModel):
    """
    Pydantic model representing an Azure Databricks workspace.

    Attributes:
        id: The unique identifier of the workspace.
        name: The name of the workspace.
        location: The Azure region where the workspace is deployed.
        custom_managed_vnet_id: The ID of the custom managed virtual network, if configured.
    """

    id: str
    name: str
    location: str
    custom_managed_vnet_id: Optional[str]
