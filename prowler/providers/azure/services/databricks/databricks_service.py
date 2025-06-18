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
                    workspace_managed_disk_encryption = getattr(
                        getattr(
                            getattr(workspace, "encryption", None), "entities", None
                        ),
                        "managed_disk",
                        None,
                    )

                    key_vault_properties = getattr(
                        workspace_managed_disk_encryption, "key_vault_properties", None
                    )

                    if key_vault_properties:
                        managed_disk_encryption = ManagedDiskEncryption(
                            key_name=key_vault_properties.key_name,
                            key_version=key_vault_properties.key_version,
                            key_vault_uri=key_vault_properties.key_vault_uri,
                        )
                    else:
                        managed_disk_encryption = None

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
                        managed_disk_encryption=managed_disk_encryption,
                    )
            except Exception as error:
                logger.error(
                    f"Subscription: {subscription} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                )
        return workspaces


class ManagedDiskEncryption(BaseModel):
    """
    Pydantic model representing the encryption settings for a workspace's managed disks.

    Attributes:
        key_name: The name of the key used for encryption.
        key_version: The version of the key used for encryption.
        key_vault_uri: The URI of the key vault containing the key used for encryption.
    """

    key_name: str
    key_version: str
    key_vault_uri: str


class DatabricksWorkspace(BaseModel):
    """
    Pydantic model representing an Azure Databricks workspace.

    Attributes:
        id: The unique identifier of the workspace.
        name: The name of the workspace.
        location: The Azure region where the workspace is deployed.
        custom_managed_vnet_id: The ID of the custom managed virtual network, if configured.
        managed_disk_encryption: The encryption settings for the workspace's managed disks.
    """

    id: str
    name: str
    location: str
    custom_managed_vnet_id: Optional[str] = None
    managed_disk_encryption: Optional[ManagedDiskEncryption] = None
