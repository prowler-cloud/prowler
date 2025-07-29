from typing import Optional

from azure.mgmt.recoveryservices import RecoveryServicesClient
from azure.mgmt.recoveryservicesbackup import RecoveryServicesBackupClient
from azure.mgmt.recoveryservicesbackup.activestamp.models import DataSourceType
from pydantic import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.azure.azure_provider import AzureProvider
from prowler.providers.azure.lib.service.service import AzureService


class BackupItem(BaseModel):
    """Minimal BackupItem: only essential identifying and descriptive fields."""

    id: str
    name: str
    workload_type: Optional[DataSourceType]


class BackupVault(BaseModel):
    """Minimal BackupVault: only essential identifying fields and its backup items."""

    id: str
    name: str
    location: str
    backup_protected_items: dict[str, BackupItem] = Field(default_factory=dict)


class Recovery(AzureService):
    def __init__(self, provider: AzureProvider):
        super().__init__(RecoveryServicesClient, provider)
        self.vaults: dict[str, dict[str, BackupVault]] = self._get_vaults()
        RecoveryBackup(provider, self.vaults)

    def _get_vaults(self) -> dict[str, dict[str, BackupVault]]:
        """
        Retrieve all Recovery Services vaults for each subscription.

        Returns:
            Nested dictionary of vaults by subscription.
        """
        logger.info("Recovery - Getting Recovery Services vaults...")
        vaults_dict: dict[str, dict[str, BackupVault]] = {}
        try:
            vaults_dict: dict[str, dict[str, BackupVault]] = {}
            for subscription_name, client in self.clients.items():
                vaults = client.vaults.list_by_subscription_id()
                vaults_dict[subscription_name] = {}
                for vault in vaults:
                    vault_obj = BackupVault(
                        id=vault.id,
                        name=vault.name,
                        location=vault.location,
                    )
                    vaults_dict[subscription_name][vault_obj.id] = vault_obj
        except Exception as error:
            logger.error(
                f"Subscription name: {subscription_name} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return vaults_dict


class RecoveryBackup(AzureService):
    def __init__(
        self, provider: AzureProvider, vaults: dict[str, dict[str, BackupVault]]
    ):
        super().__init__(RecoveryServicesBackupClient, provider)
        for subscription_name, vaults in vaults.items():
            for vault in vaults.values():
                vault.backup_protected_items = self._get_backup_protected_items(
                    subscription_name=subscription_name, vault=vault
                )

    def _get_backup_protected_items(
        self, subscription_name: str, vault: BackupVault
    ) -> dict[str, BackupItem]:
        """
        Retrieve all backup protected items for a given vault.
        """
        logger.info("Recovery - Getting backup protected items...")
        backup_protected_items_dict: dict[str, BackupItem] = {}
        try:
            backup_protected_items = self.clients[
                subscription_name
            ].backup_protected_items.list(
                vault_name=vault.name,
                resource_group_name=vault.id.split("/")[4],
            )
            for item in backup_protected_items:
                item_properties = getattr(item, "properties", None)
                backup_protected_items_dict[item.id] = BackupItem(
                    id=item.id,
                    name=item.name,
                    workload_type=(
                        item_properties.workload_type if item_properties else None
                    ),
                )
        except Exception as e:
            logger.error(f"Recovery - Error getting backup protected items: {e}")
        return backup_protected_items_dict
