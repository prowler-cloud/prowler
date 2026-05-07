from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)

VAULT_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/rg1/providers/Microsoft.RecoveryServices/vaults/test-vault"


class Test_recovery_vault_has_protected_items:
    def test_no_subscriptions(self):
        recovery_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.recovery.recovery_vault_has_protected_items.recovery_vault_has_protected_items.recovery_client",
                new=recovery_client,
            ),
        ):
            from prowler.providers.azure.services.recovery.recovery_vault_has_protected_items.recovery_vault_has_protected_items import (
                recovery_vault_has_protected_items,
            )

            recovery_client.vaults = {}

            check = recovery_vault_has_protected_items()
            result = check.execute()
            assert len(result) == 0

    def test_vault_with_protected_items(self):
        recovery_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.recovery.recovery_vault_has_protected_items.recovery_vault_has_protected_items.recovery_client",
                new=recovery_client,
            ),
        ):
            from prowler.providers.azure.services.recovery.recovery_vault_has_protected_items.recovery_vault_has_protected_items import (
                recovery_vault_has_protected_items,
            )
            from prowler.providers.azure.services.recovery.recovery_service import (
                BackupItem,
                BackupVault,
            )

            vault = BackupVault(
                id=VAULT_ID,
                name="test-vault",
                location="eastus",
                backup_protected_items={
                    "item1": BackupItem(
                        id="item1",
                        name="vm-backup",
                        workload_type=None,
                    )
                },
            )
            recovery_client.vaults = {AZURE_SUBSCRIPTION_ID: {VAULT_ID: vault}}

            check = recovery_vault_has_protected_items()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "1 protected items" in result[0].status_extended

    def test_vault_empty(self):
        recovery_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.recovery.recovery_vault_has_protected_items.recovery_vault_has_protected_items.recovery_client",
                new=recovery_client,
            ),
        ):
            from prowler.providers.azure.services.recovery.recovery_vault_has_protected_items.recovery_vault_has_protected_items import (
                recovery_vault_has_protected_items,
            )
            from prowler.providers.azure.services.recovery.recovery_service import (
                BackupVault,
            )

            vault = BackupVault(
                id=VAULT_ID,
                name="empty-vault",
                location="westeurope",
                backup_protected_items={},
            )
            recovery_client.vaults = {AZURE_SUBSCRIPTION_ID: {VAULT_ID: vault}}

            check = recovery_vault_has_protected_items()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "no protected items" in result[0].status_extended
