from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)

VAULT_ID = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/rg1/providers/Microsoft.RecoveryServices/vaults/test-vault"
POLICY_ID = f"{VAULT_ID}/backupPolicies/DefaultPolicy"


class Test_recovery_vault_backup_policy_retention_adequate:
    def test_no_subscriptions(self):
        recovery_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.recovery.recovery_vault_backup_policy_retention_adequate.recovery_vault_backup_policy_retention_adequate.recovery_client",
                new=recovery_client,
            ),
        ):
            from prowler.providers.azure.services.recovery.recovery_vault_backup_policy_retention_adequate.recovery_vault_backup_policy_retention_adequate import (
                recovery_vault_backup_policy_retention_adequate,
            )

            recovery_client.vaults = {}

            check = recovery_vault_backup_policy_retention_adequate()
            result = check.execute()
            assert len(result) == 0

    def test_vault_no_policies(self):
        recovery_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.recovery.recovery_vault_backup_policy_retention_adequate.recovery_vault_backup_policy_retention_adequate.recovery_client",
                new=recovery_client,
            ),
        ):
            from prowler.providers.azure.services.recovery.recovery_vault_backup_policy_retention_adequate.recovery_vault_backup_policy_retention_adequate import (
                recovery_vault_backup_policy_retention_adequate,
            )
            from prowler.providers.azure.services.recovery.recovery_service import (
                BackupVault,
            )

            vault = BackupVault(
                id=VAULT_ID,
                name="test-vault",
                location="eastus",
                backup_policies={},
            )
            recovery_client.vaults = {AZURE_SUBSCRIPTION_ID: {VAULT_ID: vault}}

            check = recovery_vault_backup_policy_retention_adequate()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "has no backup policies configured" in result[0].status_extended

    def test_policy_adequate_retention(self):
        recovery_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.recovery.recovery_vault_backup_policy_retention_adequate.recovery_vault_backup_policy_retention_adequate.recovery_client",
                new=recovery_client,
            ),
        ):
            from prowler.providers.azure.services.recovery.recovery_vault_backup_policy_retention_adequate.recovery_vault_backup_policy_retention_adequate import (
                recovery_vault_backup_policy_retention_adequate,
            )
            from prowler.providers.azure.services.recovery.recovery_service import (
                BackupPolicy,
                BackupVault,
            )

            vault = BackupVault(
                id=VAULT_ID,
                name="test-vault",
                location="eastus",
                backup_policies={
                    POLICY_ID: BackupPolicy(
                        id=POLICY_ID,
                        name="DefaultPolicy",
                        retention_days=90,
                    )
                },
            )
            recovery_client.vaults = {AZURE_SUBSCRIPTION_ID: {VAULT_ID: vault}}

            check = recovery_vault_backup_policy_retention_adequate()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "90-day" in result[0].status_extended

    def test_policy_insufficient_retention(self):
        recovery_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.recovery.recovery_vault_backup_policy_retention_adequate.recovery_vault_backup_policy_retention_adequate.recovery_client",
                new=recovery_client,
            ),
        ):
            from prowler.providers.azure.services.recovery.recovery_vault_backup_policy_retention_adequate.recovery_vault_backup_policy_retention_adequate import (
                recovery_vault_backup_policy_retention_adequate,
            )
            from prowler.providers.azure.services.recovery.recovery_service import (
                BackupPolicy,
                BackupVault,
            )

            vault = BackupVault(
                id=VAULT_ID,
                name="test-vault",
                location="eastus",
                backup_policies={
                    POLICY_ID: BackupPolicy(
                        id=POLICY_ID,
                        name="ShortPolicy",
                        retention_days=7,
                    )
                },
            )
            recovery_client.vaults = {AZURE_SUBSCRIPTION_ID: {VAULT_ID: vault}}

            check = recovery_vault_backup_policy_retention_adequate()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "7-day" in result[0].status_extended
            assert "minimum: 30" in result[0].status_extended

    def test_policy_no_retention_configured(self):
        recovery_client = mock.MagicMock

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.recovery.recovery_vault_backup_policy_retention_adequate.recovery_vault_backup_policy_retention_adequate.recovery_client",
                new=recovery_client,
            ),
        ):
            from prowler.providers.azure.services.recovery.recovery_vault_backup_policy_retention_adequate.recovery_vault_backup_policy_retention_adequate import (
                recovery_vault_backup_policy_retention_adequate,
            )
            from prowler.providers.azure.services.recovery.recovery_service import (
                BackupPolicy,
                BackupVault,
            )

            vault = BackupVault(
                id=VAULT_ID,
                name="test-vault",
                location="eastus",
                backup_policies={
                    POLICY_ID: BackupPolicy(
                        id=POLICY_ID,
                        name="NoRetentionPolicy",
                        retention_days=None,
                    )
                },
            )
            recovery_client.vaults = {AZURE_SUBSCRIPTION_ID: {VAULT_ID: vault}}

            check = recovery_vault_backup_policy_retention_adequate()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "no daily retention" in result[0].status_extended
