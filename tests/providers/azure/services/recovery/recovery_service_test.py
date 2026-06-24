from types import SimpleNamespace
from unittest import mock

from prowler.providers.azure.services.recovery.recovery_service import (
    BackupVault,
    RecoveryBackup,
)
from tests.providers.azure.azure_fixtures import AZURE_SUBSCRIPTION_ID

VAULT_ID = (
    f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/rg1/"
    "providers/Microsoft.RecoveryServices/vaults/test-vault"
)
POLICY_ID = f"{VAULT_ID}/backupPolicies/ShortPolicy"


class BackupClientFake:
    def __init__(self, policies):
        self.backup_policies = mock.MagicMock()
        self.backup_policies.list.return_value = policies


class Test_RecoveryBackup_Service:
    def test_get_backup_policies_lists_unprotected_vault_policies(self):
        policy = SimpleNamespace(
            id=POLICY_ID,
            name="ShortPolicy",
            properties=SimpleNamespace(
                retention_policy=SimpleNamespace(
                    daily_schedule=SimpleNamespace(
                        retention_duration=SimpleNamespace(count=7)
                    )
                )
            ),
        )
        client = BackupClientFake(policies=[policy])
        vault = BackupVault(
            id=VAULT_ID,
            name="test-vault",
            location="eastus",
            backup_protected_items={},
        )
        recovery_backup = object.__new__(RecoveryBackup)
        recovery_backup.clients = {AZURE_SUBSCRIPTION_ID: client}

        backup_policies = recovery_backup._get_backup_policies(
            subscription_id=AZURE_SUBSCRIPTION_ID,
            vault=vault,
        )

        client.backup_policies.list.assert_called_once_with(
            vault_name="test-vault",
            resource_group_name="rg1",
        )
        assert list(backup_policies) == [POLICY_ID]
        assert backup_policies[POLICY_ID].name == "ShortPolicy"
        assert backup_policies[POLICY_ID].retention_days == 7
