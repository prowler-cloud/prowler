from types import SimpleNamespace
from unittest import mock
from unittest.mock import MagicMock, patch

from prowler.providers.azure.services.recovery.recovery_service import (
    BackupVault,
    Recovery,
    RecoveryBackup,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    RESOURCE_GROUP,
    RESOURCE_GROUP_LIST,
    set_mocked_azure_provider,
)

VAULT_ID = (
    f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/rg1/"
    "providers/Microsoft.RecoveryServices/vaults/test-vault"
)
POLICY_ID = f"{VAULT_ID}/backupPolicies/ShortPolicy"


class BackupClientFake:
    def __init__(self, policies):
        self.backup_policies = mock.MagicMock()
        self.backup_policies.list.return_value = policies


class Test_Recovery_get_vaults:
    def test_get_vaults_no_resource_groups(self):
        mock_client = MagicMock()
        mock_client.vaults = MagicMock()
        mock_client.vaults.list_by_subscription_id.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.recovery.recovery_service.Recovery._get_vaults",
                return_value={},
            ),
            patch(
                "prowler.providers.azure.services.recovery.recovery_service.RecoveryBackup",
            ),
        ):
            recovery = Recovery(set_mocked_azure_provider())

        recovery.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        recovery.resource_groups = None

        result = recovery._get_vaults()

        mock_client.vaults.list_by_subscription_id.assert_called_once()
        mock_client.vaults.list_by_resource_group.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_vaults_with_resource_group(self):
        mock_vault = MagicMock()
        mock_vault.id = "vault-id-1"
        mock_vault.name = "my-vault"
        mock_vault.location = "eastus"

        mock_client = MagicMock()
        mock_client.vaults = MagicMock()
        mock_client.vaults.list_by_resource_group.return_value = [mock_vault]

        with (
            patch(
                "prowler.providers.azure.services.recovery.recovery_service.Recovery._get_vaults",
                return_value={},
            ),
            patch(
                "prowler.providers.azure.services.recovery.recovery_service.RecoveryBackup",
            ),
        ):
            recovery = Recovery(set_mocked_azure_provider())

        recovery.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        recovery.resource_groups = {AZURE_SUBSCRIPTION_ID: [RESOURCE_GROUP]}

        result = recovery._get_vaults()

        mock_client.vaults.list_by_resource_group.assert_called_once_with(
            resource_group_name=RESOURCE_GROUP
        )
        mock_client.vaults.list_by_subscription_id.assert_not_called()
        assert AZURE_SUBSCRIPTION_ID in result
        assert "vault-id-1" in result[AZURE_SUBSCRIPTION_ID]

    def test_get_vaults_empty_resource_group_for_subscription(self):
        mock_client = MagicMock()
        mock_client.vaults = MagicMock()

        with (
            patch(
                "prowler.providers.azure.services.recovery.recovery_service.Recovery._get_vaults",
                return_value={},
            ),
            patch(
                "prowler.providers.azure.services.recovery.recovery_service.RecoveryBackup",
            ),
        ):
            recovery = Recovery(set_mocked_azure_provider())

        recovery.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        recovery.resource_groups = {AZURE_SUBSCRIPTION_ID: []}

        result = recovery._get_vaults()

        mock_client.vaults.list_by_resource_group.assert_not_called()
        mock_client.vaults.list_by_subscription_id.assert_not_called()
        assert result[AZURE_SUBSCRIPTION_ID] == {}

    def test_get_vaults_with_multiple_resource_groups(self):
        mock_client = MagicMock()
        mock_client.vaults = MagicMock()
        mock_client.vaults.list_by_resource_group.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.recovery.recovery_service.Recovery._get_vaults",
                return_value={},
            ),
            patch(
                "prowler.providers.azure.services.recovery.recovery_service.RecoveryBackup",
            ),
        ):
            recovery = Recovery(set_mocked_azure_provider())

        recovery.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        recovery.resource_groups = {AZURE_SUBSCRIPTION_ID: RESOURCE_GROUP_LIST}

        result = recovery._get_vaults()

        assert mock_client.vaults.list_by_resource_group.call_count == 2
        assert AZURE_SUBSCRIPTION_ID in result

    def test_get_vaults_with_mixed_case_resource_group(self):
        mock_client = MagicMock()
        mock_client.vaults = MagicMock()
        mock_client.vaults.list_by_resource_group.return_value = []

        with (
            patch(
                "prowler.providers.azure.services.recovery.recovery_service.Recovery._get_vaults",
                return_value={},
            ),
            patch(
                "prowler.providers.azure.services.recovery.recovery_service.RecoveryBackup",
            ),
        ):
            recovery = Recovery(set_mocked_azure_provider())

        recovery.clients = {AZURE_SUBSCRIPTION_ID: mock_client}
        recovery.resource_groups = {AZURE_SUBSCRIPTION_ID: ["RG"]}

        recovery._get_vaults()

        mock_client.vaults.list_by_resource_group.assert_called_once_with(
            resource_group_name="RG"
        )


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
