from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_vm_backup_enabled:
    def test_vm_backup_enabled_no_subscriptions(self):
        vm_client = mock.MagicMock
        recovery_client = mock.MagicMock

        vm_client.virtual_machines = {}
        recovery_client.vaults = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_backup_enabled.vm_backup_enabled.vm_client",
                new=vm_client,
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_backup_enabled.vm_backup_enabled.recovery_client",
                new=recovery_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_backup_enabled.vm_backup_enabled import (
                vm_backup_enabled,
            )

            check = vm_backup_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_no_vms(self):
        mock_vm_client = mock.MagicMock()
        mock_vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {}}
        mock_recovery_client = mock.MagicMock()
        mock_recovery_client.vaults = {AZURE_SUBSCRIPTION_ID: {}}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_backup_enabled.vm_backup_enabled.vm_client",
                new=mock_vm_client,
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_backup_enabled.vm_backup_enabled.recovery_client",
                new=mock_recovery_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_backup_enabled.vm_backup_enabled import (
                vm_backup_enabled,
            )

            check = vm_backup_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_vm_protected_by_backup(self):
        vm_id = str(uuid4())
        vm_name = "VMTest"
        vault_id = str(uuid4())
        vault_name = "vault1"
        mock_vm_client = mock.MagicMock()
        mock_recovery_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_backup_enabled.vm_backup_enabled.vm_client",
                new=mock_vm_client,
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_backup_enabled.vm_backup_enabled.recovery_client",
                new=mock_recovery_client,
            ),
        ):
            from azure.mgmt.recoveryservicesbackup.activestamp.models import (
                DataSourceType,
            )

            from prowler.providers.azure.services.recovery.recovery_service import (
                BackupItem,
                BackupVault,
            )
            from prowler.providers.azure.services.vm.vm_backup_enabled.vm_backup_enabled import (
                vm_backup_enabled,
            )
            from prowler.providers.azure.services.vm.vm_service import (
                ManagedDiskParameters,
                OSDisk,
                StorageProfile,
                VirtualMachine,
            )

            vm = VirtualMachine(
                resource_id=vm_id,
                resource_name=vm_name,
                location="eastus",
                security_profile=None,
                extensions=[],
                storage_profile=StorageProfile(
                    os_disk=OSDisk(
                        name="os_disk_name",
                        operating_system_type="Linux",
                        managed_disk=ManagedDiskParameters(id="managed_disk_id"),
                    ),
                    data_disks=[],
                ),
            )
            backup_item = BackupItem(
                id=str(uuid4()),
                name=f"someprefix;{vm_name}",
                workload_type=DataSourceType.VM,
            )
            vault = BackupVault(
                id=vault_id,
                name=vault_name,
                location="eastus",
                backup_protected_items={backup_item.id: backup_item},
            )
            mock_vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {vm_id: vm}}
            mock_recovery_client.vaults = {AZURE_SUBSCRIPTION_ID: {vault_id: vault}}
            check = vm_backup_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == vm_name
            assert result[0].resource_id == vm_id
            assert (
                result[0].status_extended
                == f"VM {vm_name} in subscription {AZURE_SUBSCRIPTION_ID} is protected by Azure Backup (vault: {vault_name})."
            )

    def test_vm_not_protected_by_backup(self):
        vm_id = str(uuid4())
        vm_name = "VMTest"
        vault_id = str(uuid4())
        vault_name = "vault1"
        mock_vm_client = mock.MagicMock()
        mock_recovery_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_backup_enabled.vm_backup_enabled.vm_client",
                new=mock_vm_client,
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_backup_enabled.vm_backup_enabled.recovery_client",
                new=mock_recovery_client,
            ),
        ):
            from azure.mgmt.recoveryservicesbackup.activestamp.models import (
                DataSourceType,
            )

            from prowler.providers.azure.services.recovery.recovery_service import (
                BackupItem,
                BackupVault,
            )
            from prowler.providers.azure.services.vm.vm_backup_enabled.vm_backup_enabled import (
                vm_backup_enabled,
            )
            from prowler.providers.azure.services.vm.vm_service import (
                ManagedDiskParameters,
                OSDisk,
                StorageProfile,
                VirtualMachine,
            )

            vm = VirtualMachine(
                resource_id=vm_id,
                resource_name=vm_name,
                location="eastus",
                security_profile=None,
                extensions=[],
                storage_profile=StorageProfile(
                    os_disk=OSDisk(
                        name="os_disk_name",
                        operating_system_type="Linux",
                        managed_disk=ManagedDiskParameters(id="managed_disk_id"),
                    ),
                    data_disks=[],
                ),
            )
            backup_item = BackupItem(
                id=str(uuid4()),
                name="someprefix;OtherVM",
                workload_type=DataSourceType.VM,
            )
            vault = BackupVault(
                id=vault_id,
                name=vault_name,
                location="eastus",
                backup_protected_items={backup_item.id: backup_item},
            )
            mock_vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {vm_id: vm}}
            mock_recovery_client.vaults = {AZURE_SUBSCRIPTION_ID: {vault_id: vault}}
            check = vm_backup_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == vm_name
            assert result[0].resource_id == vm_id
            assert (
                result[0].status_extended
                == f"VM {vm_name} in subscription {AZURE_SUBSCRIPTION_ID} is not protected by Azure Backup."
            )

    def test_vm_protected_by_backup_non_vm_workload(self):
        vm_id = str(uuid4())
        vm_name = "VMTest"
        vault_id = str(uuid4())
        vault_name = "vault1"
        mock_vm_client = mock.MagicMock()
        mock_recovery_client = mock.MagicMock()
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_backup_enabled.vm_backup_enabled.vm_client",
                new=mock_vm_client,
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_backup_enabled.vm_backup_enabled.recovery_client",
                new=mock_recovery_client,
            ),
        ):
            from azure.mgmt.recoveryservicesbackup.activestamp.models import (
                DataSourceType,
            )

            from prowler.providers.azure.services.recovery.recovery_service import (
                BackupItem,
                BackupVault,
            )
            from prowler.providers.azure.services.vm.vm_backup_enabled.vm_backup_enabled import (
                vm_backup_enabled,
            )
            from prowler.providers.azure.services.vm.vm_service import (
                ManagedDiskParameters,
                OSDisk,
                StorageProfile,
                VirtualMachine,
            )

            vm = VirtualMachine(
                resource_id=vm_id,
                resource_name=vm_name,
                location="eastus",
                security_profile=None,
                extensions=[],
                storage_profile=StorageProfile(
                    os_disk=OSDisk(
                        name="os_disk_name",
                        operating_system_type="Linux",
                        managed_disk=ManagedDiskParameters(id="managed_disk_id"),
                    ),
                    data_disks=[],
                ),
            )
            backup_item = BackupItem(
                id=str(uuid4()),
                name=f"someprefix;{vm_name}",
                workload_type=DataSourceType.FILE_FOLDER,
            )
            vault = BackupVault(
                id=vault_id,
                name=vault_name,
                location="eastus",
                backup_protected_items={backup_item.id: backup_item},
            )
            mock_vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {vm_id: vm}}
            mock_recovery_client.vaults = {AZURE_SUBSCRIPTION_ID: {vault_id: vault}}
            check = vm_backup_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == vm_name
            assert result[0].resource_id == vm_id
            assert (
                result[0].status_extended
                == f"VM {vm_name} in subscription {AZURE_SUBSCRIPTION_ID} is not protected by Azure Backup."
            )
