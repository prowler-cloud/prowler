from unittest import mock
from uuid import uuid4

from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_vm_sufficient_daily_backup_retention_period:
    def test_no_subscriptions(self):
        vm_client = mock.MagicMock()
        recovery_client = mock.MagicMock()
        vm_client.virtual_machines = {}
        recovery_client.vaults = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_sufficient_daily_backup_retention_period.vm_sufficient_daily_backup_retention_period.vm_client",
                new=vm_client,
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_sufficient_daily_backup_retention_period.vm_sufficient_daily_backup_retention_period.recovery_client",
                new=recovery_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_sufficient_daily_backup_retention_period.vm_sufficient_daily_backup_retention_period import (
                vm_sufficient_daily_backup_retention_period,
            )

            check = vm_sufficient_daily_backup_retention_period()
            result = check.execute()
            assert len(result) == 0

    def test_no_vms(self):
        vm_client = mock.MagicMock()
        recovery_client = mock.MagicMock()
        vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {}}
        recovery_client.vaults = {AZURE_SUBSCRIPTION_ID: {}}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_sufficient_daily_backup_retention_period.vm_sufficient_daily_backup_retention_period.vm_client",
                new=vm_client,
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_sufficient_daily_backup_retention_period.vm_sufficient_daily_backup_retention_period.recovery_client",
                new=recovery_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_sufficient_daily_backup_retention_period.vm_sufficient_daily_backup_retention_period import (
                vm_sufficient_daily_backup_retention_period,
            )

            check = vm_sufficient_daily_backup_retention_period()
            result = check.execute()
            assert len(result) == 0

    def test_vm_with_sufficient_retention(self):
        from azure.mgmt.recoveryservicesbackup.activestamp.models import DataSourceType

        from prowler.providers.azure.services.recovery.recovery_service import (
            BackupItem,
            BackupPolicy,
            BackupVault,
        )
        from prowler.providers.azure.services.vm.vm_service import (
            ManagedDiskParameters,
            OSDisk,
            StorageProfile,
            VirtualMachine,
        )

        vm_id = str(uuid4())
        vm_name = "VMTest"
        vault_id = str(uuid4())
        policy_id = str(uuid4())
        retention_days = 14
        min_retention_days = 7

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
            backup_policy_id=policy_id,
        )
        backup_policy = BackupPolicy(
            id=policy_id,
            name="policy1",
            retention_days=retention_days,
        )
        vault = BackupVault(
            id=vault_id,
            name="vault1",
            location="eastus",
            backup_protected_items={backup_item.id: backup_item},
            backup_policies={policy_id: backup_policy},
        )
        vm_client = mock.MagicMock()
        recovery_client = mock.MagicMock()
        vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {vm_id: vm}}
        recovery_client.vaults = {AZURE_SUBSCRIPTION_ID: {vault_id: vault}}
        vm_client.audit_config = {
            "vm_backup_min_daily_retention_days": min_retention_days
        }
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(
                    audit_config=vm_client.audit_config
                ),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_sufficient_daily_backup_retention_period.vm_sufficient_daily_backup_retention_period.vm_client",
                new=vm_client,
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_sufficient_daily_backup_retention_period.vm_sufficient_daily_backup_retention_period.recovery_client",
                new=recovery_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_sufficient_daily_backup_retention_period.vm_sufficient_daily_backup_retention_period import (
                vm_sufficient_daily_backup_retention_period,
            )

            check = vm_sufficient_daily_backup_retention_period()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == vm_name
            assert result[0].resource_id == vm_id
            assert (
                f"has a daily backup retention period of {retention_days} days"
                in result[0].status_extended
            )

    def test_vm_with_insufficient_retention(self):
        from azure.mgmt.recoveryservicesbackup.activestamp.models import DataSourceType

        from prowler.providers.azure.services.recovery.recovery_service import (
            BackupItem,
            BackupPolicy,
            BackupVault,
        )
        from prowler.providers.azure.services.vm.vm_service import (
            ManagedDiskParameters,
            OSDisk,
            StorageProfile,
            VirtualMachine,
        )

        vm_id = str(uuid4())
        vm_name = "VMTest"
        vault_id = str(uuid4())
        policy_id = str(uuid4())
        retention_days = 3
        min_retention_days = 7

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
            backup_policy_id=policy_id,
        )
        backup_policy = BackupPolicy(
            id=policy_id,
            name="policy1",
            retention_days=retention_days,
        )
        vault = BackupVault(
            id=vault_id,
            name="vault1",
            location="eastus",
            backup_protected_items={backup_item.id: backup_item},
            backup_policies={policy_id: backup_policy},
        )
        vm_client = mock.MagicMock()
        recovery_client = mock.MagicMock()
        vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {vm_id: vm}}
        recovery_client.vaults = {AZURE_SUBSCRIPTION_ID: {vault_id: vault}}
        vm_client.audit_config = {
            "vm_backup_min_daily_retention_days": min_retention_days
        }
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(
                    audit_config=vm_client.audit_config
                ),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_sufficient_daily_backup_retention_period.vm_sufficient_daily_backup_retention_period.vm_client",
                new=vm_client,
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_sufficient_daily_backup_retention_period.vm_sufficient_daily_backup_retention_period.recovery_client",
                new=recovery_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_sufficient_daily_backup_retention_period.vm_sufficient_daily_backup_retention_period import (
                vm_sufficient_daily_backup_retention_period,
            )

            check = vm_sufficient_daily_backup_retention_period()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == vm_name
            assert result[0].resource_id == vm_id
            assert (
                f"has insufficient daily backup retention period of {retention_days} days"
                in result[0].status_extended
            )

    def test_vm_with_no_backup_policy(self):
        from azure.mgmt.recoveryservicesbackup.activestamp.models import DataSourceType

        from prowler.providers.azure.services.recovery.recovery_service import (
            BackupItem,
            BackupVault,
        )
        from prowler.providers.azure.services.vm.vm_service import (
            ManagedDiskParameters,
            OSDisk,
            StorageProfile,
            VirtualMachine,
        )

        vm_id = str(uuid4())
        vm_name = "VMTest"
        vault_id = str(uuid4())

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
            backup_policy_id=None,
        )
        vault = BackupVault(
            id=vault_id,
            name="vault1",
            location="eastus",
            backup_protected_items={backup_item.id: backup_item},
            backup_policies={},
        )
        vm_client = mock.MagicMock()
        recovery_client = mock.MagicMock()
        vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {vm_id: vm}}
        recovery_client.vaults = {AZURE_SUBSCRIPTION_ID: {vault_id: vault}}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_sufficient_daily_backup_retention_period.vm_sufficient_daily_backup_retention_period.vm_client",
                new=vm_client,
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_sufficient_daily_backup_retention_period.vm_sufficient_daily_backup_retention_period.recovery_client",
                new=recovery_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_sufficient_daily_backup_retention_period.vm_sufficient_daily_backup_retention_period import (
                vm_sufficient_daily_backup_retention_period,
            )

            check = vm_sufficient_daily_backup_retention_period()
            result = check.execute()
            assert len(result) == 0
