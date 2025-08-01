from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.vm.vm_service import (
    ManagedDiskParameters,
    OSDisk,
    SecurityProfile,
    StorageProfile,
    UefiSettings,
    VirtualMachine,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_vm_trusted_launch_enabled:
    def test_vm_no_subscriptions(self):
        vm_client = mock.MagicMock
        vm_client.virtual_machines = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_trusted_launch_enabled.vm_trusted_launch_enabled.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_trusted_launch_enabled.vm_trusted_launch_enabled import (
                vm_trusted_launch_enabled,
            )

            check = vm_trusted_launch_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_vm_no_vm(self):
        vm_client = mock.MagicMock
        vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {}}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_trusted_launch_enabled.vm_trusted_launch_enabled.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_trusted_launch_enabled.vm_trusted_launch_enabled import (
                vm_trusted_launch_enabled,
            )

            check = vm_trusted_launch_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_vm_trusted_launch_enabled(self):
        vm_id = str(uuid4())
        vm_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_trusted_launch_enabled.vm_trusted_launch_enabled.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_trusted_launch_enabled.vm_trusted_launch_enabled import (
                vm_trusted_launch_enabled,
            )

            vm_client.virtual_machines = {
                AZURE_SUBSCRIPTION_ID: {
                    vm_id: VirtualMachine(
                        resource_id=vm_id,
                        resource_name="VMTest",
                        location="location",
                        security_profile=SecurityProfile(
                            security_type="TrustedLaunch",
                            uefi_settings=UefiSettings(
                                secure_boot_enabled=True,
                                v_tpm_enabled=True,
                            ),
                        ),
                        extensions=[],
                        storage_profile=StorageProfile(
                            os_disk=OSDisk(
                                name="os_disk_name",
                                operating_system_type="Linux",
                                managed_disk=ManagedDiskParameters(
                                    id="managed_disk_id"
                                ),
                            ),
                            data_disks=[],
                        ),
                    )
                }
            }
            check = vm_trusted_launch_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "VMTest"
            assert result[0].resource_id == vm_id
            assert (
                result[0].status_extended
                == f"VM VMTest has trusted launch enabled in subscription {AZURE_SUBSCRIPTION_ID}"
            )

    def test_vm_trusted_launch_disabled(self):
        vm_id = str(uuid4())
        vm_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_trusted_launch_enabled.vm_trusted_launch_enabled.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_trusted_launch_enabled.vm_trusted_launch_enabled import (
                vm_trusted_launch_enabled,
            )

            vm_client.virtual_machines = {
                AZURE_SUBSCRIPTION_ID: {
                    vm_id: VirtualMachine(
                        resource_id=vm_id,
                        resource_name="VMTest",
                        location="location",
                        security_profile=SecurityProfile(
                            security_type="TrustedLaunch",
                            uefi_settings=UefiSettings(
                                secure_boot_enabled=False,
                                v_tpm_enabled=False,
                            ),
                        ),
                        extensions=[],
                        storage_profile=StorageProfile(
                            os_disk=OSDisk(
                                name="os_disk_name",
                                operating_system_type="Linux",
                                managed_disk=ManagedDiskParameters(
                                    id="managed_disk_id"
                                ),
                            ),
                            data_disks=[],
                        ),
                    )
                }
            }

            check = vm_trusted_launch_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "VMTest"
            assert result[0].resource_id == vm_id
            assert (
                result[0].status_extended
                == f"VM VMTest has trusted launch disabled in subscription {AZURE_SUBSCRIPTION_ID}"
            )

    def test_vm_no_security_profile(self):
        vm_id = str(uuid4())
        vm_client = mock.MagicMock
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_trusted_launch_enabled.vm_trusted_launch_enabled.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_trusted_launch_enabled.vm_trusted_launch_enabled import (
                vm_trusted_launch_enabled,
            )

            vm_client.virtual_machines = {
                AZURE_SUBSCRIPTION_ID: {
                    vm_id: VirtualMachine(
                        resource_id=vm_id,
                        resource_name="VMTest",
                        location="location",
                        security_profile=None,
                        extensions=[],
                        storage_profile=StorageProfile(
                            os_disk=OSDisk(
                                name="os_disk_name",
                                operating_system_type="Linux",
                                managed_disk=ManagedDiskParameters(
                                    id="managed_disk_id"
                                ),
                            ),
                            data_disks=[],
                        ),
                    )
                }
            }

            check = vm_trusted_launch_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "VMTest"
            assert result[0].resource_id == vm_id
            assert (
                result[0].status_extended
                == f"VM VMTest has trusted launch disabled in subscription {AZURE_SUBSCRIPTION_ID}"
            )
