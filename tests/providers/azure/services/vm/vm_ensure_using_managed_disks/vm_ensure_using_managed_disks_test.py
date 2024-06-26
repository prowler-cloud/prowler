from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.vm.vm_service import VirtualMachine
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_vm_ensure_using_managed_disks:
    def test_vm_no_subscriptions(self):
        vm_client = mock.MagicMock
        vm_client.virtual_machines = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.vm.vm_ensure_using_managed_disks.vm_ensure_using_managed_disks.vm_client",
            new=vm_client,
        ):
            from prowler.providers.azure.services.vm.vm_ensure_using_managed_disks.vm_ensure_using_managed_disks import (
                vm_ensure_using_managed_disks,
            )

            check = vm_ensure_using_managed_disks()
            result = check.execute()
            assert len(result) == 0

    def test_vm_subscriptions(self):
        vm_client = mock.MagicMock
        vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {}}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.vm.vm_ensure_using_managed_disks.vm_ensure_using_managed_disks.vm_client",
            new=vm_client,
        ):
            from prowler.providers.azure.services.vm.vm_ensure_using_managed_disks.vm_ensure_using_managed_disks import (
                vm_ensure_using_managed_disks,
            )

            check = vm_ensure_using_managed_disks()
            result = check.execute()
            assert len(result) == 0

    def test_vm_ensure_using_managed_disks(self):
        vm_id = str(uuid4())
        vm_client = mock.MagicMock
        vm_client.virtual_machines = {
            AZURE_SUBSCRIPTION_ID: {
                vm_id: VirtualMachine(
                    resource_id="/subscriptions/resource_id",
                    resource_name="VMTest",
                    location="location",
                    security_profile=mock.MagicMock(
                        security_type="TrustedLaunch",
                        uefi_settings=mock.MagicMock(
                            secure_boot_enabled=True,
                            v_tpm_enabled=True,
                        ),
                    ),
                    storage_profile=mock.MagicMock(
                        os_disk=mock.MagicMock(
                            create_option="FromImage",
                            managed_disk=mock.MagicMock(id="managed_disk_id"),
                        ),
                        data_disks=[],
                    ),
                ),
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.vm.vm_ensure_using_managed_disks.vm_ensure_using_managed_disks.vm_client",
            new=vm_client,
        ):
            from prowler.providers.azure.services.vm.vm_ensure_using_managed_disks.vm_ensure_using_managed_disks import (
                vm_ensure_using_managed_disks,
            )

            check = vm_ensure_using_managed_disks()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "VMTest"
            assert result[0].location == "location"
            assert result[0].resource_id == vm_id
            assert (
                result[0].status_extended
                == f"VM VMTest is using managed disks in subscription {AZURE_SUBSCRIPTION_ID}"
            )

    def test_vm_using_not_managed_os_disk(self):
        vm_id = str(uuid4())
        vm_client = mock.MagicMock
        vm_client.virtual_machines = {
            AZURE_SUBSCRIPTION_ID: {
                vm_id: VirtualMachine(
                    resource_id="/subscriptions/resource_id",
                    resource_name="VMTest",
                    location="location",
                    security_profile=mock.MagicMock(
                        security_type="TrustedLaunch",
                        uefi_settings=mock.MagicMock(
                            secure_boot_enabled=True,
                            v_tpm_enabled=True,
                        ),
                    ),
                    storage_profile=mock.MagicMock(
                        os_disk=mock.MagicMock(
                            create_option="FromImage",
                            managed_disk=None,
                        ),
                        data_disks=[],
                    ),
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.vm.vm_ensure_using_managed_disks.vm_ensure_using_managed_disks.vm_client",
            new=vm_client,
        ):
            from prowler.providers.azure.services.vm.vm_ensure_using_managed_disks.vm_ensure_using_managed_disks import (
                vm_ensure_using_managed_disks,
            )

            check = vm_ensure_using_managed_disks()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "VMTest"
            assert result[0].resource_id == vm_id
            assert result[0].location == "location"
            assert (
                result[0].status_extended
                == f"VM VMTest is not using managed disks in subscription {AZURE_SUBSCRIPTION_ID}"
            )

    def test_vm_using_not_managed_data_disks(self):
        vm_id = str(uuid4())
        vm_client = mock.MagicMock
        vm_client.virtual_machines = {
            AZURE_SUBSCRIPTION_ID: {
                vm_id: VirtualMachine(
                    resource_id="/subscriptions/resource_id",
                    resource_name="VMTest",
                    location="location",
                    security_profile=mock.MagicMock(
                        security_type="TrustedLaunch",
                        uefi_settings=mock.MagicMock(
                            secure_boot_enabled=True,
                            v_tpm_enabled=True,
                        ),
                    ),
                    storage_profile=mock.MagicMock(
                        os_disk=mock.MagicMock(
                            create_option="FromImage",
                            managed_disk=mock.MagicMock(id="managed_disk_id"),
                        ),
                        data_disks=[mock.MagicMock(managed_disk=None)],
                    ),
                )
            }
        }

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_azure_provider(),
        ), mock.patch(
            "prowler.providers.azure.services.vm.vm_ensure_using_managed_disks.vm_ensure_using_managed_disks.vm_client",
            new=vm_client,
        ):
            from prowler.providers.azure.services.vm.vm_ensure_using_managed_disks.vm_ensure_using_managed_disks import (
                vm_ensure_using_managed_disks,
            )

            check = vm_ensure_using_managed_disks()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "VMTest"
            assert result[0].resource_id == vm_id
            assert result[0].location == "location"
            assert (
                result[0].status_extended
                == f"VM VMTest is not using managed disks in subscription {AZURE_SUBSCRIPTION_ID}"
            )
