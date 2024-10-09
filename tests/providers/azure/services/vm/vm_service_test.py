from unittest import mock
from unittest.mock import patch

from azure.mgmt.compute.models import ManagedDiskParameters, OSDisk, StorageProfile

from prowler.providers.azure.services.vm.vm_service import (
    Disk,
    VirtualMachine,
    VirtualMachines,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


def mock_vm_get_virtual_machines(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "vm_id-1": VirtualMachine(
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
                storage_profile=StorageProfile(
                    os_disk=OSDisk(
                        create_option="FromImage",
                        managed_disk=ManagedDiskParameters(id="managed_disk_id"),
                    ),
                    data_disks=[],
                ),
            )
        }
    }


def mock_vm_get_disks(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "disk_id-1": Disk(
                resource_id="disk_id-1",
                location="location",
                resource_name="DiskTest",
                vms_attached=["managed_by"],
                encryption_type="EncryptionAtRestWithPlatformKey",
            )
        }
    }


@patch(
    "prowler.providers.azure.services.vm.vm_service.VirtualMachines._get_virtual_machines",
    new=mock_vm_get_virtual_machines,
)
@patch(
    "prowler.providers.azure.services.vm.vm_service.VirtualMachines._get_disks",
    new=mock_vm_get_disks,
)
class Test_VirtualMachines_Service:
    def test_get_client(self):
        app_insights = VirtualMachines(set_mocked_azure_provider())
        assert (
            app_insights.clients[AZURE_SUBSCRIPTION_ID].__class__.__name__
            == "ComputeManagementClient"
        )

    def test__get_subscriptions__(self):
        app_insights = VirtualMachines(set_mocked_azure_provider())
        assert app_insights.subscriptions.__class__.__name__ == "dict"

    def test__get_virtual_machines(self):
        virtual_machines = VirtualMachines(set_mocked_azure_provider())
        assert len(virtual_machines.virtual_machines) == 1
        assert (virtual_machines.virtual_machines[AZURE_SUBSCRIPTION_ID])[
            "vm_id-1"
        ].location == "location"
        assert (
            virtual_machines.virtual_machines[AZURE_SUBSCRIPTION_ID][
                "vm_id-1"
            ].resource_id
            == "/subscriptions/resource_id"
        )
        assert (
            virtual_machines.virtual_machines[AZURE_SUBSCRIPTION_ID][
                "vm_id-1"
            ].resource_name
            == "VMTest"
        )
        assert (
            virtual_machines.virtual_machines[AZURE_SUBSCRIPTION_ID][
                "vm_id-1"
            ].security_profile.security_type
            == "TrustedLaunch"
        )
        assert (
            virtual_machines.virtual_machines[AZURE_SUBSCRIPTION_ID][
                "vm_id-1"
            ].security_profile.uefi_settings.secure_boot_enabled
            is True
        )
        assert (
            virtual_machines.virtual_machines[AZURE_SUBSCRIPTION_ID][
                "vm_id-1"
            ].security_profile.uefi_settings.v_tpm_enabled
            is True
        )
        assert (
            virtual_machines.virtual_machines[AZURE_SUBSCRIPTION_ID][
                "vm_id-1"
            ].storage_profile.os_disk.managed_disk.id
            == "managed_disk_id"
        )
        assert (
            len(
                virtual_machines.virtual_machines[AZURE_SUBSCRIPTION_ID][
                    "vm_id-1"
                ].storage_profile.data_disks
            )
            == 0
        )

    def test__get_disks(self):
        disks = VirtualMachines(set_mocked_azure_provider()).disks
        assert len(disks) == 1
        assert disks[AZURE_SUBSCRIPTION_ID]["disk_id-1"].resource_id == "disk_id-1"
        assert disks[AZURE_SUBSCRIPTION_ID]["disk_id-1"].resource_name == "DiskTest"
        assert disks[AZURE_SUBSCRIPTION_ID]["disk_id-1"].location == "location"
        assert disks[AZURE_SUBSCRIPTION_ID]["disk_id-1"].vms_attached == ["managed_by"]
        assert (
            disks[AZURE_SUBSCRIPTION_ID]["disk_id-1"].encryption_type
            == "EncryptionAtRestWithPlatformKey"
        )
