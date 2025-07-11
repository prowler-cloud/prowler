from unittest.mock import patch

from prowler.providers.azure.services.vm.vm_service import (
    Disk,
    LinuxConfiguration,
    ManagedDiskParameters,
    OperatingSystemType,
    OSDisk,
    SecurityProfile,
    StorageProfile,
    UefiSettings,
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
                        operating_system_type=OperatingSystemType.LINUX,
                        managed_disk=ManagedDiskParameters(id="managed_disk_id"),
                    ),
                    data_disks=[],
                ),
                linux_configuration=None,
            )
        }
    }


def mock_vm_get_virtual_machines_with_none(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "vm_id-1": VirtualMachine(
                resource_id="/subscriptions/resource_id",
                resource_name="VMWithNoneValues",
                location="location",
                security_profile=None,
                extensions=[],
                storage_profile=None,
                linux_configuration=None,
            ),
            "vm_id-2": VirtualMachine(
                resource_id="/subscriptions/resource_id2",
                resource_name="VMWithPartialNone",
                location="location",
                security_profile=None,
                extensions=[],
                storage_profile=StorageProfile(
                    os_disk=None,
                    data_disks=[],
                ),
                linux_configuration=None,
            ),
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


def mock_vm_get_virtual_machines_with_linux(_):
    return {
        AZURE_SUBSCRIPTION_ID: {
            "vm_id-linux": VirtualMachine(
                resource_id="/subscriptions/resource_id_linux",
                resource_name="LinuxVM",
                location="location",
                security_profile=None,
                extensions=[],
                storage_profile=None,
                linux_configuration=LinuxConfiguration(
                    disable_password_authentication=True
                ),
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


@patch(
    "prowler.providers.azure.services.vm.vm_service.VirtualMachines._get_virtual_machines",
    new=mock_vm_get_virtual_machines_with_none,
)
class Test_VirtualMachines_NoneCases:
    def test_virtual_machine_with_none_storage_profile(self):
        virtual_machines = VirtualMachines(set_mocked_azure_provider())
        vm_1 = virtual_machines.virtual_machines[AZURE_SUBSCRIPTION_ID]["vm_id-1"]
        assert vm_1.storage_profile is None
        assert vm_1.resource_name == "VMWithNoneValues"

    def test_virtual_machine_with_partial_none_storage_profile(self):
        virtual_machines = VirtualMachines(set_mocked_azure_provider())
        vm_2 = virtual_machines.virtual_machines[AZURE_SUBSCRIPTION_ID]["vm_id-2"]
        assert vm_2.storage_profile.os_disk is None
        assert vm_2.storage_profile.data_disks == []
        assert vm_2.resource_name == "VMWithPartialNone"


@patch(
    "prowler.providers.azure.services.vm.vm_service.VirtualMachines._get_virtual_machines",
    new=mock_vm_get_virtual_machines_with_linux,
)
def test_virtual_machine_with_linux_configuration():
    virtual_machines = VirtualMachines(set_mocked_azure_provider())
    vm = virtual_machines.virtual_machines[AZURE_SUBSCRIPTION_ID]["vm_id-linux"]
    assert vm.linux_configuration is not None
    assert vm.linux_configuration.disable_password_authentication is True
