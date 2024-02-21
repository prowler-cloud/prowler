from unittest.mock import patch

from azure.mgmt.compute.models import ManagedDiskParameters, OSDisk, StorageProfile

from prowler.providers.azure.services.vm.vm_service import (
    Disk,
    VirtualMachine,
    VirtualMachines,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION,
    set_mocked_azure_audit_info,
)


def mock_vm_get_virtual_machines(_):
    return {
        AZURE_SUBSCRIPTION: {
            "vm_id-1": VirtualMachine(
                resource_id="/subscriptions/resource_id",
                resource_name="VMTest",
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
        AZURE_SUBSCRIPTION: {
            "disk_id-1": Disk(
                resource_id="disk_id-1",
                resource_name="DiskTest",
                vms_attached=["managed_by"],
                encryption_type="EncryptionAtRestWithPlatformKey",
            )
        }
    }


@patch(
    "prowler.providers.azure.services.vm.vm_service.VirtualMachines.__get_virtual_machines__",
    new=mock_vm_get_virtual_machines,
)
@patch(
    "prowler.providers.azure.services.vm.vm_service.VirtualMachines.__get_disks__",
    new=mock_vm_get_disks,
)
class Test_AppInsights_Service:
    def test__get_client__(self):
        app_insights = VirtualMachines(set_mocked_azure_audit_info())
        assert (
            app_insights.clients[AZURE_SUBSCRIPTION].__class__.__name__
            == "ComputeManagementClient"
        )

    def test__get_subscriptions__(self):
        app_insights = VirtualMachines(set_mocked_azure_audit_info())
        assert app_insights.subscriptions.__class__.__name__ == "dict"

    def test__get_virtual_machines(self):
        virtual_machines = VirtualMachines(set_mocked_azure_audit_info())
        assert len(virtual_machines.virtual_machines) == 1
        assert (
            virtual_machines.virtual_machines[AZURE_SUBSCRIPTION]["vm_id-1"].resource_id
            == "/subscriptions/resource_id"
        )
        assert (
            virtual_machines.virtual_machines[AZURE_SUBSCRIPTION][
                "vm_id-1"
            ].resource_name
            == "VMTest"
        )
        assert (
            virtual_machines.virtual_machines[AZURE_SUBSCRIPTION][
                "vm_id-1"
            ].storage_profile.os_disk.managed_disk.id
            == "managed_disk_id"
        )
        assert (
            len(
                virtual_machines.virtual_machines[AZURE_SUBSCRIPTION][
                    "vm_id-1"
                ].storage_profile.data_disks
            )
            == 0
        )

    def test__get_disks(self):
        disks = VirtualMachines(set_mocked_azure_audit_info()).disks
        assert len(disks) == 1
        assert disks[AZURE_SUBSCRIPTION]["disk_id-1"].resource_id == "disk_id-1"
        assert disks[AZURE_SUBSCRIPTION]["disk_id-1"].resource_name == "DiskTest"
        assert disks[AZURE_SUBSCRIPTION]["disk_id-1"].vms_attached == ["managed_by"]
        assert (
            disks[AZURE_SUBSCRIPTION]["disk_id-1"].encryption_type
            == "EncryptionAtRestWithPlatformKey"
        )
