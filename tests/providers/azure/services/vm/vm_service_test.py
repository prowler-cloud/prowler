from unittest.mock import MagicMock, patch

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
                vm_size="Standard_A8_v2",
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
                vm_size=None,
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
                vm_size="Standard_B1s",
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
        assert (
            virtual_machines.virtual_machines[AZURE_SUBSCRIPTION_ID]["vm_id-1"].vm_size
            == "Standard_A8_v2"
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


class Test_VirtualMachine_SecurityProfile_Validation:
    """Test VirtualMachine SecurityProfile Pydantic validation"""

    def test_security_profile_with_all_fields(self):
        """Test that SecurityProfile with all fields validates correctly"""
        vm = VirtualMachine(
            resource_id="/subscriptions/test/vm1",
            resource_name="test-vm",
            location="eastus",
            security_profile=SecurityProfile(
                security_type="TrustedLaunch",
                uefi_settings=UefiSettings(
                    secure_boot_enabled=True,
                    v_tpm_enabled=True,
                ),
            ),
            extensions=[],
        )

        assert vm.security_profile is not None
        assert vm.security_profile.security_type == "TrustedLaunch"
        assert vm.security_profile.uefi_settings is not None
        assert vm.security_profile.uefi_settings.secure_boot_enabled is True
        assert vm.security_profile.uefi_settings.v_tpm_enabled is True

    def test_security_profile_with_none_uefi_settings(self):
        """Test that SecurityProfile with None uefi_settings validates correctly"""
        vm = VirtualMachine(
            resource_id="/subscriptions/test/vm2",
            resource_name="test-vm-2",
            location="westus",
            security_profile=SecurityProfile(
                security_type="Standard",
                uefi_settings=None,
            ),
            extensions=[],
        )

        assert vm.security_profile is not None
        assert vm.security_profile.security_type == "Standard"
        assert vm.security_profile.uefi_settings is None

    def test_security_profile_with_none_security_type(self):
        """Test that SecurityProfile with None security_type validates correctly"""
        vm = VirtualMachine(
            resource_id="/subscriptions/test/vm3",
            resource_name="test-vm-3",
            location="northeurope",
            security_profile=SecurityProfile(
                security_type=None,
                uefi_settings=UefiSettings(
                    secure_boot_enabled=False,
                    v_tpm_enabled=False,
                ),
            ),
            extensions=[],
        )

        assert vm.security_profile is not None
        assert vm.security_profile.security_type is None
        assert vm.security_profile.uefi_settings is not None
        assert vm.security_profile.uefi_settings.secure_boot_enabled is False

    def test_security_profile_with_all_none(self):
        """Test that SecurityProfile with all None values validates correctly"""
        vm = VirtualMachine(
            resource_id="/subscriptions/test/vm4",
            resource_name="test-vm-4",
            location="southeastasia",
            security_profile=SecurityProfile(
                security_type=None,
                uefi_settings=None,
            ),
            extensions=[],
        )

        assert vm.security_profile is not None
        assert vm.security_profile.security_type is None
        assert vm.security_profile.uefi_settings is None

    def test_virtual_machine_with_none_security_profile(self):
        """Test that VirtualMachine with None security_profile validates correctly"""
        vm = VirtualMachine(
            resource_id="/subscriptions/test/vm5",
            resource_name="test-vm-5",
            location="japaneast",
            security_profile=None,
            extensions=[],
        )

        assert vm.security_profile is None

    def test_security_profile_creation_from_azure_sdk_simulation(self):
        """
        Test that SecurityProfile can be created from Azure SDK-like objects
        This simulates the conversion that happens in _get_virtual_machines
        """
        # Simulate Azure SDK SecurityProfile object
        mock_azure_security_profile = MagicMock()
        mock_azure_security_profile.security_type = "TrustedLaunch"

        mock_azure_uefi_settings = MagicMock()
        mock_azure_uefi_settings.secure_boot_enabled = True
        mock_azure_uefi_settings.v_tpm_enabled = True

        # Simulate the conversion that happens in the service
        security_type = getattr(mock_azure_security_profile, "security_type", None)
        uefi_settings = UefiSettings(
            secure_boot_enabled=getattr(
                mock_azure_uefi_settings, "secure_boot_enabled", False
            ),
            v_tpm_enabled=getattr(mock_azure_uefi_settings, "v_tpm_enabled", False),
        )
        security_profile = SecurityProfile(
            security_type=security_type,
            uefi_settings=uefi_settings,
        )

        # Create VirtualMachine with converted SecurityProfile
        vm = VirtualMachine(
            resource_id="/subscriptions/test/vm6",
            resource_name="test-vm-6",
            location="uksouth",
            security_profile=security_profile,
            extensions=[],
        )

        # Verify no ValidationError is raised and data is correct
        assert vm.security_profile is not None
        assert vm.security_profile.security_type == "TrustedLaunch"
        assert vm.security_profile.uefi_settings.secure_boot_enabled is True
        assert vm.security_profile.uefi_settings.v_tpm_enabled is True

    def test_security_profile_with_dict_input(self):
        """Test that SecurityProfile can be created from dictionary (Pydantic feature)"""
        vm = VirtualMachine(
            resource_id="/subscriptions/test/vm7",
            resource_name="test-vm-7",
            location="canadacentral",
            security_profile={
                "security_type": "ConfidentialVM",
                "uefi_settings": {
                    "secure_boot_enabled": True,
                    "v_tpm_enabled": True,
                },
            },
            extensions=[],
        )

        assert vm.security_profile is not None
        assert vm.security_profile.security_type == "ConfidentialVM"
        assert vm.security_profile.uefi_settings.secure_boot_enabled is True

    def test_uefi_settings_boolean_values(self):
        """Test that UefiSettings properly handles boolean values"""
        uefi_true = UefiSettings(secure_boot_enabled=True, v_tpm_enabled=True)
        assert uefi_true.secure_boot_enabled is True
        assert uefi_true.v_tpm_enabled is True

        uefi_false = UefiSettings(secure_boot_enabled=False, v_tpm_enabled=False)
        assert uefi_false.secure_boot_enabled is False
        assert uefi_false.v_tpm_enabled is False

        uefi_mixed = UefiSettings(secure_boot_enabled=True, v_tpm_enabled=False)
        assert uefi_mixed.secure_boot_enabled is True
        assert uefi_mixed.v_tpm_enabled is False

    def test_security_profile_full_service_simulation(self):
        """
        Full integration test simulating the complete VM service flow
        This tests the actual scenario where Azure SDK objects are converted
        """

        def mock_list_vms(*args, **kwargs):
            # Simulate Azure SDK VM object with security_profile
            mock_vm = MagicMock()
            mock_vm.id = "/subscriptions/test/resourceGroups/test-rg/providers/Microsoft.Compute/virtualMachines/test-vm"
            mock_vm.name = "test-vm-full-sim"
            mock_vm.location = "eastus"

            # Simulate Azure SDK SecurityProfile (this was causing the ValidationError)
            mock_security_profile = MagicMock()
            mock_security_profile.security_type = "TrustedLaunch"

            mock_uefi_settings = MagicMock()
            mock_uefi_settings.secure_boot_enabled = True
            mock_uefi_settings.v_tpm_enabled = True
            mock_security_profile.uefi_settings = mock_uefi_settings

            mock_vm.security_profile = mock_security_profile
            mock_vm.resources = []
            mock_vm.storage_profile = None
            mock_vm.hardware_profile = None
            mock_vm.os_profile = None

            return [mock_vm]

        # Create mock client with properly configured virtual_machines attribute
        mock_client = MagicMock()
        # Explicitly create virtual_machines as a MagicMock to ensure it has list_all method
        # This prevents AttributeError in GitHub Actions where it might be a dict
        mock_client.virtual_machines = MagicMock()
        mock_client.virtual_machines.list_all.side_effect = mock_list_vms

        with (
            patch.object(VirtualMachines, "_get_disks", return_value={}),
            patch.object(VirtualMachines, "_get_vm_scale_sets", return_value={}),
            patch.object(VirtualMachines, "_get_virtual_machines", return_value={}),
        ):
            vm_service = VirtualMachines(set_mocked_azure_provider())
            # Replace the client with our mocked one
            vm_service.clients[AZURE_SUBSCRIPTION_ID] = mock_client

        # Now call _get_virtual_machines with the mocked client (patch is removed)
        # This simulates the actual service flow
        virtual_machines = vm_service._get_virtual_machines()

        # Verify VM was created successfully without ValidationError
        assert len(virtual_machines[AZURE_SUBSCRIPTION_ID]) == 1

        vm_id = list(virtual_machines[AZURE_SUBSCRIPTION_ID].keys())[0]
        vm = virtual_machines[AZURE_SUBSCRIPTION_ID][vm_id]

        # Verify the VM object is valid
        assert vm.resource_name == "test-vm-full-sim"
        assert vm.location == "eastus"

        # Verify SecurityProfile was converted correctly (not Azure SDK object)
        assert vm.security_profile is not None
        assert isinstance(vm.security_profile, SecurityProfile)
        assert vm.security_profile.security_type == "TrustedLaunch"

        # Verify UefiSettings was converted correctly
        assert vm.security_profile.uefi_settings is not None
        assert isinstance(vm.security_profile.uefi_settings, UefiSettings)
        assert vm.security_profile.uefi_settings.secure_boot_enabled is True
        assert vm.security_profile.uefi_settings.v_tpm_enabled is True
