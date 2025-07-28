from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.vm.vm_service import (
    SecurityProfile,
    StorageProfile,
    UefiSettings,
    VirtualMachine,
)
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_vm_desired_sku_size:
    def test_vm_no_subscriptions(self):
        """Test when there are no subscriptions."""
        vm_client = mock.MagicMock
        vm_client.virtual_machines = {}
        vm_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size import (
                vm_desired_sku_size,
            )

            check = vm_desired_sku_size()
            result = check.execute()
            assert len(result) == 0

    def test_vm_subscriptions_empty(self):
        """Test when subscriptions exist but have no VMs."""
        vm_client = mock.MagicMock
        vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {}}
        vm_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size import (
                vm_desired_sku_size,
            )

            check = vm_desired_sku_size()
            result = check.execute()
            assert len(result) == 0

    def test_vm_using_desired_sku_size_default_config(self):
        """Test VM using a SKU size that is in the default configuration."""
        vm_id = str(uuid4())
        vm_client = mock.MagicMock
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
                        os_disk=None,
                        data_disks=[],
                    ),
                    vm_size="Standard_A8_v2",
                ),
            }
        }
        vm_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size import (
                vm_desired_sku_size,
            )

            check = vm_desired_sku_size()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "VMTest"
            assert result[0].resource_id == vm_id
            assert (
                result[0].status_extended
                == f"VM VMTest is using desired SKU size Standard_A8_v2 in subscription {AZURE_SUBSCRIPTION_ID}."
            )

    def test_vm_using_desired_sku_size_custom_config(self):
        """Test VM using a SKU size that is in the custom configuration."""
        vm_id = str(uuid4())
        vm_client = mock.MagicMock
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
                        os_disk=None,
                        data_disks=[],
                    ),
                    vm_size="Standard_B1s",
                ),
            }
        }
        vm_client.audit_config = {
            "desired_vm_sku_sizes": ["Standard_B1s", "Standard_B2s"]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size import (
                vm_desired_sku_size,
            )

            check = vm_desired_sku_size()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "VMTest"
            assert result[0].resource_id == vm_id
            assert (
                result[0].status_extended
                == f"VM VMTest is using desired SKU size Standard_B1s in subscription {AZURE_SUBSCRIPTION_ID}."
            )

    def test_vm_using_non_desired_sku_size_default_config(self):
        """Test VM using a SKU size that is not in the default configuration."""
        vm_id = str(uuid4())
        vm_client = mock.MagicMock
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
                        os_disk=None,
                        data_disks=[],
                    ),
                    vm_size="Standard_B1s",
                ),
            }
        }
        vm_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size import (
                vm_desired_sku_size,
            )

            check = vm_desired_sku_size()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "VMTest"
            assert result[0].resource_id == vm_id
            assert (
                result[0].status_extended
                == f"VM VMTest is using Standard_B1s which is not a desired SKU size in subscription {AZURE_SUBSCRIPTION_ID}."
            )

    def test_vm_using_non_desired_sku_size_custom_config(self):
        """Test VM using a SKU size that is not in the custom configuration."""
        vm_id = str(uuid4())
        vm_client = mock.MagicMock
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
                        os_disk=None,
                        data_disks=[],
                    ),
                    vm_size="Standard_A8_v2",
                ),
            }
        }
        vm_client.audit_config = {
            "desired_vm_sku_sizes": ["Standard_B1s", "Standard_B2s"]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size import (
                vm_desired_sku_size,
            )

            check = vm_desired_sku_size()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "VMTest"
            assert result[0].resource_id == vm_id
            assert (
                result[0].status_extended
                == f"VM VMTest is using Standard_A8_v2 which is not a desired SKU size in subscription {AZURE_SUBSCRIPTION_ID}."
            )

    def test_vm_with_none_vm_size(self):
        """Test VM with None vm_size."""
        vm_id = str(uuid4())
        vm_client = mock.MagicMock
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
                        os_disk=None,
                        data_disks=[],
                    ),
                    vm_size=None,
                ),
            }
        }
        vm_client.audit_config = {"desired_vm_sku_sizes": ["Standard_A8_v2"]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size import (
                vm_desired_sku_size,
            )

            check = vm_desired_sku_size()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "VMTest"
            assert result[0].resource_id == vm_id
            assert (
                result[0].status_extended
                == f"VM VMTest is using None which is not a desired SKU size in subscription {AZURE_SUBSCRIPTION_ID}."
            )

    def test_multiple_vms_different_statuses(self):
        """Test multiple VMs with different statuses."""
        vm_id_1 = str(uuid4())
        vm_id_2 = str(uuid4())
        vm_id_3 = str(uuid4())

        vm_client = mock.MagicMock
        vm_client.virtual_machines = {
            AZURE_SUBSCRIPTION_ID: {
                vm_id_1: VirtualMachine(
                    resource_id=vm_id_1,
                    resource_name="VMApproved",
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
                        os_disk=None,
                        data_disks=[],
                    ),
                    vm_size="Standard_A8_v2",
                ),
                vm_id_2: VirtualMachine(
                    resource_id=vm_id_2,
                    resource_name="VMNotApproved",
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
                        os_disk=None,
                        data_disks=[],
                    ),
                    vm_size="Standard_B1s",
                ),
                vm_id_3: VirtualMachine(
                    resource_id=vm_id_3,
                    resource_name="VMAnotherApproved",
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
                        os_disk=None,
                        data_disks=[],
                    ),
                    vm_size="Standard_DS3_v2",
                ),
            }
        }
        vm_client.audit_config = {
            "desired_vm_sku_sizes": ["Standard_A8_v2", "Standard_DS3_v2"]
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size import (
                vm_desired_sku_size,
            )

            check = vm_desired_sku_size()
            result = check.execute()
            assert len(result) == 3

            # Find the PASS result
            pass_result = next(
                r
                for r in result
                if r.status == "PASS" and r.resource_name == "VMApproved"
            )
            assert pass_result.subscription == AZURE_SUBSCRIPTION_ID
            assert pass_result.resource_id == vm_id_1
            assert (
                pass_result.status_extended
                == f"VM VMApproved is using desired SKU size Standard_A8_v2 in subscription {AZURE_SUBSCRIPTION_ID}."
            )

            # Find the FAIL result
            fail_result = next(
                r
                for r in result
                if r.status == "FAIL" and r.resource_name == "VMNotApproved"
            )
            assert fail_result.subscription == AZURE_SUBSCRIPTION_ID
            assert fail_result.resource_id == vm_id_2
            assert (
                fail_result.status_extended
                == f"VM VMNotApproved is using Standard_B1s which is not a desired SKU size in subscription {AZURE_SUBSCRIPTION_ID}."
            )

            # Find the second PASS result
            pass_result_2 = next(
                r
                for r in result
                if r.status == "PASS" and r.resource_name == "VMAnotherApproved"
            )
            assert pass_result_2.subscription == AZURE_SUBSCRIPTION_ID
            assert pass_result_2.resource_id == vm_id_3
            assert (
                pass_result_2.status_extended
                == f"VM VMAnotherApproved is using desired SKU size Standard_DS3_v2 in subscription {AZURE_SUBSCRIPTION_ID}."
            )

    def test_multiple_subscriptions(self):
        """Test multiple subscriptions with different VMs."""
        vm_id_1 = str(uuid4())
        vm_id_2 = str(uuid4())
        subscription_2 = "subscription-2"

        vm_client = mock.MagicMock
        vm_client.virtual_machines = {
            AZURE_SUBSCRIPTION_ID: {
                vm_id_1: VirtualMachine(
                    resource_id=vm_id_1,
                    resource_name="VMSub1",
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
                        os_disk=None,
                        data_disks=[],
                    ),
                    vm_size="Standard_A8_v2",
                ),
            },
            subscription_2: {
                vm_id_2: VirtualMachine(
                    resource_id=vm_id_2,
                    resource_name="VMSub2",
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
                        os_disk=None,
                        data_disks=[],
                    ),
                    vm_size="Standard_B1s",
                ),
            },
        }
        vm_client.audit_config = {"desired_vm_sku_sizes": ["Standard_A8_v2"]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size import (
                vm_desired_sku_size,
            )

            check = vm_desired_sku_size()
            result = check.execute()
            assert len(result) == 2

            # Find the PASS result from subscription 1
            pass_result = next(
                r
                for r in result
                if r.status == "PASS" and r.subscription == AZURE_SUBSCRIPTION_ID
            )
            assert pass_result.resource_name == "VMSub1"
            assert pass_result.resource_id == vm_id_1

            # Find the FAIL result from subscription 2
            fail_result = next(
                r
                for r in result
                if r.status == "FAIL" and r.subscription == subscription_2
            )
            assert fail_result.resource_name == "VMSub2"
            assert fail_result.resource_id == vm_id_2

    def test_empty_desired_sku_sizes_config(self):
        """Test when the desired SKU sizes configuration is empty."""
        vm_id = str(uuid4())
        vm_client = mock.MagicMock
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
                        os_disk=None,
                        data_disks=[],
                    ),
                    vm_size="Standard_A8_v2",
                ),
            }
        }
        vm_client.audit_config = {"desired_vm_sku_sizes": []}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size import (
                vm_desired_sku_size,
            )

            check = vm_desired_sku_size()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "VMTest"
            assert result[0].resource_id == vm_id
            assert (
                result[0].status_extended
                == f"VM VMTest is using Standard_A8_v2 which is not a desired SKU size in subscription {AZURE_SUBSCRIPTION_ID}."
            )

    def test_case_sensitive_sku_size_matching(self):
        """Test that SKU size matching is case sensitive."""
        vm_id = str(uuid4())
        vm_client = mock.MagicMock
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
                        os_disk=None,
                        data_disks=[],
                    ),
                    vm_size="standard_a8_v2",  # lowercase
                ),
            }
        }
        vm_client.audit_config = {
            "desired_vm_sku_sizes": ["Standard_A8_v2"]
        }  # proper case

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_desired_sku_size.vm_desired_sku_size import (
                vm_desired_sku_size,
            )

            check = vm_desired_sku_size()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"  # Should fail due to case mismatch
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            assert result[0].resource_name == "VMTest"
            assert result[0].resource_id == vm_id
            assert (
                result[0].status_extended
                == f"VM VMTest is using standard_a8_v2 which is not a desired SKU size in subscription {AZURE_SUBSCRIPTION_ID}."
            )
