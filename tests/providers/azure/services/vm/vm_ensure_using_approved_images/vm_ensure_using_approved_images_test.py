from unittest import mock
from uuid import uuid4

from prowler.providers.azure.services.vm.vm_service import VirtualMachine
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    set_mocked_azure_provider,
)


class Test_vm_ensure_using_approved_images:
    def test_no_subscriptions(self):
        vm_client = mock.MagicMock()
        vm_client.virtual_machines = {}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_ensure_using_approved_images.vm_ensure_using_approved_images.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_ensure_using_approved_images.vm_ensure_using_approved_images import (
                vm_ensure_using_approved_images,
            )

            check = vm_ensure_using_approved_images()
            result = check.execute()
            assert len(result) == 0

    def test_empty_vms_in_subscription(self):
        vm_client = mock.MagicMock()
        vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {}}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_ensure_using_approved_images.vm_ensure_using_approved_images.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_ensure_using_approved_images.vm_ensure_using_approved_images import (
                vm_ensure_using_approved_images,
            )

            check = vm_ensure_using_approved_images()
            result = check.execute()
            assert len(result) == 0

    def test_vm_with_approved_image(self):
        vm_id = str(uuid4())
        approved_image_id = f"/subscriptions/{AZURE_SUBSCRIPTION_ID}/resourceGroups/rg/providers/Microsoft.Compute/images/custom-image"
        vm = VirtualMachine(
            resource_id=vm_id,
            resource_name="VMTestApproved",
            location="westeurope",
            security_profile=None,
            extensions=[],
            storage_profile=None,
            image_reference=approved_image_id,
        )
        vm_client = mock.MagicMock()
        vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {vm_id: vm}}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_ensure_using_approved_images.vm_ensure_using_approved_images.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_ensure_using_approved_images.vm_ensure_using_approved_images import (
                vm_ensure_using_approved_images,
            )

            check = vm_ensure_using_approved_images()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_name == "VMTestApproved"
            assert result[0].resource_id == vm_id
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            expected_status_extended = f"VM VMTestApproved in subscription {AZURE_SUBSCRIPTION_ID} is using an approved machine image: custom-image."
            assert result[0].status_extended == expected_status_extended

    def test_vm_with_not_approved_image(self):
        vm_id = str(uuid4())
        not_approved_image_id = "/subscriptions/other/resourceGroups/rg/providers/Microsoft.Compute/otherResource/other-image"
        vm = VirtualMachine(
            resource_id=vm_id,
            resource_name="VMTestNotApproved",
            location="westeurope",
            security_profile=None,
            extensions=[],
            storage_profile=None,
            image_reference=not_approved_image_id,
        )
        vm_client = mock.MagicMock()
        vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {vm_id: vm}}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_ensure_using_approved_images.vm_ensure_using_approved_images.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_ensure_using_approved_images.vm_ensure_using_approved_images import (
                vm_ensure_using_approved_images,
            )

            check = vm_ensure_using_approved_images()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == "VMTestNotApproved"
            assert result[0].resource_id == vm_id
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            expected_status_extended = f"VM VMTestNotApproved in subscription {AZURE_SUBSCRIPTION_ID} is not using an approved machine image."
            assert result[0].status_extended == expected_status_extended

    def test_vm_with_missing_image_reference(self):
        vm_id = str(uuid4())
        vm = VirtualMachine(
            resource_id=vm_id,
            resource_name="VMTestNoImageRef",
            location="westeurope",
            security_profile=None,
            extensions=[],
            storage_profile=None,
            image_reference=None,
        )
        vm_client = mock.MagicMock()
        vm_client.virtual_machines = {AZURE_SUBSCRIPTION_ID: {vm_id: vm}}
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_azure_provider(),
            ),
            mock.patch(
                "prowler.providers.azure.services.vm.vm_ensure_using_approved_images.vm_ensure_using_approved_images.vm_client",
                new=vm_client,
            ),
        ):
            from prowler.providers.azure.services.vm.vm_ensure_using_approved_images.vm_ensure_using_approved_images import (
                vm_ensure_using_approved_images,
            )

            check = vm_ensure_using_approved_images()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_name == "VMTestNoImageRef"
            assert result[0].resource_id == vm_id
            assert result[0].subscription == AZURE_SUBSCRIPTION_ID
            expected_status_extended = f"VM VMTestNoImageRef in subscription {AZURE_SUBSCRIPTION_ID} is not using an approved machine image."
            assert result[0].status_extended == expected_status_extended
